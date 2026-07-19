#!/usr/bin/env python3
"""
FlashS3 performance benchmarks (HTTP / SigV4).

Measures:
  - sequential & concurrent PUT (write)
  - GET cold  (engine started with cache disabled, or first pass after restart)
  - GET warm  (same keys, InMemoryLRU cache enabled)

Usage:
  python3 scripts/benchmark.py
  python3 scripts/benchmark.py --objects 500 --size 65536 --concurrency 8
  python3 scripts/benchmark.py --endpoint http://127.0.0.1:9000   # attach to running engine

Environment (when spawning engine):
  FLASHS3_ACCESS_KEY / FLASHS3_SECRET_KEY (defaults: flash / flashsecret)
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path


ACCESS = os.environ.get("FLASHS3_ACCESS_KEY", "flash")
SECRET = os.environ.get("FLASHS3_SECRET_KEY", "flashsecret")
REGION = os.environ.get("FLASHS3_REGION", "us-east-1")


def uri_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="-_.~")


def sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


@dataclass
class BenchResult:
    name: str
    ops: int
    bytes_total: int
    seconds: float
    errors: int
    latency_ms_p50: float
    latency_ms_p95: float
    latency_ms_p99: float

    @property
    def ops_per_sec(self) -> float:
        return self.ops / self.seconds if self.seconds > 0 else 0.0

    @property
    def mib_per_sec(self) -> float:
        return (self.bytes_total / (1024 * 1024)) / self.seconds if self.seconds > 0 else 0.0


class S3Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        parsed = urllib.parse.urlsplit(self.base)
        self.host = parsed.netloc

    def _headers(self, method: str, path: str, payload: bytes, extra: dict | None = None) -> dict:
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(payload).hexdigest()
        canonical_headers = (
            f"host:{self.host}\n"
            f"x-amz-content-sha256:{payload_hash}\n"
            f"x-amz-date:{amz_date}\n"
        )
        signed_headers = "host;x-amz-content-sha256;x-amz-date"
        canonical_request = (
            f"{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )
        scope = f"{date_stamp}/{REGION}/s3/aws4_request"
        sts = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n"
            f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        )
        k_date = sign(("AWS4" + SECRET).encode(), date_stamp)
        k_region = sign(k_date, REGION)
        k_service = sign(k_region, "s3")
        k_signing = sign(k_service, "aws4_request")
        signature = hmac.new(k_signing, sts.encode(), hashlib.sha256).hexdigest()
        headers = {
            "Host": self.host,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
            "Authorization": (
                f"AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, "
                f"SignedHeaders={signed_headers}, Signature={signature}"
            ),
        }
        if extra:
            headers.update(extra)
        return headers

    def request(self, method: str, path: str, data: bytes = b"", extra: dict | None = None) -> tuple[int, bytes, float]:
        headers = self._headers(method, path, data, extra)
        body = data if method in ("PUT", "POST") else None
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=headers)
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                payload = resp.read()
                dt = time.perf_counter() - t0
                return resp.status, payload, dt
        except urllib.error.HTTPError as e:
            dt = time.perf_counter() - t0
            return e.code, e.read(), dt


def percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def run_ops(
    name: str,
    client: S3Client,
    work: list[tuple[str, str, bytes]],
    concurrency: int,
) -> BenchResult:
    """work items: (method, path, body)"""
    latencies: list[float] = []
    errors = 0
    bytes_total = 0
    t0 = time.perf_counter()

    def one(item: tuple[str, str, bytes]) -> tuple[int, float, int]:
        method, path, body = item
        status, _, dt = client.request(method, path, body)
        return status, dt, len(body) if method == "PUT" else 0

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futs = [pool.submit(one, w) for w in work]
        for fut in as_completed(futs):
            status, dt, nbytes = fut.result()
            latencies.append(dt * 1000.0)
            if status >= 400:
                errors += 1
            else:
                # for GET, count response size approx via request body 0 — fix below
                bytes_total += nbytes

    # For GET benchmarks, count expected object sizes from work list metadata
    if work and work[0][0] == "GET":
        # caller passes body as size marker (expected bytes) for accounting
        bytes_total = sum(len(b) for _, _, b in work if True)
        # actually we stuffed expected size into body for GET as dummy — use len
        pass

    elapsed = time.perf_counter() - t0
    latencies.sort()
    ok = len(work) - errors
    return BenchResult(
        name=name,
        ops=ok,
        bytes_total=bytes_total if work and work[0][0] == "PUT" else sum(len(b) for *_, b in work),
        seconds=elapsed,
        errors=errors,
        latency_ms_p50=percentile(latencies, 50),
        latency_ms_p95=percentile(latencies, 95),
        latency_ms_p99=percentile(latencies, 99),
    )


def start_engine(data_dir: Path, bind: str, cache_policy: str, cache_max: int) -> subprocess.Popen:
    env = os.environ.copy()
    env.update(
        {
            "FLASHS3_DATA_DIR": str(data_dir),
            "FLASHS3_BIND": bind,
            "FLASHS3_CACHE_POLICY": cache_policy,
            "FLASHS3_CACHE_MAX_BYTES": str(cache_max),
            "FLASHS3_CACHE_OBJECT_MAX_BYTES": str(4 * 1024 * 1024),
            "FLASHS3_ACCESS_KEY": ACCESS,
            "FLASHS3_SECRET_KEY": SECRET,
            "RUST_LOG": "warn",
        }
    )
    root = Path(__file__).resolve().parents[1]
    bin_path = root / "target" / "release" / "flash-s3-engine"
    if bin_path.exists():
        cmd = [str(bin_path)]
    else:
        cmd = ["cargo", "run", "-q", "-p", "flash-s3-engine", "--release", "--"]
    proc = subprocess.Popen(
        cmd,
        cwd=str(root),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    # wait for health
    base = f"http://{bind}"
    deadline = time.time() + 60
    while time.time() < deadline:
        if proc.poll() is not None:
            err = proc.stderr.read().decode() if proc.stderr else ""
            raise RuntimeError(f"engine exited early: {err}")
        try:
            urllib.request.urlopen(base + "/healthz", timeout=1)
            return proc
        except Exception:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("engine did not become healthy in time")


def ensure_bucket(client: S3Client, bucket: str) -> None:
    status, _, _ = client.request("PUT", f"/{bucket}")
    if status not in (200, 409):
        raise RuntimeError(f"create bucket failed: {status}")


def print_result(r: BenchResult) -> None:
    print(
        f"  {r.name:28s}  ops={r.ops:6d}  errors={r.errors}  "
        f"{r.ops_per_sec:8.1f} ops/s  {r.mib_per_sec:8.2f} MiB/s  "
        f"p50={r.latency_ms_p50:7.2f}ms  p95={r.latency_ms_p95:7.2f}ms  p99={r.latency_ms_p99:7.2f}ms"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="FlashS3 write/read benchmarks")
    ap.add_argument("--objects", type=int, default=200, help="number of objects per phase")
    ap.add_argument("--size", type=int, default=64 * 1024, help="object size in bytes")
    ap.add_argument("--concurrency", type=int, default=4, help="parallel clients")
    ap.add_argument(
        "--profile",
        choices=("default", "latency"),
        default="default",
        help="latency profile uses many small objects (overrides --objects/--size defaults if those left default)",
    )
    ap.add_argument("--endpoint", type=str, default="", help="use existing engine (skip spawn)")
    ap.add_argument("--cache-max-bytes", type=int, default=512 * 1024 * 1024)
    ap.add_argument("--json-out", type=str, default="", help="write results JSON to path")
    args = ap.parse_args()
    # Apply latency profile defaults only when user kept stock defaults.
    if args.profile == "latency" and args.objects == 200 and args.size == 64 * 1024:
        args.objects = 2000
        args.size = 4096
        args.concurrency = max(args.concurrency, 16)

    results: list[BenchResult] = []
    payload = os.urandom(args.size)
    keys = [f"bench/obj-{i:06d}.bin" for i in range(args.objects)]

    print("FlashS3 benchmark")
    print(f"  objects={args.objects}  size={args.size} B  concurrency={args.concurrency}")

    procs: list[subprocess.Popen] = []
    try:
        if args.endpoint:
            endpoint = args.endpoint.rstrip("/")
            print(f"  mode=attach  endpoint={endpoint}")
            client = S3Client(endpoint)
            ensure_bucket(client, "bench")

            # WRITE
            work = [("PUT", f"/bench/{k}", payload) for k in keys]
            r = run_ops("write_put", client, work, args.concurrency)
            results.append(r)
            print_result(r)

            # READ warm (assume cache already filling from writes if engine has cache)
            # cold: read once after note — first pass
            work_get = [("GET", f"/bench/{k}", payload) for k in keys]  # body len = size for accounting
            r_cold = run_ops("read_first_pass", client, work_get, args.concurrency)
            results.append(r_cold)
            print_result(r_cold)

            r_warm = run_ops("read_second_pass_warm", client, work_get, args.concurrency)
            results.append(r_warm)
            print_result(r_warm)
        else:
            # Controlled: cold with cache=None, then warm with InMemoryLRU on same data dir
            with tempfile.TemporaryDirectory(prefix="flashs3-bench-") as td:
                data_dir = Path(td)
                bind_cold = "127.0.0.1:19001"
                bind_warm = "127.0.0.1:19002"

                print("  phase 1: write + cold read (cache=None)")
                p1 = start_engine(data_dir, bind_cold, "None", args.cache_max_bytes)
                procs.append(p1)
                client = S3Client(f"http://{bind_cold}")
                ensure_bucket(client, "bench")

                work = [("PUT", f"/bench/{k}", payload) for k in keys]
                r = run_ops("write_put", client, work, args.concurrency)
                results.append(r)
                print_result(r)

                work_get = [("GET", f"/bench/{k}", payload) for k in keys]
                r_cold = run_ops("read_cold_uncached", client, work_get, args.concurrency)
                results.append(r_cold)
                print_result(r_cold)

                p1.terminate()
                p1.wait(timeout=10)
                procs.clear()

                print("  phase 2: warm read (cache=InMemoryLRU, same data)")
                p2 = start_engine(data_dir, bind_warm, "InMemoryLRU", args.cache_max_bytes)
                procs.append(p2)
                client2 = S3Client(f"http://{bind_warm}")

                # first pass fills cache from disk
                r_fill = run_ops("read_fill_cache", client2, work_get, args.concurrency)
                results.append(r_fill)
                print_result(r_fill)

                r_warm = run_ops("read_warm_cached", client2, work_get, args.concurrency)
                results.append(r_warm)
                print_result(r_warm)

                # speedup summary
                if r_cold.seconds > 0 and r_warm.ops_per_sec > 0:
                    print()
                    print(
                        f"  summary: warm/cold throughput ratio = "
                        f"{r_warm.ops_per_sec / max(r_cold.ops_per_sec, 0.001):.2f}x  "
                        f"(p50 cold {r_cold.latency_ms_p50:.2f}ms → warm {r_warm.latency_ms_p50:.2f}ms)"
                    )
                    print(
                        "  note: HTTP+SigV4 often dominates for small objects; OS page cache also"
                    )
                    print(
                        "        speeds 'cold' disk reads. For raw cache gains run:"
                    )
                    print(
                        "        cargo run -p flash-s3-engine --example micro_bench --release"
                    )

        if args.json_out:
            out = {
                "meta": {
                    "objects": args.objects,
                    "size": args.size,
                    "concurrency": args.concurrency,
                    "access_key": ACCESS,
                },
                "results": [asdict(r) | {"ops_per_sec": r.ops_per_sec, "mib_per_sec": r.mib_per_sec} for r in results],
            }
            Path(args.json_out).write_text(json.dumps(out, indent=2))
            print(f"\n  wrote {args.json_out}")

        if any(r.errors for r in results):
            print("\nWARNING: some operations returned errors", file=sys.stderr)
            return 1
        print("\nOK")
        return 0
    finally:
        for p in procs:
            p.terminate()
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()


if __name__ == "__main__":
    sys.exit(main())
