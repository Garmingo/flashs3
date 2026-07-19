#!/usr/bin/env python3
"""Run the same S3 HTTP/SigV4 workload against FlashS3, MinIO, and Garage.

The script starts one backend at a time, resets its Docker volume before each
run, and delegates request generation and result collection to benchmark.py.
It writes both the raw per-backend JSON and a combined, reproducible report.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = ROOT / "benchmarks" / "compose.yaml"
ENV_FILE = ROOT / "benchmarks" / ".env"
DEFAULT_ENV_FILE = ROOT / "benchmarks" / ".env.example"

BACKENDS = (
    ("flashs3", "http://127.0.0.1:19000"),
    ("minio", "http://127.0.0.1:19001"),
    ("garage", "http://127.0.0.1:19002"),
)

# Standard public comparison matrix: 2,000 objects at each requested object
# size and level of client concurrency. The order is intentional so the first
# run remains the historical 64 KiB / 16-client comparison.
STANDARD_WORKLOADS = tuple(
    {
        "objects": 2_000,
        "object_size_bytes": size,
        "concurrency": concurrency,
    }
    for size in (64 * 1024, 128 * 1024, 1024 * 1024)
    for concurrency in (16, 32, 1)
)


def load_env_file(path: Path) -> dict[str, str]:
    """Read the simple KEY=VALUE format used by the Compose environment file."""
    values: dict[str, str] = {}
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def compose(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("docker", "compose", "--env-file", str(ENV_FILE), "-f", str(COMPOSE_FILE), *args),
        cwd=ROOT,
        check=check,
        text=True,
    )


def wait_for_port(endpoint: str, timeout: int = 90) -> None:
    host_port = endpoint.removeprefix("http://").rsplit(":", 1)
    host, port = host_port[0], int(host_port[1])
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    raise TimeoutError(f"{endpoint} did not accept connections within {timeout}s")


def wait_for_s3(endpoint: str, timeout: int = 90) -> None:
    """Wait until the backend accepts an authenticated CreateBucket request."""
    # Imported lazily after BENCH_* values are copied into os.environ below.
    from benchmark import S3Client

    client = S3Client(endpoint)
    deadline = time.monotonic() + timeout
    last_error = "no response"
    while time.monotonic() < deadline:
        try:
            status, _, _ = client.request("PUT", "/bench")
            if status in (200, 409):
                return
            last_error = f"HTTP {status}"
        except Exception as error:  # connection resets are normal during startup
            last_error = str(error)
        time.sleep(0.5)
    raise TimeoutError(f"{endpoint} did not accept authenticated S3 requests: {last_error}")


def image_id(service: str) -> str:
    image = subprocess.run(
        (
            "docker",
            "inspect",
            "--format",
            "{{.Config.Image}}",
            f"flashs3-benchmark-{service}-1",
        ),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return subprocess.run(
        ("docker", "image", "inspect", "--format", "{{.Id}}", image),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def host_metadata() -> dict[str, str]:
    result = {
        "system": platform.platform(),
        "machine": platform.machine(),
    }
    if platform.system() == "Darwin":
        cpu = subprocess.run(
            ("sysctl", "-n", "machdep.cpu.brand_string"),
            check=False,
            capture_output=True,
            text=True,
        ).stdout.strip()
        memory = subprocess.run(
            ("sysctl", "-n", "hw.memsize"),
            check=False,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if cpu:
            result["cpu"] = cpu
        if memory:
            result["memory_bytes"] = memory
    return result


def workload_name(workload: dict[str, int]) -> str:
    """Return a stable, readable identifier for a workload."""
    size = workload["object_size_bytes"]
    if size % (1024 * 1024) == 0:
        size_label = f"{size // (1024 * 1024)}mib"
    else:
        size_label = f"{size // 1024}kib"
    return f'{workload["objects"]}x{size_label}-c{workload["concurrency"]}'


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare FlashS3, MinIO, and Garage with an identical S3 workload."
    )
    parser.add_argument(
        "--single",
        action="store_true",
        help="run only one custom workload instead of the standard 3 × 3 matrix",
    )
    parser.add_argument("--objects", type=int, default=2_000, help="used with --single")
    parser.add_argument("--size", type=int, default=64 * 1024, help="object size in bytes; used with --single")
    parser.add_argument("--concurrency", type=int, default=16, help="used with --single")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "benchmarks" / "results")
    args = parser.parse_args()

    if not ENV_FILE.exists():
        print(
            f"Missing {ENV_FILE.relative_to(ROOT)}. Copy "
            f"{DEFAULT_ENV_FILE.relative_to(ROOT)} and review the pinned images.",
            file=sys.stderr,
        )
        return 2

    benchmark_env = load_env_file(ENV_FILE)
    client_env = {
        "FLASHS3_ACCESS_KEY": benchmark_env["BENCH_ACCESS_KEY"],
        "FLASHS3_SECRET_KEY": benchmark_env["BENCH_SECRET_KEY"],
        "FLASHS3_REGION": benchmark_env["BENCH_REGION"],
    }
    # benchmark.py reads these once at module import time. Keeping them in the
    # parent environment also lets wait_for_s3 reuse its SigV4 implementation.
    os.environ.update(client_env)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    workloads = (
        ({"objects": args.objects, "object_size_bytes": args.size, "concurrency": args.concurrency},)
        if args.single
        else STANDARD_WORKLOADS
    )
    report: dict[str, Any] = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "host": host_metadata(),
        "protocol": "S3 path-style HTTP with SigV4",
        "workloads": [],
    }

    try:
        print(f"Running {len(workloads)} workload(s) across {len(BACKENDS)} backends.")
        for workload in workloads:
            name = workload_name(workload)
            print(f"\n## {name} ##")
            workload_report: dict[str, Any] = {**workload, "backends": {}}

            for service, endpoint in BACKENDS:
                print(f"\n== {service} ==")
                compose("down", "--volumes", "--remove-orphans", check=False)
                compose("up", "--detach", service)
                wait_for_port(endpoint)
                wait_for_s3(endpoint)

                output = args.output_dir / f"{run_id}-{name}-{service}.json"
                subprocess.run(
                    (
                        sys.executable,
                        str(ROOT / "scripts" / "benchmark.py"),
                        "--endpoint",
                        endpoint,
                        "--label",
                        service,
                        "--objects",
                        str(workload["objects"]),
                        "--size",
                        str(workload["object_size_bytes"]),
                        "--concurrency",
                        str(workload["concurrency"]),
                        "--json-out",
                        str(output),
                    ),
                    cwd=ROOT,
                    env=os.environ,
                    check=True,
                )
                workload_report["backends"][service] = {
                    "endpoint": endpoint,
                    "image_id": image_id(service),
                    "result_file": output.name,
                    "results": json.loads(output.read_text())["results"],
                }
            report["workloads"].append(workload_report)
    finally:
        compose("down", "--volumes", "--remove-orphans", check=False)

    report_file = args.output_dir / f"{run_id}-comparison.json"
    report_file.write_text(json.dumps(report, indent=2) + "\n")
    try:
        report_path = report_file.relative_to(ROOT)
    except ValueError:
        report_path = report_file
    print(f"\nWrote {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
