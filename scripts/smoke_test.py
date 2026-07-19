#!/usr/bin/env python3
"""Minimal SigV4 smoke test against a running flash-s3-engine."""

from __future__ import annotations

import hashlib
import hmac
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

ACCESS = "flash"
SECRET = "flashsecret"
REGION = "us-east-1"
HOST = "127.0.0.1:9000"
BASE = f"http://{HOST}"


def sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def uri_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="-_.~")


def sigv4_headers(method: str, url_path: str, payload: bytes, extra: dict[str, str] | None = None):
    parsed = urllib.parse.urlsplit(url_path)
    path = parsed.path or "/"
    # canonical query
    q = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    canonical_query = "&".join(f"{uri_encode(k)}={uri_encode(v)}" for k, v in sorted(q))

    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical_headers = f"host:{HOST}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = (
        f"{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    credential_scope = f"{date_stamp}/{REGION}/s3/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )
    k_date = sign(("AWS4" + SECRET).encode(), date_stamp)
    k_region = sign(k_date, REGION)
    k_service = sign(k_region, "s3")
    k_signing = sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth = (
        f"AWS4-HMAC-SHA256 Credential={ACCESS}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    headers = {
        "Host": HOST,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
        "Authorization": auth,
    }
    if extra:
        headers.update(extra)
    return headers


def req(method: str, path: str, data: bytes = b"", extra: dict[str, str] | None = None, auth: bool = True):
    headers = sigv4_headers(method, path, data, extra) if auth else dict(extra or {})
    body = data if method in ("PUT", "POST") else (data if data else None)
    r = urllib.request.Request(BASE + path, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def main() -> int:
    print("health", req("GET", "/healthz", auth=False)[0])
    status, _, body = req("PUT", "/demo")
    print("create bucket", status, body[:120])
    if status not in (200, 409):
        print(body)
        return 1
    payload = b"hello flashs3"
    status, hdrs, body = req("PUT", "/demo/hello.txt", payload, {"Content-Type": "text/plain"})
    print("put object", status, hdrs.get("ETag") or hdrs.get("etag"), body[:80])
    if status != 200:
        print(body)
        return 1
    status, _, body = req("GET", "/demo/hello.txt")
    print("get object", status, body)
    if body != payload:
        return 1
    status, _, body = req("PUT", "/demo/hello.txt?acl", b"", {"x-amz-acl": "public-read"})
    print("put acl", status, body[:120])
    if status != 200:
        return 1
    status, _, body = req("GET", "/demo/hello.txt", auth=False)
    print("anon get", status, body)
    if status != 200 or body != payload:
        return 1
    policy = b'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::demo/*"}]}'
    status, _, body = req("PUT", "/demo?policy", policy, {"Content-Type": "application/json"})
    print("put policy", status, body[:120])
    status, _, body = req("GET", "/demo")
    print("list", status, body[:200])
    # cache hit
    status, _, body = req("GET", "/demo/hello.txt")
    print("get cached", status, body)
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
