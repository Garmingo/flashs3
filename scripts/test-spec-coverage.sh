#!/usr/bin/env bash
# Ceph s3-tests coverage benchmark against a local flash-s3-engine.
#
# This is NOT a CI gate and is intentionally separate from `cargo test`.
# Failures are expected for unimplemented S3 surface area; the script prints a
# summary and exits 0 unless the engine failed to start.
#
# Usage:
#   ./scripts/test-spec-coverage.sh
#   S3_TESTS_FILTER='s3tests_boto3/functional/test_s3.py' ./scripts/test-spec-coverage.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="${ROOT}/.cache"
S3_TESTS_DIR="${CACHE}/s3-tests"
DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/flashs3-s3tests.XXXXXX")"
ENGINE_LOG="${DATA_DIR}/engine.log"
CONF="${DATA_DIR}/s3tests.conf"
BIND_HOST="127.0.0.1"
BIND_PORT="${FLASHS3_SPEC_PORT:-19090}"
ACCESS_KEY="FLASHTESTMAIN"
SECRET_KEY="flashsecretmainxxxxxxxxxxxxxxxxxxxx"
ALT_ACCESS="FLASHTESTALT"
ALT_SECRET="flashsecretaltxxxxxxxxxxxxxxxxxxxxx"
S3_TESTS_REPO="${S3_TESTS_REPO:-https://github.com/ceph/s3-tests.git}"
S3_TESTS_FILTER="${S3_TESTS_FILTER:-s3tests_boto3/functional}"

cleanup() {
  if [[ -n "${ENGINE_PID:-}" ]] && kill -0 "${ENGINE_PID}" 2>/dev/null; then
    kill "${ENGINE_PID}" 2>/dev/null || true
    wait "${ENGINE_PID}" 2>/dev/null || true
  fi
  rm -rf "${DATA_DIR}"
}
trap cleanup EXIT

echo "==> FlashS3 Ceph s3-tests coverage benchmark"
echo "    data dir : ${DATA_DIR}"
echo "    endpoint : http://${BIND_HOST}:${BIND_PORT}"
echo "    filter   : ${S3_TESTS_FILTER}"
echo

command -v cargo >/dev/null || { echo "error: cargo is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "error: python3 is required" >&2; exit 1; }
command -v curl >/dev/null || { echo "error: curl is required" >&2; exit 1; }

mkdir -p "${CACHE}" "${DATA_DIR}/data"
if [[ ! -d "${S3_TESTS_DIR}/.git" ]]; then
  echo "==> Cloning ceph/s3-tests into ${S3_TESTS_DIR}"
  git clone --depth 1 "${S3_TESTS_REPO}" "${S3_TESTS_DIR}"
else
  echo "==> Using cached s3-tests at ${S3_TESTS_DIR}"
fi

echo "==> Seeding credentials.json (main + alt)"
python3 - <<PY
import hashlib, json, pathlib
def cid(ak: str) -> str:
    return hashlib.sha256(ak.encode()).hexdigest()
path = pathlib.Path("${DATA_DIR}/data/credentials.json")
doc = {
    "keys": [
        {
            "access_key": "${ACCESS_KEY}",
            "secret_key": "${SECRET_KEY}",
            "canonical_id": cid("${ACCESS_KEY}"),
            "display_name": "main",
            "is_root": True,
            "status": "active",
        },
        {
            "access_key": "${ALT_ACCESS}",
            "secret_key": "${ALT_SECRET}",
            "canonical_id": cid("${ALT_ACCESS}"),
            "display_name": "alt",
            "is_root": False,
            "status": "active",
        },
    ]
}
path.write_text(json.dumps(doc, indent=2))
print(path)
PY

echo "==> Building flash-s3-engine"
cargo build -p flash-s3-engine --quiet

echo "==> Starting flash-s3-engine"
FLASHS3_DATA_DIR="${DATA_DIR}/data" \
FLASHS3_BIND="${BIND_HOST}:${BIND_PORT}" \
FLASHS3_REGION="us-east-1" \
FLASHS3_AUTH_REQUIRED=false \
  "${ROOT}/target/debug/flash-s3-engine" >"${ENGINE_LOG}" 2>&1 &
ENGINE_PID=$!

for _ in $(seq 1 50); do
  if curl -sf "http://${BIND_HOST}:${BIND_PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${ENGINE_PID}" 2>/dev/null; then
    echo "error: engine exited early; log:" >&2
    cat "${ENGINE_LOG}" >&2 || true
    exit 1
  fi
  sleep 0.1
done
if ! curl -sf "http://${BIND_HOST}:${BIND_PORT}/healthz" >/dev/null 2>&1; then
  echo "error: engine did not become healthy" >&2
  cat "${ENGINE_LOG}" >&2 || true
  exit 1
fi
echo "==> Engine healthy (pid ${ENGINE_PID})"

cat >"${CONF}" <<EOF
[DEFAULT]

[fixtures]
bucket prefix = flashs3-s3tests-{random}-

[s3 main]
display_name = main
user_id = ${ACCESS_KEY}
email = main@flashs3.local
access_key = ${ACCESS_KEY}
secret_key = ${SECRET_KEY}
api_name = flashs3
host = ${BIND_HOST}
port = ${BIND_PORT}
is_secure = no

[s3 alt]
display_name = alt
user_id = ${ALT_ACCESS}
email = alt@flashs3.local
access_key = ${ALT_ACCESS}
secret_key = ${ALT_SECRET}

[s3 tenant]
display_name = alt
user_id = ${ALT_ACCESS}
email = alt@flashs3.local
access_key = ${ALT_ACCESS}
secret_key = ${ALT_SECRET}
EOF

echo "==> Running s3-tests (failures expected; coverage benchmark only)"
set +e
(
  cd "${S3_TESTS_DIR}"
  if [[ -f tox.ini ]] && command -v tox >/dev/null; then
    S3TEST_CONF="${CONF}" tox -- "${S3_TESTS_FILTER}" 2>&1 | tee "${DATA_DIR}/s3tests.out"
  elif [[ -f tox.ini ]]; then
    python3 -m pip install --user 'tox' >/dev/null 2>&1 || true
    S3TEST_CONF="${CONF}" python3 -m tox -- "${S3_TESTS_FILTER}" 2>&1 | tee "${DATA_DIR}/s3tests.out"
  else
    python3 -m pip install --user pytest boto3 botocore >/dev/null 2>&1 || true
    S3TEST_CONF="${CONF}" python3 -m pytest "${S3_TESTS_FILTER}" -q --tb=line 2>&1 | tee "${DATA_DIR}/s3tests.out"
  fi
)
STATUS=$?
set -e

echo
echo "==> Coverage summary"
if [[ -f "${DATA_DIR}/s3tests.out" ]]; then
  grep -E 'passed|failed|error|skipped|=+' "${DATA_DIR}/s3tests.out" | tail -30 || true
  cp -f "${DATA_DIR}/s3tests.out" "${CACHE}/s3tests-last.out" 2>/dev/null || true
fi
cp -f "${ENGINE_LOG}" "${CACHE}/s3tests-engine-last.log" 2>/dev/null || true

echo
echo "Benchmark finished (s3-tests exit=${STATUS})."
echo "Always exiting 0 so this never gates CI; see .cache/s3tests-last.out"
exit 0
