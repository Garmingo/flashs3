#!/usr/bin/env bash
# Ceph s3-tests coverage benchmark against a local flash-s3-engine.
#
# This is NOT a CI gate and is intentionally separate from `cargo test`.
# Failures are expected for unimplemented S3 surface area; the script prints a
# summary and exits 0 unless the engine failed to start.
#
# Usage:
#   ./scripts/test-spec-coverage.sh
#   S3_TESTS_FILTER='s3tests/functional/test_s3.py' ./scripts/test-spec-coverage.sh
#   S3_TESTS_FILTER='s3tests/functional/test_s3.py::test_bucket_list_empty' ./scripts/test-spec-coverage.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="${ROOT}/.cache"
S3_TESTS_DIR="${CACHE}/s3-tests"
VENV_DIR="${CACHE}/s3-tests-venv"
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
# Core S3 surface only by default. IAM/STS/s3select need separate services and
# would drown the summary in ClientError(Unknown) / setup noise.
# Override: S3_TESTS_FILTER='s3tests/functional' ./scripts/test-spec-coverage.sh
S3_TESTS_FILTER="${S3_TESTS_FILTER:-s3tests/functional/test_s3.py s3tests/functional/test_headers.py}"

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

echo "==> Preparing Python venv at ${VENV_DIR}"
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  python3 -m venv "${VENV_DIR}"
fi
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
python -m pip install --upgrade pip wheel setuptools >/dev/null
python -m pip install -r "${S3_TESTS_DIR}/requirements.txt" >/dev/null
python -m pip install -e "${S3_TESTS_DIR}" >/dev/null
echo "    python   : $(command -v python) ($(python --version 2>&1))"
echo "    pytest   : $(python -c 'import pytest; print(pytest.__version__)')"

echo "==> Seeding credentials.json (main + alt)"
python - <<PY
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

echo "==> Writing s3tests.conf from upstream SAMPLE + local overrides"
python - <<PY
import hashlib
from configparser import RawConfigParser
from pathlib import Path

sample = Path("${S3_TESTS_DIR}/s3tests.conf.SAMPLE")
out = Path("${CONF}")
cfg = RawConfigParser()
cfg.read(sample)

def cid(ak: str) -> str:
    return hashlib.sha256(ak.encode()).hexdigest()

main_ak = "${ACCESS_KEY}"
main_sk = "${SECRET_KEY}"
alt_ak = "${ALT_ACCESS}"
alt_sk = "${ALT_SECRET}"
main_uid = cid(main_ak)
alt_uid = cid(alt_ak)

cfg["DEFAULT"]["host"] = "${BIND_HOST}"
cfg["DEFAULT"]["port"] = "${BIND_PORT}"
cfg["DEFAULT"]["is_secure"] = "False"
cfg["DEFAULT"]["ssl_verify"] = "False"

cfg["fixtures"]["bucket prefix"] = "flashs3-s3tests-{random}-"

cfg["s3 main"]["display_name"] = "main"
cfg["s3 main"]["user_id"] = main_uid
cfg["s3 main"]["email"] = "main@flashs3.local"
cfg["s3 main"]["api_name"] = "us-east-1"
cfg["s3 main"]["access_key"] = main_ak
cfg["s3 main"]["secret_key"] = main_sk

cfg["s3 alt"]["display_name"] = "alt"
cfg["s3 alt"]["user_id"] = alt_uid
cfg["s3 alt"]["email"] = "alt@flashs3.local"
cfg["s3 alt"]["access_key"] = alt_ak
cfg["s3 alt"]["secret_key"] = alt_sk

cfg["s3 tenant"]["display_name"] = "tenant"
cfg["s3 tenant"]["user_id"] = alt_uid
cfg["s3 tenant"]["email"] = "tenant@flashs3.local"
cfg["s3 tenant"]["access_key"] = alt_ak
cfg["s3 tenant"]["secret_key"] = alt_sk
cfg["s3 tenant"]["tenant"] = "flashs3"

# IAM sections are required at configure() time even if those tests are skipped.
for section, ak, sk, uid, email, display in [
    ("iam", main_ak, main_sk, main_uid, "iam@flashs3.local", "main"),
    ("iam root", main_ak, main_sk, main_uid, "iam-root@flashs3.local", "main"),
    ("iam alt root", alt_ak, alt_sk, alt_uid, "iam-alt@flashs3.local", "alt"),
]:
    if not cfg.has_section(section):
        cfg.add_section(section)
    cfg[section]["access_key"] = ak
    cfg[section]["secret_key"] = sk
    cfg[section]["user_id"] = uid
    cfg[section]["email"] = email
    cfg[section]["display_name"] = display
    if section.startswith("iam") and "root" in section:
        cfg[section]["account_id"] = uid

with out.open("w") as f:
    cfg.write(f)
print(out)
PY

echo "==> Running s3-tests via pytest (failures expected; coverage benchmark only)"
set +e
(
  cd "${S3_TESTS_DIR}"
  # Prefer an explicit path under s3tests/; fall back if caller passed a custom filter.
  FILTER_ARGS=()
  # shellcheck disable=SC2206
  FILTER_ARGS=(${S3_TESTS_FILTER})
  S3TEST_CONF="${CONF}" python -m pytest "${FILTER_ARGS[@]}" -q --tb=line 2>&1 \
    | tee "${DATA_DIR}/s3tests.out"
)
STATUS=${PIPESTATUS[0]}
set -e

echo
echo "==> Coverage summary"
if [[ -f "${DATA_DIR}/s3tests.out" ]]; then
  # pytest short summary / progress line
  grep -E 'passed|failed|error|skipped|xfailed|xpassed|====' "${DATA_DIR}/s3tests.out" | tail -40 || true
  cp -f "${DATA_DIR}/s3tests.out" "${CACHE}/s3tests-last.out" 2>/dev/null || true
  # Compact counts if present
  if grep -qE '[0-9]+ (passed|failed)' "${DATA_DIR}/s3tests.out"; then
    echo
    echo "Last pytest result line:"
    grep -E '[0-9]+ (passed|failed|error|skipped)' "${DATA_DIR}/s3tests.out" | tail -3 || true
  fi
  # Distinguish cascade setup errors from real assertion failures.
  SETUP_ERRS=$(grep -c 'ERROR at setup of' "${DATA_DIR}/s3tests.out" 2>/dev/null || true)
  BUCKET_NE=$(grep -c 'BucketNotEmpty' "${DATA_DIR}/s3tests.out" 2>/dev/null || true)
  echo
  echo "Note: pytest ERROR usually means exception during fixture setup/teardown"
  echo "      (e.g. cleanup DeleteBucket), not an assertion failure (FAILED)."
  echo "      setup_errors≈${SETUP_ERRS:-0}  BucketNotEmpty mentions≈${BUCKET_NE:-0}"
fi
cp -f "${ENGINE_LOG}" "${CACHE}/s3tests-engine-last.log" 2>/dev/null || true

echo
echo "Benchmark finished (pytest exit=${STATUS})."
echo "Always exiting 0 so this never gates CI; see .cache/s3tests-last.out"
exit 0
