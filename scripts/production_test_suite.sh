#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"
if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="python"
fi

PRODUCTION_URL="${PRODUCTION_URL:-https://ldot-ssr-2.vercel.app}"
API_URL="${API_URL:-}"
API_KEY="${API_KEY:-}"

echo "=== CIAI Production Test Suite ==="
echo "Production URL: $PRODUCTION_URL"
echo

echo "[1/4] Unit tests"
"$PYTHON_BIN" -m pytest -q tests/test_detection.py

echo
echo "[2/4] Detection benchmark"
"$PYTHON_BIN" -m pytest -q tests/test_detection_benchmark.py

echo
echo "[3/4] Security audit"
"$PYTHON_BIN" tests/security_audit.py

echo
echo "[4/4] Production smoke checks"

check_page() {
  local path="$1"
  local expected="$2"
  local body
  body="$(curl -fsS "$PRODUCTION_URL$path")"
  if ! grep -Fq "$expected" <<<"$body"; then
    echo "Smoke check failed for $path"
    echo "Expected to find: $expected"
    exit 1
  fi
  echo "  ✓ $path"
}

check_page "/" "Autonomous Prompt Security Layer"
check_page "/metrics" "Security Metrics"
check_page "/simulator" "Sandbox Simulator"
check_page "/governance" "Proxy Governance"

if [[ -n "$API_URL" && -n "$API_KEY" ]]; then
  echo
  echo "Running API smoke tests against $API_URL"
  API_URL="$API_URL" API_KEY="$API_KEY" bash scripts/smoke_test.sh
else
  echo
  echo "API_URL/API_KEY not set; skipped API smoke tests."
fi

echo
echo "Production test suite completed successfully."