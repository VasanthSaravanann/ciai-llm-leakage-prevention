#!/usr/bin/env bash
set -euo pipefail

echo "Starting local OIDC test provider on port ${OIDC_TEST_PORT:-9000}"
python scripts/oidc_test_provider.py
