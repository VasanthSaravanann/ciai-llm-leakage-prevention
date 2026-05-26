#!/usr/bin/env bash
# Trigger the API CI workflow via GitHub CLI
set -e

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI not found. Install GitHub CLI and authenticate (gh auth login)."
  exit 2
fi

WORKFLOW=${1:-api-ci.yml}
REF=${2:-main}

echo "Triggering workflow $WORKFLOW on ref $REF..."
gh workflow run "$WORKFLOW" --ref "$REF"
echo "Triggered. Check Actions tab for progress."
