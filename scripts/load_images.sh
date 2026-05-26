#!/usr/bin/env bash
set -euo pipefail

# Load all tar archives from ./images directory into local Docker daemon
ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

IMAGES_DIR=images
if [ ! -d "$IMAGES_DIR" ]; then
  echo "No images directory found. Create an 'images' directory and place tar files there."
  exit 1
fi

for f in "$IMAGES_DIR"/*.tar; do
  [ -e "$f" ] || continue
  echo "Loading $f"
  docker load -i "$f"
done

echo "All images loaded. You can now run: bash scripts/start_from_images.sh"
