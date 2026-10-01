#!/usr/bin/env bash
# Builds the payload_crypto Lambda layer into .build/layer/python:
#   payload_crypto.py + cryptography wheels for Lambda python3.12 on x86_64.
# No Docker: pip downloads the Linux wheels directly. boto3 is not vendored,
# the Lambda runtime provides it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/.build/layer/python"
PYTHON="${PYTHON:-python3}"

rm -rf "$ROOT/.build/layer"
mkdir -p "$OUT"

"$PYTHON" -m pip install --quiet --target "$OUT" \
  --platform manylinux2014_x86_64 --implementation cp --python-version 3.12 \
  --only-binary=:all: --upgrade "cryptography==43.0.1"

cp "$ROOT/layer/python/payload_crypto.py" "$OUT/"
find "$OUT" -type d -name "__pycache__" -prune -exec rm -rf {} +

echo "layer built: .build/layer ($(du -sh "$ROOT/.build/layer" | cut -f1))"
