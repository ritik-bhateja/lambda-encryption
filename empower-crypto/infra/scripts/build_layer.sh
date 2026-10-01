#!/usr/bin/env bash
# Builds the Lambda layer into .build/layer/python:
#   empower_crypto.py + cryptography wheels for Lambda python3.12 on x86_64.
#
# Works on macOS, Windows (Git Bash / WSL) and Linux, with no Docker: pip
# downloads the Linux wheels directly instead of compiling anything.
# boto3 is NOT vendored, the Lambda runtime already provides it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/.build/layer/python"
PYTHON="${PYTHON:-python3}"

rm -rf "$ROOT/.build/layer"
mkdir -p "$OUT"

"$PYTHON" -m pip install \
  --quiet \
  --target "$OUT" \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 3.12 \
  --only-binary=:all: \
  --upgrade \
  "cryptography==43.0.1"

cp "$ROOT/layer/python/empower_crypto.py" "$OUT/"

# Trim what Lambda never needs.
find "$OUT" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "$OUT" -type d -name "tests" -path "*cffi*" -prune -exec rm -rf {} + 2>/dev/null || true

SIZE=$(du -sh "$ROOT/.build/layer" | cut -f1)
echo "layer built: .build/layer ($SIZE)"
for f in "$OUT"/*; do echo "  $(basename "$f")"; done
