#!/usr/bin/env bash
# Builds TWO Lambda layers:
#
#   Layer 1 (deps):  cryptography wheels only  -> .build/layer-deps/python/
#   Layer 2 (code):  payload_crypto.py only    -> .build/layer-code/python/
#
# Layer 2 imports from Layer 1 at runtime (Lambda puts both on sys.path).
# No Docker: pip downloads the Linux x86_64 wheels directly.
# boto3 is not vendored; the Lambda runtime provides it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${PYTHON:-python3}"

# ── Layer 1: cryptography dependency ────────────────────────────────────────
DEPS_OUT="$ROOT/.build/layer-deps/python"
rm -rf "$ROOT/.build/layer-deps"
mkdir -p "$DEPS_OUT"

"$PYTHON" -m pip install --quiet --target "$DEPS_OUT" \
  --platform manylinux2014_x86_64 --implementation cp --python-version 3.12 \
  --only-binary=:all: --upgrade "cryptography==43.0.1"

find "$DEPS_OUT" -type d -name "__pycache__" -prune -exec rm -rf {} +
echo "layer-deps built: .build/layer-deps ($(du -sh "$ROOT/.build/layer-deps" | cut -f1))"

# ── Layer 2: payload_crypto.py source ────────────────────────────────────────
CODE_OUT="$ROOT/.build/layer-code/python"
rm -rf "$ROOT/.build/layer-code"
mkdir -p "$CODE_OUT"

cp "$ROOT/layer/python/payload_crypto.py" "$CODE_OUT/"
echo "layer-code built: .build/layer-code ($(du -sh "$ROOT/.build/layer-code" | cut -f1))"

# ── Keep .build/layer as a combined artifact for backwards compatibility ─────
# (existing deployments that reference the old single layer still work)
COMBINED_OUT="$ROOT/.build/layer/python"
rm -rf "$ROOT/.build/layer"
mkdir -p "$COMBINED_OUT"
cp -r "$DEPS_OUT"/. "$COMBINED_OUT/"
cp "$ROOT/layer/python/payload_crypto.py" "$COMBINED_OUT/"
find "$COMBINED_OUT" -type d -name "__pycache__" -prune -exec rm -rf {} +
echo "layer (combined, backwards-compat) built: .build/layer ($(du -sh "$ROOT/.build/layer" | cut -f1))"
