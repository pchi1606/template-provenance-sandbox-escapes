#!/usr/bin/env bash
# One-command reproduction of the S4 paper's headline numbers.
# Requirements: python3 (>= 3.10) with the venv module, and pip. A local
# virtualenv (.venv/) is created on first run and jinja2 is installed into
# it (needs network once); everything else is CPU-only and offline.
set -euo pipefail
cd "$(dirname "$0")"

echo "==> [1/5] Python check"
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found"; exit 1; }
python3 --version

echo "==> [2/5] Dependencies"
if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
fi
if ! .venv/bin/python -c "import jinja2" 2>/dev/null; then
  .venv/bin/pip install --quiet -r requirements.txt
else
  echo "jinja2 already available"
fi
PY=.venv/bin/python

echo "==> [3/5] Differential-testing harness (80 render cells)"
$PY code/full_harness.py

echo "==> [4/5] vLLM kwargs-override logic replay"
$PY code/vllm_kwargs_override_demo.py

echo "==> [5/5] Verifying headline numbers"
$PY scripts/verify_reproduction.py

echo "REPRODUCTION COMPLETE: all headline checks passed."
