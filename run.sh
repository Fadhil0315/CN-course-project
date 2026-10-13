#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ ! -x .venv/bin/python ]]; then
  printf 'Set up the Python 3.12+ virtual environment using README.md first.\n' >&2
  exit 1
fi
exec .venv/bin/python -m streamlit run app.py "$@"
