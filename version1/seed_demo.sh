#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

PYTHON_BIN="python3"
if [ -d ".venv/bin" ]; then
    PYTHON_BIN=".venv/bin/python"
fi

export PYTHONPATH="$PWD:$PWD/E3_E4_Backend/backend:$PWD/E2_Threat_Detection:$PWD/Integration/Contracts${PYTHONPATH:+:$PYTHONPATH}"

exec "$PYTHON_BIN" E3_E4_Backend/backend/seed_demo.py "$@"
