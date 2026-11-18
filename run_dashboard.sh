#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

PYTHON_BIN="python3"
if [ -d ".venv/bin" ]; then
    PYTHON_BIN=".venv/bin/python"
fi

echo "Starting Team 14 Network Traffic Monitoring and Alert System..."
echo "Target Pipeline: E4 Dashboard -> PipelineCoordinator -> E1 -> E3 -> E2 -> E3 -> E4"
echo "Dashboard will be available at: http://127.0.0.1:8000"
echo ""

export PYTHONPATH="$PWD:$PWD/E3_E4_Backend/backend:$PWD/E2_Threat_Detection:$PWD/Integration/Contracts${PYTHONPATH:+:$PYTHONPATH}"

exec "$PYTHON_BIN" E3_E4_Backend/backend/main.py
