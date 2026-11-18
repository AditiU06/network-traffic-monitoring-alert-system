#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

PYTHON_BIN="python3"
if [ -d ".venv/bin" ]; then
    PYTHON_BIN=".venv/bin/python"
fi

export PYTHONPATH="$PWD:$PWD/E3_E4_Backend/backend:$PWD/E2_Threat_Detection:$PWD/Integration/Contracts${PYTHONPATH:+:$PYTHONPATH}"

echo "============================================================================"
echo "1/3 Running E2 Threat Detection Tests (44 tests)..."
echo "============================================================================"
"$PYTHON_BIN" -m unittest discover -s E2_Threat_Detection/tests -v

echo ""
echo "============================================================================"
echo "2/3 Running E3/E4 Backend Tests (46 tests)..."
echo "============================================================================"
"$PYTHON_BIN" -m pytest E3_E4_Backend/backend/tests -q

echo ""
echo "============================================================================"
echo "3/3 Running Integration Coordinator Tests (3 tests)..."
echo "============================================================================"
"$PYTHON_BIN" -m pytest Integration/Orchestration/test_coordinator.py -v

echo ""
echo "============================================================================"
echo "ALL 93 TESTS PASSED SUCCESSFULLY!"
echo "============================================================================"
