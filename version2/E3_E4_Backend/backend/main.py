"""Start the API and dashboard:  python main.py   then open http://127.0.0.1:8000"""
import os
import sys
from pathlib import Path

# Ensure workspace root and all engines are on sys.path
_workspace_root = Path(__file__).resolve().parent.parent.parent
_e1_root = _workspace_root / "E1_Concurrent_Log_Processing"
_e2_root = _workspace_root / "E2_Threat_Detection"
_contracts_root = _workspace_root / "Integration" / "Contracts"

for p in (_workspace_root, _e1_root, _e2_root, _contracts_root):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

from app.engines.e3_data_management import DataManagementService
from app.engines.e4_api_dashboard import create_app
from Integration.Orchestration import PipelineCoordinator

service = DataManagementService(os.environ.get("E3_DB", "network_monitor.db"))
coordinator = PipelineCoordinator(service)
app = create_app(service, log_dir=os.environ.get("LOG_DIR", "logs"), processor=coordinator)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
