import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))   # so "import app" works

import pytest
from app.engines.e3_data_management import DataManagementService


@pytest.fixture
def svc(tmp_path):
    s = DataManagementService(str(tmp_path / "e3.db"), busy_timeout=0.2)
    s.user_id = s.create_user("System Admin", "soham", "s@x.in", "hash")
    return s


def make_run(svc, run_id="r1", **kw):
    run = dict(run_id=run_id, initiated_by=svc.user_id, file_name="conn.log", log_type="conn",
               run_mode="BENCHMARK", started_at="2026-11-14T10:00:00Z")
    run.update(kw)
    return svc.save_processing_run(run)


def ev(i, ip="10.0.0.1", ts="2026-11-14T10:00:00Z", **kw):
    e = dict(event_id=f"e{i}", event_timestamp=ts, source_ip=ip, source_port=40000 + i % 1000,
             destination_ip="10.0.0.9", destination_port=22, protocol="tcp", conn_state="REJ", orig_bytes=100)
    e.update(kw)
    return e
