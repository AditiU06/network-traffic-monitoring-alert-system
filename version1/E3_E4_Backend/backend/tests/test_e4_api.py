import io
import time
import pytest
from conftest import make_run, ev
from app.engines.e4_api_dashboard import create_app
from app.engines.e4_api_dashboard.security import hash_password, verify_password

PW = "Demo@12345"


@pytest.fixture
def client(svc, tmp_path):
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "t.log").write_text(
        "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\torig_bytes\n"
        "1731578400.1\t10.1.1.1\t5000\t10.2.2.2\t80\ttcp\tSF\t100\n"
        "1731578401.2\t10.1.1.1\t5001\t10.2.2.2\t81\ttcp\tREJ\t-\n"
        "broken line\n")
    svc.create_user("Security Analyst", "ana", "a@x.in", hash_password(PW))
    svc.create_user("NetOps Admin", "ned", "n@x.in", hash_password(PW))
    svc.create_user("System Admin", "adm", "ad@x.in", hash_password(PW))
    app = create_app(svc, log_dir=tmp_path / "logs")
    app.testing = True
    return app.test_client()


def login(client, user="adm", pw=PW):
    r = client.post("/api/v1/auth/login", json={"username": user, "password": pw})
    return r, ({"Authorization": "Bearer " + r.get_json()["token"]} if r.status_code == 200 else {})


def seed(svc):
    make_run(svc)
    svc.insert_events_batch("r1", [ev(i, ts=f"2026-11-14T10:00:{i:02d}Z") for i in range(1, 6)])
    svc.save_alerts([dict(alert_id="a1", run_id="r1", severity="HIGH", rule_code="PORT_SCAN", affected_ip="10.0.0.1",
                          window_start="2026-11-14T10:00:00Z", detected_at="2026-11-14T10:00:30Z", related_event_ids=["e1", "e2"])])


def test_password_hashing():
    h = hash_password("secret123")
    assert verify_password("secret123", h) and not verify_password("wrong", h) and "secret123" not in h


def test_login_works_and_bad_login_is_generic(client):
    r, h = login(client)
    assert r.status_code == 200 and r.get_json()["user"]["role"] == "System Admin" and "start_run" in r.get_json()["user"]["permissions"]
    bad1 = client.post("/api/v1/auth/login", json={"username": "adm", "password": "nope"})
    bad2 = client.post("/api/v1/auth/login", json={"username": "ghost", "password": "nope"})
    assert bad1.status_code == bad2.status_code == 401 and bad1.get_json() == bad2.get_json()


def test_account_locks_after_five_failures(client):
    for _ in range(5):
        client.post("/api/v1/auth/login", json={"username": "ned", "password": "x"})
    assert client.post("/api/v1/auth/login", json={"username": "ned", "password": PW}).status_code == 429


def test_everything_needs_a_token(client):
    for path in ["/runs", "/logs?ip=1.1.1.1", "/alerts?status=OPEN", "/benchmarks", "/dashboard/summary"]:
        r = client.get("/api/v1" + path)
        assert r.status_code == 401 and r.get_json()["error"]["code"] == "UNAUTHENTICATED"
    assert client.get("/api/v1/runs", headers={"Authorization": "Bearer fake"}).status_code == 401


def test_logout_ends_the_session(client):
    _, h = login(client)
    assert client.get("/api/v1/auth/me", headers=h).status_code == 200
    client.post("/api/v1/auth/logout", headers=h)
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401


def test_roles_are_enforced(client, svc):
    seed(svc)
    _, ned = login(client, "ned"); _, ana = login(client, "ana")
    assert client.patch("/api/v1/alerts/a1", json={"status": "RESOLVED"}, headers=ned).status_code == 403
    assert client.post("/api/v1/runs", json={"mode": "sequential", "threads": 2, "logFile": "t.log"}, headers=ana).status_code == 403
    assert client.patch("/api/v1/alerts/a1", json={"status": "resolved"}, headers=ana).status_code == 200
    assert client.get("/api/v1/alerts/a1", headers=ned).get_json()["alertStatus"] == "RESOLVED"


def test_start_run_validation(client):
    _, h = login(client)
    post = lambda **b: client.post("/api/v1/runs", json=b, headers=h)
    for threads in (0, 17, "x", 2.5):
        r = post(mode="sequential", threads=threads, logFile="t.log")
        assert r.status_code == 400 and r.get_json()["error"]["code"] == "INVALID_THREADS"
    assert post(mode="turbo", threads=2, logFile="t.log").status_code == 400
    assert post(mode="sequential", threads=2, logFile="missing.log").status_code == 404
    assert post(mode="sequential", threads=2, logFile="../../etc/passwd").status_code == 400
    assert post(mode="sequential", threads=2, logFile="/etc/passwd").status_code == 400
    assert post(mode="sequential", threads=2, logFile="t.log", extra=1).status_code == 400


def test_start_run_end_to_end(client):
    _, h = login(client)
    r = client.post("/api/v1/runs", json={"mode": "multithreaded", "threads": 4, "logFile": "t.log"}, headers=h)
    assert r.status_code == 202 and r.get_json()["status"] == "RUNNING"
    run_id = r.get_json()["runId"]
    for _ in range(50):
        d = client.get(f"/api/v1/runs/{run_id}", headers=h).get_json()
        if d["status"] != "RUNNING":
            break
        time.sleep(0.1)
    assert d["status"] == "COMPLETED" and d["validCount"] == 2 and d["malformedCount"] == 1
    assert d["metrics"][0]["workerCount"] == 4
    logs = client.get(f"/api/v1/logs?runId={run_id}", headers=h).get_json()
    assert logs["total"] == 2 and logs["items"][0]["sourceIp"] == "10.1.1.1"
    assert any(i["origBytes"] is None for i in logs["items"])      # '-' stayed empty


def test_logs_and_alerts_filters(client, svc):
    seed(svc); _, h = login(client)
    r = client.get("/api/v1/logs?ip=10.0.0.1&from=2026-11-14T10:00:02Z&to=2026-11-14T10:00:04Z&size=10", headers=h).get_json()
    assert r["total"] == 3 and set(r) == {"total", "page", "size", "items"}
    assert client.get("/api/v1/logs", headers=h).status_code == 400
    assert client.get("/api/v1/logs?ip=10.0.0.1&from=yesterday", headers=h).status_code == 400
    assert client.get("/api/v1/logs?ip=10.0.0.1&page=0", headers=h).status_code == 400
    assert client.get("/api/v1/alerts", headers=h).get_json()["error"]["code"] == "BAD_FILTER"
    assert client.get("/api/v1/alerts?severity=high", headers=h).get_json()["items"][0]["severityName"] == "HIGH"
    assert client.get("/api/v1/alerts/nope", headers=h).status_code == 404
    assert len(client.get("/api/v1/alerts/a1", headers=h).get_json()["events"]) == 2


def test_summary_and_benchmarks(client, svc):
    seed(svc)
    svc.save_performance_results("r1", [dict(execution_mode="SEQUENTIAL", worker_count=1, execution_time_sec=10.0),
                                        dict(execution_mode="MULTITHREADED", worker_count=8, execution_time_sec=4.0)],
                                 dict(speedup_ratio=2.5, equivalence_status="PASS"))
    _, h = login(client)
    s = client.get("/api/v1/dashboard/summary", headers=h).get_json()
    assert s["eventsStored"] == 5 and s["alertsBySeverity"]["HIGH"] == 1
    b = client.get("/api/v1/benchmarks", headers=h).get_json()["items"][0]
    assert b["speedupRatio"] == 2.5 and len(b["metrics"]) == 2 and b["metrics"][0]["executionMode"] == "MULTITHREADED"


def test_errors_never_leak_internals(client, svc, monkeypatch):
    _, h = login(client)
    monkeypatch.setattr(svc, "list_runs", lambda **k: 1 / 0)
    r = client.get("/api/v1/runs", headers=h)
    assert r.status_code == 500 and r.get_json() == {"error": {"code": "INTERNAL_ERROR", "message": "Something went wrong on the server."}}
    assert client.get("/api/v1/nothing", headers=h).get_json()["error"]["code"] == "NOT_FOUND"


def test_dashboard_page_and_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and b"Network Traffic Monitor" in r.data
    assert r.headers["X-Frame-Options"] == "DENY" and "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/..%2f..%2fmain.py").status_code in (400, 404)


def test_severity_order_is_kept(client, svc):
    _, h = login(client)
    keys = list(client.get("/api/v1/dashboard/summary", headers=h).get_json()["alertsBySeverity"])
    assert keys == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def test_list_and_upload_log_files(client):
    _, h = login(client)
    r = client.get("/api/v1/logs/files", headers=h)
    assert r.status_code == 200
    assert any(f["fileName"] == "t.log" for f in r.get_json()["files"])

    r = client.post("/api/v1/logs/upload", headers=h)
    assert r.status_code == 400 and r.get_json()["error"]["code"] == "NO_FILE"

    data = {
        "file": (io.BytesIO(b"#fields\tts\tid.orig_h\n1.0\t1.1.1.1\n"), "uploaded.log"),
        "runImmediately": "false"
    }
    r = client.post("/api/v1/logs/upload", data=data, content_type="multipart/form-data", headers=h)
    assert r.status_code == 200 and r.get_json()["status"] == "UPLOADED"
    assert r.get_json()["fileName"] == "uploaded.log"

    data_run = {
        "file": (io.BytesIO(b"#fields\tts\tid.orig_h\n2.0\t2.2.2.2\n"), "upload_run.log"),
        "runImmediately": "true",
        "mode": "sequential",
        "threads": "2"
    }
    r = client.post("/api/v1/logs/upload", data=data_run, content_type="multipart/form-data", headers=h)
    assert r.status_code == 202 and r.get_json()["status"] == "RUNNING"
    assert "runId" in r.get_json()
