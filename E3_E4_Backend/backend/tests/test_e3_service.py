import sqlite3
import threading
import time
from conftest import make_run, ev


def test_many_threads_writing_at_once(svc):
    for k in range(8):
        make_run(svc, run_id=f"r{k}")
    errors = []

    def work(k):
        try:
            for b in range(5):
                r = svc.insert_events_batch(f"r{k}", [ev(k * 1000 + b * 100 + i) for i in range(100)])
                assert r["inserted"] == 100
        except Exception as ex:
            errors.append(ex)

    ts = [threading.Thread(target=work, args=(k,)) for k in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert not errors
    assert svc.get_dashboard_summary()["events_stored"] == 8 * 500


def test_busy_database_queues_then_flushes(svc):
    make_run(svc)
    other = sqlite3.connect(svc.db_path, isolation_level=None)
    other.execute("BEGIN IMMEDIATE")                       # someone else is holding the write lock
    r = svc.insert_events_batch("r1", [ev(1), ev(2)])
    assert r["status"] == "QUEUED" and len(svc.retry_buffer) == 1
    other.execute("COMMIT"); other.close()
    flushed = svc.flush_retry_buffer()
    assert flushed[0]["inserted"] == 2 and not svc.retry_buffer


def test_failed_batch_leaves_nothing_behind(svc):
    make_run(svc)
    try:
        svc._write(lambda c: (_ for _ in ()).throw(RuntimeError("boom")))
    except RuntimeError:
        pass
    # a batch with one invalid alert-style error mid-way must not half-save: use the DB directly
    from app.database.db import transaction
    c = svc._conn()
    try:
        with transaction(c):
            c.execute("INSERT INTO protocol (protocol_name) VALUES ('temp')")
            raise RuntimeError("fail midway")
    except RuntimeError:
        pass
    assert c.execute("SELECT COUNT(*) FROM protocol WHERE protocol_name='temp'").fetchone()[0] == 0


def test_search_is_fast_on_50k_events(svc):
    make_run(svc)
    for b in range(10):
        svc.insert_events_batch("r1", [ev(b * 5000 + i, ip=f"10.0.{(i % 50)}.1", ts=1731578400 + b * 5000 + i) for i in range(5000)])
    assert svc.get_dashboard_summary()["events_stored"] == 50000
    for _ in range(20):
        svc.search_events(source_ip="10.0.7.1", from_ts=1731578400, to_ts=1731578400 + 20000, size=50)
    rep = svc.monitor.report()["search_events"]
    print("search_events:", rep)
    assert rep["mean_ms"] < 50
