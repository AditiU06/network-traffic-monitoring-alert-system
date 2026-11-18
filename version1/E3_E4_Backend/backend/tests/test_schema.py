import sqlite3
import pytest
from app.database.db import get_connection, init_db


@pytest.fixture
def conn(tmp_path):
    c = get_connection(str(tmp_path / "t.db"))
    init_db(c)
    c.execute("INSERT INTO user_account (role_id, username, email, password_hash) VALUES (1,'soham','s@x.in','h')")
    yield c
    c.close()


def add_run(c, run_id="r1", valid=2, bad=1):
    c.execute("""INSERT INTO processing_run (run_id, initiated_by, file_name, log_type, run_mode, started_at,
                 input_count, valid_count, malformed_count)
                 VALUES (?,?,?,?,?,?,?,?,?)""", (run_id, 1, "conn.log", "conn", "BENCHMARK", "2026-11-14T10:00:00Z", valid + bad, valid, bad))


def add_event(c, event_id="e1", run_id="r1", **kw):
    cols = dict(event_id=event_id, run_id=run_id, event_timestamp="2026-11-14T10:00:01Z",
                source_ip="10.0.0.1", destination_ip="10.0.0.2"); cols.update(kw)
    c.execute(f"INSERT INTO network_event ({','.join(cols)}) VALUES ({','.join('?'*len(cols))})", list(cols.values()))


def test_tables_and_seed_data(conn):
    n = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchone()[0]
    assert n == 13  # 12 entities + the alert_event_link table
    assert conn.execute("SELECT COUNT(*) FROM severity_level").fetchone()[0] == 4


def test_counts_must_add_up(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("""INSERT INTO processing_run (run_id, initiated_by, file_name, log_type, run_mode, started_at,
                        input_count, valid_count, malformed_count) VALUES ('bad',1,'f','conn','BENCHMARK','t',10,3,3)""")


def test_event_needs_real_run(conn):
    with pytest.raises(sqlite3.IntegrityError):
        add_event(conn, run_id="does-not-exist")


def test_port_range(conn):
    add_run(conn)
    with pytest.raises(sqlite3.IntegrityError):
        add_event(conn, source_port=70000)


def test_unknown_bytes_stay_null(conn):
    add_run(conn); add_event(conn)
    assert conn.execute("SELECT orig_bytes FROM network_event").fetchone()[0] is None


def test_worker_count_1_to_16(conn):
    add_run(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO performance_metric (run_id, execution_mode, worker_count, execution_time_sec) VALUES ('r1','MULTITHREADED',17,1.0)")


def test_no_duplicate_alert(conn):
    add_run(conn)
    q = "INSERT INTO alert (alert_id, run_id, severity_id, rule_code, affected_ip, window_start, detected_at) VALUES (?,?,?,?,?,?,?)"
    conn.execute(q, ("a1", "r1", 2, "PORT_SCAN", "10.0.0.1", "w", "d"))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(q, ("a2", "r1", 2, "PORT_SCAN", "10.0.0.1", "w", "d"))


def test_deleting_run_cascades(conn):
    add_run(conn); add_event(conn)
    conn.execute("DELETE FROM processing_run WHERE run_id='r1'")
    assert conn.execute("SELECT COUNT(*) FROM network_event").fetchone()[0] == 0


def test_cannot_delete_severity_in_use(conn):
    add_run(conn)
    conn.execute("INSERT INTO alert (alert_id, run_id, severity_id, rule_code, affected_ip, window_start, detected_at) VALUES ('a1','r1',2,'X','1.1.1.1','w','d')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM severity_level WHERE severity_id=2")


def test_legacy_database_migration(tmp_path):
    """Verifies that an existing database missing the new columns is safely migrated."""
    legacy_db = tmp_path / "legacy.db"
    c = get_connection(str(legacy_db))
    # Create minimal legacy tables without new columns
    c.execute("CREATE TABLE processing_run (run_id TEXT PRIMARY KEY, started_at TEXT)")
    c.execute("CREATE TABLE network_event (event_id TEXT PRIMARY KEY, run_id TEXT, event_timestamp TEXT, source_ip TEXT, destination_ip TEXT)")
    
    # Run init_db which should perform migration
    init_db(c)
    
    cols = {r["name"] for r in c.execute("PRAGMA table_info(network_event)").fetchall()}
    for expected in ("uid", "history", "total_bytes", "total_packets", "bytes_per_packet", "orig_to_resp_ratio"):
        assert expected in cols
    c.close()
