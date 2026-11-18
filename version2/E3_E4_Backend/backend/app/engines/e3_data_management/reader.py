"""Everything that only READS. Every value goes in as a ? parameter, never glued into the SQL text."""
import sqlite3
import time

from .errors import AlertNotFound, InvalidFilterError, QueryTimeout, RunNotFound
from .validation import to_utc_text

MAX_PAGE_SIZE = 200
STATUSES = ("OPEN", "ACKNOWLEDGED", "RESOLVED")


def run_query(conn, sql, params=(), timeout_ms=3000):
    """Run one query, and stop it if it takes longer than timeout_ms."""
    deadline = time.monotonic() + timeout_ms / 1000
    conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 1000)
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError as ex:
        if "interrupted" in str(ex):
            raise QueryTimeout(f"query took longer than {timeout_ms} ms") from None
        raise
    finally:
        conn.set_progress_handler(None, 0)


def _page(page, size):
    try:
        page, size = int(page), int(size)
    except (TypeError, ValueError):
        raise InvalidFilterError("page and size must be numbers") from None
    if page < 1 or size < 1:
        raise InvalidFilterError("page and size must be 1 or more")
    return page, min(size, MAX_PAGE_SIZE)


def _time_filter(col, from_ts, to_ts, where, params):
    try:
        if from_ts is not None:
            where.append(f"{col} >= ?"); params.append(to_utc_text(from_ts))
        if to_ts is not None:
            where.append(f"{col} <= ?"); params.append(to_utc_text(to_ts))
    except ValueError as ex:
        raise InvalidFilterError(str(ex)) from None


def search_events(conn, *, ip=None, source_ip=None, destination_ip=None, protocol=None, run_id=None,
                  from_ts=None, to_ts=None, page=1, size=50, timeout_ms=3000) -> dict:
    page, size = _page(page, size)
    where, p = [], []
    if ip:
        where.append("(e.source_ip = ? OR e.destination_ip = ?)"); p += [ip, ip]
    if source_ip:
        where.append("e.source_ip = ?"); p.append(source_ip)
    if destination_ip:
        where.append("e.destination_ip = ?"); p.append(destination_ip)
    if protocol:
        where.append("pr.protocol_name = ?"); p.append(protocol.lower())
    if run_id:
        where.append("e.run_id = ?"); p.append(run_id)
    _time_filter("e.event_timestamp", from_ts, to_ts, where, p)
    if not where:
        raise InvalidFilterError("give at least one filter (ip, protocol, run_id or a time range)")
    base = (" FROM network_event e LEFT JOIN protocol pr ON pr.protocol_id = e.protocol_id"
            " WHERE " + " AND ".join(where))
    total = run_query(conn, "SELECT COUNT(*)" + base, p, timeout_ms)[0][0]
    rows = run_query(conn, "SELECT e.*, pr.protocol_name" + base +
                     " ORDER BY e.event_timestamp DESC, e.event_id LIMIT ? OFFSET ?",
                     p + [size, (page - 1) * size], timeout_ms)
    return {"total": total, "page": page, "size": size, "items": [dict(r) for r in rows]}


def search_alerts(conn, *, severity=None, status=None, ip=None, run_id=None, rule_code=None,
                  from_ts=None, to_ts=None, page=1, size=50, timeout_ms=3000) -> dict:
    page, size = _page(page, size)
    where, p = [], []
    if severity:
        where.append("s.severity_name = ?"); p.append(severity.upper())
    if status:
        if status.upper() not in STATUSES:
            raise InvalidFilterError("status must be OPEN, ACKNOWLEDGED or RESOLVED")
        where.append("a.alert_status = ?"); p.append(status.upper())
    if ip:
        where.append("a.affected_ip = ?"); p.append(ip)
    if run_id:
        where.append("a.run_id = ?"); p.append(run_id)
    if rule_code:
        where.append("a.rule_code = ?"); p.append(rule_code)
    _time_filter("a.detected_at", from_ts, to_ts, where, p)
    if not where:
        raise InvalidFilterError("give at least one filter (severity, status, ip, run_id or rule_code)")
    base = (" FROM alert a JOIN severity_level s ON s.severity_id = a.severity_id WHERE " + " AND ".join(where))
    total = run_query(conn, "SELECT COUNT(*)" + base, p, timeout_ms)[0][0]
    rows = run_query(conn, "SELECT a.*, s.severity_name, s.priority_rank" + base +
                     " ORDER BY s.priority_rank, a.detected_at DESC LIMIT ? OFFSET ?",
                     p + [size, (page - 1) * size], timeout_ms)
    return {"total": total, "page": page, "size": size, "items": [dict(r) for r in rows]}


def get_alert(conn, alert_id) -> dict:
    rows = run_query(conn, "SELECT a.*, s.severity_name, s.priority_rank FROM alert a "
                           "JOIN severity_level s ON s.severity_id = a.severity_id WHERE a.alert_id = ?", (alert_id,))
    if not rows:
        raise AlertNotFound(alert_id)
    alert = dict(rows[0])
    alert["events"] = [dict(r) for r in run_query(
        conn, "SELECT e.* FROM alert_event_link l JOIN network_event e ON e.event_id = l.event_id "
              "WHERE l.alert_id = ? ORDER BY e.event_timestamp", (alert_id,))]
    return alert


def get_events_for_detection(conn, run_id, limit=1000, offset=0, cursor=None) -> list:
    """The next events E2 has not checked yet, oldest first. E2 marks them evaluated when done.
    Supports keyset pagination via cursor=(timestamp, event_id) and offset-based pagination."""
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        raise InvalidFilterError("limit must be a number") from None
    if limit < 1:
        raise InvalidFilterError("limit must be 1 or more")

    where = ["e.run_id = ?", "e.is_evaluated = 0"]
    params = [run_id]

    if cursor is not None:
        if isinstance(cursor, (list, tuple)) and len(cursor) == 2:
            where.append("(e.event_timestamp > ? OR (e.event_timestamp = ? AND e.event_id > ?))")
            params.extend([str(cursor[0]), str(cursor[0]), str(cursor[1])])
        elif isinstance(cursor, dict) and "event_timestamp" in cursor and "event_id" in cursor:
            where.append("(e.event_timestamp > ? OR (e.event_timestamp = ? AND e.event_id > ?))")
            params.extend([str(cursor["event_timestamp"]), str(cursor["event_timestamp"]), str(cursor["event_id"])])
        elif isinstance(cursor, (int, str)) and str(cursor).isdigit():
            offset = int(cursor)

    sql = ("SELECT e.*, pr.protocol_name FROM network_event e "
           "LEFT JOIN protocol pr ON pr.protocol_id = e.protocol_id "
           f"WHERE {' AND '.join(where)} "
           "ORDER BY e.event_timestamp, e.event_id LIMIT ?")
    params.append(limit)

    if offset and not any("event_id >" in w for w in where):
        try:
            offset = int(offset)
        except (TypeError, ValueError):
            raise InvalidFilterError("offset must be a number") from None
        if offset > 0:
            sql += " OFFSET ?"
            params.append(offset)

    return [dict(r) for r in run_query(conn, sql, params)]


def get_run(conn, run_id) -> dict:
    rows = run_query(conn, "SELECT * FROM processing_run WHERE run_id = ?", (run_id,))
    if not rows:
        raise RunNotFound(run_id)
    return dict(rows[0])


def list_runs(conn, page=1, size=50) -> dict:
    page, size = _page(page, size)
    total = run_query(conn, "SELECT COUNT(*) FROM processing_run")[0][0]
    rows = run_query(conn, "SELECT * FROM processing_run ORDER BY started_at DESC LIMIT ? OFFSET ?", (size, (page - 1) * size))
    return {"total": total, "page": page, "size": size, "items": [dict(r) for r in rows]}


def get_performance_results(conn, run_id) -> dict:
    get_run(conn, run_id)
    metrics = [dict(r) for r in run_query(conn, "SELECT * FROM performance_metric WHERE run_id = ? ORDER BY execution_mode", (run_id,))]
    comp = run_query(conn, "SELECT * FROM benchmark_comparison WHERE run_id = ?", (run_id,))
    return {"run_id": run_id, "metrics": metrics, "comparison": dict(comp[0]) if comp else None}


def get_dashboard_summary(conn, run_id=None) -> dict:
    rf, rp = ("WHERE run_id = ?", (run_id,)) if run_id else ("", ())
    af, ap = ("AND a.run_id = ?", (run_id,)) if run_id else ("", ())
    if run_id:
        get_run(conn, run_id)
    runs = run_query(conn, f"SELECT COUNT(*), COALESCE(SUM(valid_count),0), COALESCE(SUM(malformed_count),0) FROM processing_run {rf}", rp)[0]
    events = run_query(conn, f"SELECT COUNT(*) FROM network_event {rf}", rp)[0][0]
    by_sev = {r[0]: r[1] for r in run_query(
        conn, f"SELECT s.severity_name, COUNT(a.alert_id) FROM severity_level s LEFT JOIN alert a "
              f"ON a.severity_id = s.severity_id {af} GROUP BY s.severity_id ORDER BY s.priority_rank", ap)}
    by_status = {st: 0 for st in STATUSES}
    by_status.update({r[0]: r[1] for r in run_query(
        conn, f"SELECT a.alert_status, COUNT(*) FROM alert a WHERE 1=1 {af} GROUP BY a.alert_status", ap)})
    return {"runs": runs[0], "records_valid": runs[1], "records_malformed": runs[2], "events_stored": events,
            "alerts_total": sum(by_sev.values()), "alerts_by_severity": by_sev, "alerts_by_status": by_status}


def get_user_by_username(conn, username):
    rows = run_query(conn, "SELECT u.*, r.role_name FROM user_account u JOIN role r ON r.role_id = u.role_id WHERE u.username = ?", (username,))
    return dict(rows[0]) if rows else None


def get_session_user(conn, token_hash):
    """The user behind a login token, or None if the token is unknown, revoked, expired or the user is disabled."""
    from datetime import datetime, timezone
    rows = run_query(conn, "SELECT u.user_id, u.username, u.full_name, u.is_active, r.role_name, s.session_id, s.expires_at, s.is_revoked "
                           "FROM auth_session s JOIN user_account u ON u.user_id = s.user_id "
                           "JOIN role r ON r.role_id = u.role_id WHERE s.token_hash = ?", (token_hash,))
    if not rows:
        return None
    u = dict(rows[0])
    if u.pop("is_revoked") or not u.pop("is_active") or u["expires_at"] <= to_utc_text(datetime.now(timezone.utc)):
        return None
    return u


def list_benchmarks(conn, page=1, size=20) -> dict:
    """Runs that have performance numbers, newest first, each with its per-mode metrics and comparison."""
    page, size = _page(page, size)
    cond = "EXISTS (SELECT 1 FROM performance_metric m WHERE m.run_id = r.run_id)"
    total = run_query(conn, f"SELECT COUNT(*) FROM processing_run r WHERE {cond}")[0][0]
    runs = [dict(r) for r in run_query(
        conn, f"SELECT r.run_id, r.file_name, r.started_at, r.status, b.speedup_ratio, b.equivalence_status, b.mismatch_count "
              f"FROM processing_run r LEFT JOIN benchmark_comparison b ON b.run_id = r.run_id WHERE {cond} "
              f"ORDER BY r.started_at DESC LIMIT ? OFFSET ?", (size, (page - 1) * size))]
    for r in runs:
        r["metrics"] = [dict(m) for m in run_query(conn, "SELECT * FROM performance_metric WHERE run_id = ? ORDER BY execution_mode", (r["run_id"],))]
    return {"total": total, "page": page, "size": size, "items": runs}
