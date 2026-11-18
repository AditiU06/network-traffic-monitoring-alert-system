"""Everything that CHANGES the database. Each function is one all-or-nothing transaction."""
import sqlite3
from datetime import datetime, timezone

from app.database.db import transaction
from .errors import AlertNotFound, InvalidInput, RunNotFound
from .validation import to_utc_text, validate_event

CHUNK = 500  # SQLite allows ~999 "?" per query, so look things up in chunks


def _now():
    return to_utc_text(datetime.now(timezone.utc))


def _run_exists(conn, run_id):
    return conn.execute("SELECT 1 FROM processing_run WHERE run_id=?", (run_id,)).fetchone() is not None


# ---------- users and login data ----------
def create_user(conn, role_name, username, email, password_hash, full_name=None) -> int:
    with transaction(conn):
        role = conn.execute("SELECT role_id FROM role WHERE role_name=?", (role_name,)).fetchone()
        if not role:
            raise InvalidInput(f"unknown role '{role_name}'")
        try:
            cur = conn.execute(
                "INSERT INTO user_account (role_id, username, email, password_hash, full_name) VALUES (?,?,?,?,?)",
                (role["role_id"], username, email, password_hash, full_name))
        except sqlite3.IntegrityError as ex:
            raise InvalidInput(f"cannot create user: {ex}") from None
        return cur.lastrowid


def create_session(conn, session_id, user_id, token_hash, issued_at, expires_at):
    with transaction(conn):
        try:
            conn.execute("INSERT INTO auth_session (session_id,user_id,token_hash,issued_at,expires_at) VALUES (?,?,?,?,?)",
                         (session_id, user_id, token_hash, to_utc_text(issued_at), to_utc_text(expires_at)))
            conn.execute("UPDATE user_account SET last_login_at=? WHERE user_id=?", (_now(), user_id))
        except sqlite3.IntegrityError as ex:
            raise InvalidInput(f"cannot create session: {ex}") from None


def revoke_session(conn, session_id) -> bool:
    with transaction(conn):
        return conn.execute("UPDATE auth_session SET is_revoked=1 WHERE session_id=?", (session_id,)).rowcount > 0


# ---------- runs, metrics, parse errors ----------
def save_processing_run(conn, run: dict) -> str:
    """Create a run, or update it (status, counts, completed_at) if run_id already exists."""
    try:
        with transaction(conn):
            conn.execute(
                """INSERT INTO processing_run (run_id, initiated_by, file_name, log_type, run_mode, status,
                       started_at, completed_at, input_count, valid_count, malformed_count)
                   VALUES (:run_id,:initiated_by,:file_name,:log_type,:run_mode,:status,
                       :started_at,:completed_at,:input_count,:valid_count,:malformed_count)
                   ON CONFLICT(run_id) DO UPDATE SET status=excluded.status, completed_at=excluded.completed_at,
                       input_count=excluded.input_count, valid_count=excluded.valid_count,
                       malformed_count=excluded.malformed_count""",
                {"status": "RUNNING", "completed_at": None, "input_count": 0, "valid_count": 0, "malformed_count": 0,
                 **run,
                 "started_at": to_utc_text(run["started_at"]),
                 **({"completed_at": to_utc_text(run["completed_at"])} if run.get("completed_at") else {})})
    except (sqlite3.IntegrityError, KeyError) as ex:
        raise InvalidInput(f"cannot save run: {ex}") from None
    return run["run_id"]


def save_parse_errors(conn, run_id, errors: list) -> int:
    with transaction(conn):
        if not _run_exists(conn, run_id):
            raise RunNotFound(run_id)
        conn.executemany("INSERT INTO parse_error (run_id,line_number,error_type,error_message) VALUES (?,?,?,?)",
                         [(run_id, x.get("line_number"), x.get("error_type", "UNKNOWN"), x.get("error_message")) for x in errors])
    return len(errors)


def save_performance_results(conn, run_id, metrics: list, comparison: dict | None = None) -> None:
    """metrics: one dict per execution mode. comparison: speedup, equivalence_status, mismatch_count."""
    try:
        with transaction(conn):
            if not _run_exists(conn, run_id):
                raise RunNotFound(run_id)
            for m in metrics:
                conn.execute(
                    """INSERT INTO performance_metric (run_id, execution_mode, worker_count, execution_time_sec,
                           throughput_rec_sec, cpu_usage_pct, peak_memory_mb)
                       VALUES (:run_id,:execution_mode,:worker_count,:execution_time_sec,
                           :throughput_rec_sec,:cpu_usage_pct,:peak_memory_mb)
                       ON CONFLICT(run_id, execution_mode) DO UPDATE SET worker_count=excluded.worker_count,
                           execution_time_sec=excluded.execution_time_sec, throughput_rec_sec=excluded.throughput_rec_sec,
                           cpu_usage_pct=excluded.cpu_usage_pct, peak_memory_mb=excluded.peak_memory_mb""",
                    {"throughput_rec_sec": None, "cpu_usage_pct": None, "peak_memory_mb": None, **m, "run_id": run_id})
            if comparison:
                conn.execute(
                    """INSERT INTO benchmark_comparison (run_id, speedup_ratio, equivalence_status, mismatch_count)
                       VALUES (:run_id,:speedup_ratio,:equivalence_status,:mismatch_count)
                       ON CONFLICT(run_id) DO UPDATE SET speedup_ratio=excluded.speedup_ratio,
                           equivalence_status=excluded.equivalence_status, mismatch_count=excluded.mismatch_count""",
                    {"mismatch_count": 0, **comparison, "run_id": run_id})
    except (sqlite3.IntegrityError, KeyError) as ex:
        raise InvalidInput(f"cannot save metrics: {ex}") from None


# ---------- events ----------
def insert_events_batch(conn, run_id, events: list) -> dict:
    """Validate, then insert the good events in ONE transaction.
    Returns {inserted, rejected, rejected_details, status}. Bad rows are listed, never silently dropped."""
    rejected, rows, seen = [], [], set()
    with transaction(conn):
        if not _run_exists(conn, run_id):
            raise RunNotFound(run_id)
        states = {r[0] for r in conn.execute("SELECT conn_state_code FROM connection_state")}
        protocols = {r["protocol_name"]: r["protocol_id"] for r in conn.execute("SELECT * FROM protocol")}
        for i, e in enumerate(events):
            try:
                row = validate_event(e, run_id, states)
            except ValueError as ex:
                rejected.append({"index": i, "event_id": e.get("event_id"), "reason": str(ex)})
                continue
            if row[0] in seen:
                rejected.append({"index": i, "event_id": row[0], "reason": "duplicate inside this batch"})
                continue
            seen.add(row[0])
            rows.append(row)
        # skip events that are already stored (makes retries safe)
        ids = [r[0] for r in rows]
        existing = set()
        for k in range(0, len(ids), CHUNK):
            part = ids[k:k + CHUNK]
            q = f"SELECT event_id FROM network_event WHERE event_id IN ({','.join('?' * len(part))})"
            existing.update(r[0] for r in conn.execute(q, part))
        fresh = []
        for r in rows:
            if r[0] in existing:
                rejected.append({"index": None, "event_id": r[0], "reason": "already stored"})
            else:
                fresh.append(r)
        # protocols we have not seen before are added to the lookup table
        for name in {r[7] for r in fresh if r[7] and r[7] not in protocols}:
            protocols[name] = conn.execute("INSERT INTO protocol (protocol_name) VALUES (?)", (name,)).lastrowid
        conn.executemany(
            """INSERT INTO network_event (event_id, run_id, event_timestamp, source_ip, source_port, destination_ip,
                   destination_port, protocol_id, conn_state_code, service, duration, orig_bytes, resp_bytes,
                   orig_pkts, resp_pkts, uid, history, total_bytes, total_packets, bytes_per_packet, orig_to_resp_ratio,
                   log_source, weird_name, notice_type, percent_lost, acks)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [r[:7] + (protocols.get(r[7]),) + r[8:] for r in fresh])
    return {"inserted": len(fresh), "rejected": len(rejected), "rejected_details": rejected,
            "status": "OK" if not rejected else "PARTIAL"}


def mark_events_evaluated(conn, event_ids: list) -> int:
    n = 0
    with transaction(conn):
        for k in range(0, len(event_ids), CHUNK):
            part = event_ids[k:k + CHUNK]
            n += conn.execute(f"UPDATE network_event SET is_evaluated=1 WHERE event_id IN ({','.join('?' * len(part))})", part).rowcount
    return n


# ---------- alerts ----------
def insert_alerts_batch(conn, alerts: list) -> dict:
    """Save alerts and the events behind them. An alert that repeats (same run, rule, IP, window)
    is not stored twice; the existing alert's suppression_count goes up by 1 instead."""
    inserted = suppressed = 0
    rejected = []
    with transaction(conn):
        sev = {r["severity_name"]: r["severity_id"] for r in conn.execute("SELECT * FROM severity_level")}
        for i, a in enumerate(alerts):
            try:
                sid = sev[str(a.get("severity", "")).upper()]
                linked = list(dict.fromkeys(a.get("related_event_ids") or []))
                if not linked:
                    raise ValueError("an alert needs at least one related event")
                if not _run_exists(conn, a["run_id"]):
                    raise ValueError("run does not exist")
                found = {r[0] for r in conn.execute(
                    f"SELECT event_id FROM network_event WHERE event_id IN ({','.join('?' * len(linked))})", linked)}
                if found != set(linked):
                    raise ValueError("some related events are not stored")
                ws, da = to_utc_text(a["window_start"]), to_utc_text(a["detected_at"])
                dup = conn.execute("SELECT alert_id FROM alert WHERE run_id=? AND rule_code=? AND affected_ip=? AND window_start=?",
                                   (a["run_id"], a["rule_code"], a["affected_ip"], ws)).fetchone()
                if dup:
                    conn.execute("UPDATE alert SET suppression_count = suppression_count + 1 WHERE alert_id=?", (dup[0],))
                    suppressed += 1
                    continue
                conn.execute(
                    """INSERT INTO alert (alert_id, run_id, severity_id, rule_code, affected_ip, window_start,
                           detected_at, alert_description, suppression_count) VALUES (?,?,?,?,?,?,?,?,?)""",
                    (a["alert_id"], a["run_id"], sid, a["rule_code"], a["affected_ip"], ws, da,
                     a.get("description"), a.get("suppression_count", 0)))
                conn.executemany("INSERT INTO alert_event_link (alert_id,event_id) VALUES (?,?)", [(a["alert_id"], x) for x in linked])
                inserted += 1
            except (KeyError, ValueError, sqlite3.IntegrityError) as ex:
                reason = "unknown severity" if isinstance(ex, KeyError) and ex.args and ex.args[0] not in a else str(ex)
                rejected.append({"index": i, "alert_id": a.get("alert_id"), "reason": reason})
    return {"inserted": inserted, "suppressed": suppressed, "rejected": len(rejected),
            "rejected_details": rejected, "status": "OK" if not rejected else "PARTIAL"}


def update_alert_status(conn, alert_id, status, user_id=None) -> dict:
    status = str(status).upper()
    if status not in ("OPEN", "ACKNOWLEDGED", "RESOLVED"):
        raise InvalidInput("status must be OPEN, ACKNOWLEDGED or RESOLVED")
    try:
        with transaction(conn):
            n = conn.execute("UPDATE alert SET alert_status=?, updated_by=?, status_updated_at=? WHERE alert_id=?",
                             (status, user_id, _now(), alert_id)).rowcount
    except sqlite3.IntegrityError:
        raise InvalidInput("user does not exist") from None
    if n == 0:
        raise AlertNotFound(alert_id)
    return {"alert_id": alert_id, "alert_status": status}
