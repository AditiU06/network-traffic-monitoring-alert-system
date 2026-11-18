"""The one object other engines talk to. E1, E2 and E4 never see SQL or the database file."""
import sqlite3
import threading
import time
import uuid
from collections import deque

from app.database.db import get_connection, init_db
from . import reader, writer
from .monitor import LatencyMonitor


def _is_busy(ex):
    return isinstance(ex, sqlite3.OperationalError) and ("locked" in str(ex) or "busy" in str(ex))


class DataManagementService:
    def __init__(self, db_path="network_monitor.db", busy_timeout=5.0):
        if db_path == ":memory:":
            raise ValueError("use a file path: every thread opens its own connection")
        self.db_path, self.busy_timeout = db_path, busy_timeout
        self._local = threading.local()          # one connection per thread (a tiny connection pool)
        self._write_lock = threading.Lock()      # one writer at a time inside this process
        self.retry_buffer = deque()              # batches that could not be written yet
        self.monitor = LatencyMonitor()
        init_db(self._conn())

    @staticmethod
    def new_id() -> str:
        return str(uuid.uuid4())

    def _conn(self):
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._local.conn = get_connection(self.db_path, self.busy_timeout)
        return c

    def _write(self, fn, *args, **kw):
        with self._write_lock:
            return fn(self._conn(), *args, **kw)

    def _read(self, fn, *args, **kw):
        t = time.perf_counter()
        try:
            return fn(self._conn(), *args, **kw)
        finally:
            self.monitor.record(fn.__name__, (time.perf_counter() - t) * 1000)

    # ----- called by E1 -----
    def save_processing_run(self, run): return self._write(writer.save_processing_run, run)
    def save_parse_errors(self, run_id, errors): return self._write(writer.save_parse_errors, run_id, errors)
    def save_performance_results(self, run_id, metrics, comparison=None):
        return self._write(writer.save_performance_results, run_id, metrics, comparison)

    def insert_events_batch(self, run_id, events):
        """Returns {inserted, rejected, status}. If the database stays busy, the batch waits in
        the retry buffer (status QUEUED) and flush_retry_buffer() tries again later."""
        return self._buffered("events", writer.insert_events_batch, run_id, events)

    # ----- called by E2 -----
    def get_events_for_detection(self, run_id, limit=1000, offset=0, cursor=None):
        return self._read(reader.get_events_for_detection, run_id, limit, offset=offset, cursor=cursor)
    def mark_events_evaluated(self, event_ids): return self._write(writer.mark_events_evaluated, event_ids)
    def save_alerts(self, alerts): return self._buffered("alerts", writer.insert_alerts_batch, alerts)

    # ----- called by E4 -----
    def search_events(self, **filters): return self._read(reader.search_events, **filters)
    def search_alerts(self, **filters): return self._read(reader.search_alerts, **filters)
    def get_alert(self, alert_id): return self._read(reader.get_alert, alert_id)
    def update_alert_status(self, alert_id, status, user_id=None): return self._write(writer.update_alert_status, alert_id, status, user_id)
    def get_run(self, run_id): return self._read(reader.get_run, run_id)
    def list_runs(self, page=1, size=50): return self._read(reader.list_runs, page, size)
    def get_performance_results(self, run_id): return self._read(reader.get_performance_results, run_id)
    def get_dashboard_summary(self, run_id=None): return self._read(reader.get_dashboard_summary, run_id)

    def list_benchmarks(self, page=1, size=20): return self._read(reader.list_benchmarks, page, size)
    def get_session_user(self, token_hash): return self._read(reader.get_session_user, token_hash)

    # ----- login data -----
    def create_user(self, *a, **k): return self._write(writer.create_user, *a, **k)
    def get_user_by_username(self, username): return self._read(reader.get_user_by_username, username)
    def create_session(self, *a, **k): return self._write(writer.create_session, *a, **k)
    def revoke_session(self, session_id): return self._write(writer.revoke_session, session_id)

    # ----- retry buffer -----
    def _buffered(self, kind, fn, *args):
        try:
            return self._write(fn, *args)
        except sqlite3.OperationalError as ex:
            if not _is_busy(ex):
                raise
            self.retry_buffer.append((kind, fn, args))
            return {"inserted": 0, "rejected": 0, "status": "QUEUED"}

    def flush_retry_buffer(self):
        """Try every waiting batch again. Anything still busy goes back into the buffer."""
        results = []
        for _ in range(len(self.retry_buffer)):
            kind, fn, args = self.retry_buffer.popleft()
            results.append(self._buffered(kind, fn, *args))
        return results
