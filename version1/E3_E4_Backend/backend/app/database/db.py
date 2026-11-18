"""Opens the SQLite database. Only Engine 3 (E3) should import this."""
import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA_FILE = Path(__file__).with_name("schema.sql")


def get_connection(db_path: str, busy_timeout: float = 5.0) -> sqlite3.Connection:
    # isolation_level=None -> we control transactions ourselves (see transaction()).
    conn = sqlite3.connect(db_path, timeout=busy_timeout, isolation_level=None)
    conn.row_factory = sqlite3.Row            # rows behave like dicts
    conn.execute("PRAGMA foreign_keys = ON")  # SQLite ignores foreign keys unless this is on
    conn.execute("PRAGMA journal_mode = WAL") # readers don't block the writer
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create all tables once. Does nothing if they already exist, and migrates missing columns."""
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='processing_run'"
    ).fetchone()
    if not exists:
        conn.executescript(SCHEMA_FILE.read_text())
    else:
        # Backward compatibility migration for pre-existing databases
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(network_event)").fetchall()}
        new_cols = [
            ("uid", "TEXT"),
            ("history", "TEXT"),
            ("total_bytes", "INTEGER"),
            ("total_packets", "INTEGER"),
            ("bytes_per_packet", "REAL"),
            ("orig_to_resp_ratio", "REAL"),
            ("log_source", "TEXT"),
            ("weird_name", "TEXT"),
            ("notice_type", "TEXT"),
            ("percent_lost", "REAL"),
            ("acks", "INTEGER"),
        ]
        for col_name, col_type in new_cols:
            if col_name not in cols:
                conn.execute(f"ALTER TABLE network_event ADD COLUMN {col_name} {col_type}")


@contextmanager
def transaction(conn: sqlite3.Connection):
    """All-or-nothing block: commit if the block finishes, roll back if it raises."""
    conn.execute("BEGIN IMMEDIATE")           # take the write lock up front
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")
