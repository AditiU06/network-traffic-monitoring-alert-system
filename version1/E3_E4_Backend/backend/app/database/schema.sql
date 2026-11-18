-- Engine 3 schema: 12 tables in 3NF. Dates are stored as ISO-8601 text (SQLite has no date type).

-- ---------- Who can log in ----------
CREATE TABLE role (
    role_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name   TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE user_account (
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    role_id       INTEGER NOT NULL REFERENCES role(role_id) ON DELETE RESTRICT,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name     TEXT,
    is_active     INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_login_at TEXT
);

CREATE TABLE auth_session (
    session_id TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES user_account(user_id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    issued_at  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    is_revoked INTEGER NOT NULL DEFAULT 0 CHECK (is_revoked IN (0, 1)),
    CHECK (expires_at > issued_at)
);

-- ---------- Lookup tables ----------
CREATE TABLE protocol (
    protocol_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol_name TEXT NOT NULL UNIQUE
);

CREATE TABLE connection_state (
    conn_state_code TEXT PRIMARY KEY,
    description     TEXT NOT NULL
);

CREATE TABLE severity_level (
    severity_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    severity_name TEXT NOT NULL UNIQUE,
    priority_rank INTEGER NOT NULL UNIQUE      -- 1 = most urgent
);

-- ---------- One processing run and what it produced ----------
CREATE TABLE processing_run (
    run_id          TEXT PRIMARY KEY,
    initiated_by    INTEGER NOT NULL REFERENCES user_account(user_id) ON DELETE RESTRICT,
    file_name       TEXT NOT NULL,
    log_type        TEXT NOT NULL,
    run_mode        TEXT NOT NULL CHECK (run_mode IN ('SEQUENTIAL','MULTITHREADED','BENCHMARK')),
    status          TEXT NOT NULL DEFAULT 'RUNNING' CHECK (status IN ('RUNNING','COMPLETED','FAILED')),
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    input_count     INTEGER NOT NULL DEFAULT 0 CHECK (input_count >= 0),
    valid_count     INTEGER NOT NULL DEFAULT 0 CHECK (valid_count >= 0),
    malformed_count INTEGER NOT NULL DEFAULT 0 CHECK (malformed_count >= 0),
    CHECK (input_count = valid_count + malformed_count),
    CHECK (completed_at IS NULL OR completed_at >= started_at)
);

CREATE TABLE parse_error (
    error_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT NOT NULL REFERENCES processing_run(run_id) ON DELETE CASCADE,
    line_number   INTEGER,
    error_type    TEXT NOT NULL,
    error_message TEXT
);

CREATE TABLE network_event (
    event_id           TEXT PRIMARY KEY,
    run_id             TEXT NOT NULL REFERENCES processing_run(run_id) ON DELETE CASCADE,
    event_timestamp    TEXT NOT NULL,
    source_ip          TEXT NOT NULL,
    source_port        INTEGER CHECK (source_port BETWEEN 0 AND 65535),
    destination_ip     TEXT NOT NULL,
    destination_port   INTEGER CHECK (destination_port BETWEEN 0 AND 65535),
    protocol_id        INTEGER REFERENCES protocol(protocol_id) ON DELETE RESTRICT,
    conn_state_code    TEXT REFERENCES connection_state(conn_state_code) ON DELETE RESTRICT,
    service            TEXT,
    duration           REAL    CHECK (duration  >= 0),   -- NULL means unknown, never 0
    orig_bytes         INTEGER CHECK (orig_bytes >= 0),
    resp_bytes         INTEGER CHECK (resp_bytes >= 0),
    orig_pkts          INTEGER CHECK (orig_pkts  >= 0),
    resp_pkts          INTEGER CHECK (resp_pkts  >= 0),
    uid                TEXT,
    history            TEXT,
    total_bytes        INTEGER CHECK (total_bytes >= 0),
    total_packets      INTEGER CHECK (total_packets >= 0),
    bytes_per_packet   REAL    CHECK (bytes_per_packet >= 0),
    orig_to_resp_ratio REAL    CHECK (orig_to_resp_ratio >= 0),
    log_source         TEXT,
    weird_name         TEXT,
    notice_type        TEXT,
    percent_lost       REAL,
    acks               INTEGER,
    is_evaluated       INTEGER NOT NULL DEFAULT 0 CHECK (is_evaluated IN (0, 1))
);

CREATE TABLE performance_metric (
    metric_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id             TEXT NOT NULL REFERENCES processing_run(run_id) ON DELETE CASCADE,
    execution_mode     TEXT NOT NULL CHECK (execution_mode IN ('SEQUENTIAL','MULTITHREADED')),
    worker_count       INTEGER NOT NULL CHECK (worker_count BETWEEN 1 AND 16),
    execution_time_sec REAL NOT NULL CHECK (execution_time_sec >= 0),
    throughput_rec_sec REAL CHECK (throughput_rec_sec >= 0),
    cpu_usage_pct      REAL CHECK (cpu_usage_pct >= 0),
    peak_memory_mb     REAL CHECK (peak_memory_mb >= 0),
    UNIQUE (run_id, execution_mode)
);

CREATE TABLE benchmark_comparison (
    run_id             TEXT PRIMARY KEY REFERENCES processing_run(run_id) ON DELETE CASCADE,
    speedup_ratio      REAL CHECK (speedup_ratio >= 0),
    equivalence_status TEXT NOT NULL CHECK (equivalence_status IN ('PASS','FAIL')),
    mismatch_count     INTEGER NOT NULL DEFAULT 0 CHECK (mismatch_count >= 0)
);

-- ---------- Alerts ----------
CREATE TABLE alert (
    alert_id          TEXT PRIMARY KEY,
    run_id            TEXT NOT NULL REFERENCES processing_run(run_id) ON DELETE CASCADE,
    severity_id       INTEGER NOT NULL REFERENCES severity_level(severity_id) ON DELETE RESTRICT,
    updated_by        INTEGER REFERENCES user_account(user_id) ON DELETE SET NULL,
    rule_code         TEXT NOT NULL,                 -- e.g. PORT_SCAN; the rule itself lives in E2's code
    affected_ip       TEXT NOT NULL,
    window_start      TEXT NOT NULL,
    detected_at       TEXT NOT NULL,
    alert_status      TEXT NOT NULL DEFAULT 'OPEN' CHECK (alert_status IN ('OPEN','ACKNOWLEDGED','RESOLVED')),
    status_updated_at TEXT,
    suppression_count INTEGER NOT NULL DEFAULT 0 CHECK (suppression_count >= 0),
    alert_description TEXT,
    UNIQUE (run_id, rule_code, affected_ip, window_start)   -- no duplicate alerts on retry
);

CREATE TABLE alert_event_link (
    alert_id TEXT NOT NULL REFERENCES alert(alert_id)         ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES network_event(event_id) ON DELETE CASCADE,
    PRIMARY KEY (alert_id, event_id)
);

-- ---------- Indexes for fast search (target < 50 ms) ----------
CREATE INDEX idx_event_timestamp_src_ip ON network_event (event_timestamp, source_ip);
CREATE INDEX idx_event_run              ON network_event (run_id);
CREATE INDEX idx_alert_severity_status  ON alert (severity_id, alert_status);
CREATE INDEX idx_alert_run              ON alert (run_id);

-- ---------- Starting data ----------
INSERT INTO role (role_name, description) VALUES
    ('System Admin',     'Starts runs and manages the system'),
    ('Security Analyst', 'Reviews and updates alerts'),
    ('NetOps Admin',     'Views logs and performance');

INSERT INTO severity_level (severity_name, priority_rank) VALUES
    ('CRITICAL', 1), ('HIGH', 2), ('MEDIUM', 3), ('LOW', 4);

INSERT INTO protocol (protocol_name) VALUES ('tcp'), ('udp'), ('icmp');

INSERT INTO connection_state (conn_state_code, description) VALUES
    ('S0',  'Connection attempt seen, no reply'),
    ('S1',  'Connection established, not closed'),
    ('SF',  'Normal start and finish'),
    ('REJ', 'Connection rejected'),
    ('S2',  'Established, originator closed, no reply from responder'),
    ('S3',  'Established, responder closed, no reply from originator'),
    ('RSTO','Established, originator aborted (RST)'),
    ('RSTR','Responder sent a RST'),
    ('RSTOS0','Originator sent SYN then RST, no SYN-ACK'),
    ('RSTRH','Responder sent SYN-ACK then RST, no SYN from originator'),
    ('SH',  'Originator sent SYN then FIN, no SYN-ACK'),
    ('SHR', 'Responder sent SYN-ACK then FIN, no SYN from originator'),
    ('OTH', 'No SYN seen, midstream traffic');
