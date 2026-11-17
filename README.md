# Network Traffic Monitoring and Alert System

**Team 14 – Integrated Security & Performance Monitoring Platform**

A high-performance, modular Python application designed to ingest, process, persist, analyze, and alert on multi-format Zeek network logs. The system combines concurrent multi-process log parsing, rule-based threat detection (38 Zeek Excel rules + supplementary heuristics), transactional SQLite persistence, and an interactive administrative dashboard with role-based access control.

---

## 1. System Architecture & Engine Interaction Workflow

The platform follows a direct, decoupled engine pipeline ($E1 \to E3 \to E2 \to E3 \to E4$):

```
  ┌────────────────────────────────────────────────────────┐
  │                E4: Web Dashboard & REST API            │
  │               (Flask / Port 8000 / RBAC Guard)         │
  └───────────────────────────┬────────────────────────────┘
                              │ Run Request (POST /api/v1/runs)
                              ▼
  ┌────────────────────────────────────────────────────────┐
  │           Integration: PipelineCoordinator             │
  │            (Direct In-Memory Orchestrator)             │
  └───────┬───────────────────┬────────────────────┬───────┘
          │ 1. Process Log    │ 2. Persist Events  │ 3. Evaluate Run
          ▼                   ▼                    ▼
  ┌───────────────┐   ┌───────────────┐    ┌───────────────┐
  │      E1       │   │      E3       │    │      E2       │
  │  Concurrent   │==>│  Data Mgmt &  │<==>│  Rule Threat  │
  │  Log Engine   │   │  Persistence  │    │   Detection   │
  │ (ProcessPool) │   │ (SQLite / WAL)│    │(38 Zeek Rules)│
  └───────────────┘   └───────────────┘    └───────────────┘
                              ▲
                              │ 4. Telemetry & Alerts Query
  ┌───────────────────────────┴────────────────────────────┐
  │                 E4: UI Telemetry & Visuals             │
  │           (Logs, Prioritized Alerts, Speedup Curves)   │
  └────────────────────────────────────────────────────────┘
```

### Component Roles & Responsibilities

1. **E1 – Concurrent Log Processing Engine (`Integration/Orchestration/e1_processor.py`)**
   - **Architecture:** Pure Python parallel worker pool (`concurrent.futures.ProcessPoolExecutor`) to bypass the Global Interpreter Lock (GIL) and distribute CPU-intensive parsing across multi-core systems without external runtime dependencies (Option A).
   - **Dynamic Log Auto-Detection:** Automatically inspects the `#path` and `#fields` headers to dynamically parse and type **any** Zeek log format (`conn.log`, `weird.log`, `tunnel.log`, `dpd.log`, `capture_loss.log`, `known_services.log`, `known_hosts.log`).
   - **Enrichment & Anomaly Extraction:** Preserves connection metrics (`total_bytes`, `total_packets`, `bytes_per_packet`, `orig_to_resp_ratio`) as well as protocol anomaly fields (`weird_name`, `notice_type`, `percent_lost`, `acks`, `tunnel_type`).
   - **Performance:** Measured speedup of **2.1x** with 4 workers on multi-core systems, surpassing the NFR-01 target of $\ge 1.5\times$.

2. **E2 – Rule-Based Threat Detection Engine (`E2_Threat_Detection/`)**
   - **Rules Implementation:** Implements all **38 Zeek Excel rules** and 7 supplementary heuristics across connection, state, and protocol anomalies.
   - **Sliding-Window Aggregation & State Tracking:** Tracks connection counts, unique target IPs/ports, ICMP sweeps, and payload thresholds across dynamic time windows.
   - **Alert Prioritization & Cooldown Suppression:** Max-heap priority ordering (`CRITICAL` $\to$ `HIGH` $\to$ `MEDIUM` $\to$ `LOW`) with sliding cooldown intervals per `(rule_id, source_ip)` to suppress redundant alert storms.
   - **E3 Keyset Pagination:** Fetches unevaluated events using keyset cursors `(event_timestamp, event_id)` to process arbitrarily large datasets (>5,000 events) without duplicate evaluations.

3. **E3 – Network Event & Alert Data Management (`E3_E4_Backend/backend/app/engines/e3_data_management/`)**
   - **Database:** SQLite 3 in 3NF with Write-Ahead Logging (WAL) and foreign key enforcement (`network_monitor.db`).
   - **Dynamic Schema Migration:** Auto-migrates database tables to accommodate multi-log columns (`log_source`, `weird_name`, `notice_type`, `percent_lost`, `acks`, etc.).
   - **Batch Transactions:** High-throughput batch insertion for ingested events and alert persistence.
   - **Data Access:** Fast keyset cursor pagination, filtered search by IP, severity, time range, status, or run ID.

4. **E4 – REST API & Web Dashboard (`E3_E4_Backend/backend/app/engines/e4_api_dashboard/`)**
   - **Backend:** Flask 3.1 REST API with JSON response serializers and custom exception handling.
   - **Role-Based Access Control (RBAC):** Token-based authentication enforcing granular permissions for `System Admin`, `Security Analyst`, and `NetOps Admin`.
   - **Interactive Frontend:** Responsive web interface providing Overview metric cards, real-time Alert triage, Log search with query filters, Run management, and interactive Benchmark speedup charts.

---

## 2. Directory Structure

```
Network Traffic Monitoring And Alert System/
├── E1_Concurrent_Log_Processing/   # Java reference source & tests
├── E2_Threat_Detection/            # E2 Rule-based detection engine
│   ├── e2_engine/                  # Detectors, rules loader, sliding windows, E3 adapter
│   ├── rules/                      # zeek_network_transport_alerts.xlsx, rules.json
│   └── tests/                      # 44 unit & integration tests
├── E3_E4_Backend/                  # Backend & Web Interface
│   └── backend/
│       ├── app/
│       │   ├── database/           # SQLite schema (schema.sql) and connection pool (db.py)
│       │   └── engines/
│       │       ├── e3_data_management/  # Validation, batch writer, reader, monitor
│       │       └── e4_api_dashboard/    # Flask blueprint, routes, security, static web assets
│       ├── tests/                  # 45 backend unit & API tests
│       └── main.py                 # Application launcher
├── Integration/                    # Orchestration & Cross-Engine Contracts
│   ├── Contracts/                  # Formal JSON schemas & Pydantic models
│   └── Orchestration/              # PipelineCoordinator & E1ParallelProcessor
├── logs/                           # Supported Zeek test logs (conn.log, weird.log, tunnel.log, etc.)
├── run_tests.bat                   # Runs all 92 unit and integration tests
├── test_live_system.py             # Live end-to-end multi-log verification script
└── README.md
```

---

## 3. Technology Stack

- **Core Runtime:** Python 3.10+ (tested on Python 3.12 and 3.14).
- **Concurrency & Multiprocessing:** `concurrent.futures.ProcessPoolExecutor` (Option A: multi-core parallel worker pool).
- **Web & REST API:** Flask 3.1, Werkzeug.
- **Data Validation & Serializers:** Pydantic 2.x, JSON Schema.
- **Database:** SQLite 3 with Write-Ahead Logging (WAL) and 3NF relational schema.
- **Testing:** `pytest` (E3/E4/Integration), `unittest` (E2).
- **Frontend:** Vanilla HTML5, CSS3, modern ES6 JavaScript (zero external CDN or runtime framework dependencies).

---

## 4. User Roles & Permission Matrix

The application enforces Role-Based Access Control (RBAC) across all REST API endpoints and dashboard UI components:

| Username | Role | Permissions | Capabilities | Restricted Actions |
| :--- | :--- | :--- | :--- | :--- |
| **`admin`** | **System Admin** | `view`, `start_run`, `update_alert` | Ingest logs, trigger runs (Sequential, Multithreaded, Benchmark), update alert triage states, view full telemetry. | *None* |
| **`analyst`**| **Security Analyst** | `view`, `update_alert` | Inspect logs, filter alerts by severity/IP, change alert status (`OPEN` $\to$ `ACKNOWLEDGED` $\to$ `RESOLVED`). | Cannot trigger new log ingestion runs (`POST /runs` $\to$ `403 Forbidden`). |
| **`netops`** | **NetOps Admin** | `view` | Read-only telemetry: monitor processing runs, inspect speedup curves, view alerts and network logs. | Cannot update alerts or trigger runs (`403 Forbidden`). |

*Default demonstration password for all accounts:* `Demo@12345`

---

## 5. Startup & Running Instructions

### 1. Launch the Dashboard Server
```powershell
.\.venv\Scripts\python.exe E3_E4_Backend\backend\main.py
```
Open your browser to: **`http://127.0.0.1:8000`**

### 2. Run the Live End-to-End Verification
To test live authentication, dashboard summary telemetry, multi-log alert retrieval, and multi-core benchmark execution against the running server:
```powershell
.\.venv\Scripts\python.exe test_live_system.py
```

### 3. Seed Demo Data (Optional)
To re-initialize the SQLite database with demonstration accounts and baseline sample runs:
```powershell
.\.venv\Scripts\python.exe E3_E4_Backend\backend\seed_demo.py
```

---

## 6. Testing & Quality Assurance

Run the comprehensive test suite (all 92 unit, regression, and integration tests):
```cmd
run_tests.bat
```

Or execute individual test suites:

- **E2 Threat Detection Tests (44 tests):**
  ```powershell
  .\.venv\Scripts\python.exe -m unittest discover -s E2_Threat_Detection\tests -v
  ```
- **E3 & E4 Backend Tests (45 tests):**
  ```powershell
  $env:PYTHONPATH = "$PWD;$PWD\E3_E4_Backend\backend;$PWD\E2_Threat_Detection"
  .\.venv\Scripts\pytest.exe E3_E4_Backend\backend\tests -q
  ```
- **Integration Coordinator Tests (3 tests):**
  ```powershell
  $env:PYTHONPATH = "$PWD;$PWD\E3_E4_Backend\backend;$PWD\E2_Threat_Detection;$PWD\Integration\Contracts"
  .\.venv\Scripts\pytest.exe Integration\Orchestration\test_coordinator.py -v
  ```

---

## 7. Supported Zeek Logs & Threat Detection Rules

The platform automatically detects the format from the Zeek `#path` header and evaluates 45 detection rules:

| Log Type | Header `#path` | Sample Trigger Rules | Severity | Description / Attack Indication |
| :--- | :--- | :--- | :--- | :--- |
| **`conn.log`** | `conn` | `R01`, `R02`, `PORT_SCAN`, `REPEATED_REJECT`, `BLACKLISTED_IP` | CRITICAL / HIGH / MEDIUM | Address scans, port scans ($\ge 15$ failed connections), connection floods, known blacklisted IPs. |
| **`weird.log`** | `weird` | `R03`, `R04`, `R08`, `R10`, `R11`, `R15`, `R20`, `R22`, `R31`, `R32` | CRITICAL / HIGH / MEDIUM / LOW | Fragment overlap/inconsistency (IDS evasion), FIN storms, TCP Xmas packets, SYN with data, corrupted checksums. |
| **`tunnel.log`** | `tunnel` | `R28` | MEDIUM | Unauthorized tunneling protocols (Teredo, GRE, IP-in-IP, AYIYA, VXLAN) bypassing perimeter controls. |
| **`capture_loss.log`** | `capture_loss` | `R06` | CRITICAL | Packet capture loss rate exceeding configured threshold (>10%). |
| **`dpd.log`** | `dpd` | `R07` | CRITICAL | Dynamic Protocol Detection analyzer anomalies or protocol violations. |
| **`known_hosts.log` / `known_services.log`** | `known_hosts` / `known_services` | `R38` | LOW | Novel or unapproved host/service observed in production traffic. |

---

## 8. REST API Reference

All protected endpoints require a Bearer token: `Authorization: Bearer <token>`.

| Method | Endpoint | Allowed Roles | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/login` | Public | Authenticates user; returns session token & permissions. |
| `POST` | `/api/v1/auth/logout` | Authenticated | Invalidates the active session token. |
| `GET` | `/api/v1/auth/me` | Authenticated | Retrieves current authenticated profile. |
| `POST` | `/api/v1/runs` | System Admin | Triggers log processing (`{logFile, mode, threads}`). |
| `GET` | `/api/v1/runs` | All Roles | Lists processing runs with pagination. |
| `GET` | `/api/v1/runs/{id}` | All Roles | Retrieves run details, performance metrics, and comparison. |
| `GET` | `/api/v1/logs` | All Roles | Searches network events by IP, protocol, run, and time range. |
| `GET` | `/api/v1/alerts` | All Roles | Queries alerts with filters (`status`, `severity`, `ip`, `runId`). |
| `GET` | `/api/v1/alerts/{id}` | All Roles | Retrieves single alert details with linked raw trigger events. |
| `PATCH`| `/api/v1/alerts/{id}` | Analyst, Admin | Updates alert triage status (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`). |
| `GET` | `/api/v1/benchmarks` | All Roles | Lists execution duration, throughput, and speedup ratios. |
| `GET` | `/api/v1/dashboard/summary`| All Roles | Returns aggregated counts for top dashboard summary cards. |

---

## 9. Verification & Performance Summary

- **Test Suite Pass Rate:** **92 / 92 tests passing (100%)**.
- **Multi-Core Speedup (NFR-01):** **2.1x speedup** measured on `sample_conn.log` with 4 worker processes (exceeds the $\ge 1.5\times$ target).
- **Data Equivalence:** **PASS** (0 record mismatches between sequential and parallel modes).
- **Multi-Log Threat Detection:** Verified live across `conn.log`, `weird.log`, and `tunnel.log`, accurately firing the corresponding Excel rules into SQLite and the E4 dashboard.
