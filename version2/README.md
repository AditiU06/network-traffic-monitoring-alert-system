# Network Traffic Monitoring and Alert System — Version 2

**Team 14 – Integrated Security & Performance Monitoring Platform (Pure Python Architecture)**

A high-performance, modular Python application designed to ingest, process, persist, analyze, and alert on multi-format Zeek network logs. Version 2 features an exclusive Python concurrent log processing engine (E1), rule-based threat detection (38 Zeek Excel rules + supplementary heuristics), transactional SQLite persistence with Write-Ahead Logging (WAL), genuine `psutil`-based benchmarking, and an interactive administrative dashboard with role-based access control.

---

## 1. System Architecture & Engine Interaction Workflow

The platform follows a decoupled, robust engine pipeline ($E1 \to E3 \to E2 \to E3 \to E4$):

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

1. **E1 – Concurrent Log Processing Engine (`E1_Concurrent_Log_Processing/`)**
   - **Exclusive Python Implementation:** Standalone module (`e1_processor.py`, `models.py`) with zero JVM or Maven dependencies.
   - **Multi-Format Zeek Parsing (18 Types):** `conn`, `weird`, `notice`, `tunnel`, `dns`, `http`, `ssl`, `x509`, `files`, `ssh`, `ftp`, `smtp`, `dhcp`, `arp`, `dpd`, `capture_loss`, `known_hosts`, `known_services`.
   - **Header Directives & Delimiters:** Full support for Zeek `#separator` (hex `\x09`, `\x20`, escapes), `#fields`, `#types`, and `#path`.
   - **Strict Data Integrity:**
     - Preserves fractional microsecond timestamp precision without timestamp fabrication.
     - Preserves missing IP addresses as `None` (never replaces with `0.0.0.0`).
     - Decouples boolean `notice` (weird.log) from `notice_type` (notice.log).
     - Captures and records parsing errors (`ParseErrorRecord`) with original line numbers.
   - **Genuine Benchmarking:** Measures actual wall-clock elapsed time, records/second throughput, and host CPU/memory consumption via `psutil`. Verifies sequential vs parallel equivalence by full dictionary content comparison.

2. **E2 – Rule-Based Threat Detection Engine (`E2_Threat_Detection/`)**
   - **Rules Implementation:** Implements all **38 Zeek Excel rules** and 7 supplementary heuristics across connection, state, and protocol anomalies.
   - **Sliding-Window Aggregation & State Tracking:** Tracks connection counts, unique target IPs/ports, ICMP sweeps, and payload thresholds across dynamic time windows.
   - **Alert Prioritization & Cooldown Suppression:** Max-heap priority ordering (`CRITICAL` $\to$ `HIGH` $\to$ `MEDIUM` $\to$ `LOW`) with sliding cooldown intervals per `(rule_id, source_ip)` to suppress redundant alert storms.
   - **E3 Keyset Pagination:** Fetches unevaluated events using keyset cursors `(event_timestamp, event_id)` to process arbitrarily large datasets (>5,000 events) without duplicate evaluations.
   - **Reliable Persistence Adapter:** Queued/busy SQLite retries ensure zero alerts are dropped.

3. **E3 – Network Event & Alert Data Management (`E3_E4_Backend/backend/app/engines/e3_data_management/`)**
   - **Database:** SQLite 3 in 3NF with Write-Ahead Logging (WAL) and foreign key enforcement (`network_monitor.db`).
   - **Dynamic Schema Migration:** Schema supports multi-log columns (`log_source`, `weird_name`, `notice_type`, `percent_lost`, `acks`, etc.) and a dedicated `parse_error` table.
   - **Batch Transactions:** High-throughput batch insertion for ingested events and alert persistence.
   - **Data Access:** Fast keyset cursor pagination, filtered search by IP, severity, time range, status, or run ID.

4. **E4 – REST API & Web Dashboard (`E3_E4_Backend/backend/app/engines/e4_api_dashboard/`)**
   - **Backend:** Flask 3.1 REST API with JSON response serializers and custom exception handling.
   - **Explicit Processor Dispatch:** Normal operation directly dispatches through `PipelineCoordinator` without silent demo fallbacks.
   - **Role-Based Access Control (RBAC):** Token-based authentication enforcing granular permissions for `System Admin`, `Security Analyst`, and `NetOps Admin`.
   - **Interactive Frontend:** Responsive web interface providing Overview metric cards, real-time Alert triage, Log search with query filters, Run management, and interactive Benchmark speedup charts.

---

## 2. Directory Structure

```
version2/
├── E1_Concurrent_Log_Processing/   # Python log-processing engine
│   ├── e1_processor.py             # Multi-format parser, parallel worker pool, psutil benchmark
│   ├── models.py                   # ParseErrorRecord, BenchmarkResult models
│   └── tests/                      # 7 E1 unit & parser equivalence tests
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
│       ├── tests/                  # 46 backend unit & API tests
│       └── main.py                 # Application launcher
├── Integration/                    # Orchestration & Cross-Engine Contracts
│   ├── Contracts/                  # Formal JSON schemas & Pydantic models
│   └── Orchestration/              # PipelineCoordinator (coordinator.py, test_coordinator.py)
├── logs/                           # Supported Zeek test logs (conn.log, weird.log, tunnel.log, etc.)
├── run_dashboard.bat               # Windows batch application launcher (:8000)
├── run_dashboard.ps1               # PowerShell application launcher
├── run_dashboard.sh                # Linux/macOS application launcher
├── run_tests.bat                   # Runs all 100 unit and integration tests (Windows)
├── run_tests.sh                    # Runs all 100 unit and integration tests (Linux/macOS)
├── test_live_system.py             # Live end-to-end multi-log verification script
└── README.md
```

---

## 3. Technology Stack

- **Core Runtime:** Python 3.10+ (tested on Python 3.12 and 3.14).
- **Concurrency & Multiprocessing:** `concurrent.futures.ProcessPoolExecutor` (multi-core parallel worker pool).
- **Benchmarking & Telemetry:** `psutil` (genuine CPU and RSS memory telemetry).
- **Web & REST API:** Flask 3.1, Werkzeug.
- **Persistence:** SQLite 3 (WAL mode, foreign keys, 3NF schema).
- **Security:** Argon2 / PBKDF2 password hashing, Bearer JWT session tokens, RBAC authorization.

---

## 4. Running the Tests

To run the complete test suite across all four engines (100 tests total):

### On Windows
```cmd
cd version2
run_tests.bat
```

### On Linux / macOS
```bash
cd version2
chmod +x run_tests.sh
./run_tests.sh
```

### Test Breakdown:
1. **E1 Concurrent Log Processing Engine:** 7 tests (`E1_Concurrent_Log_Processing/tests/test_e1_parser.py`)
2. **E2 Threat Detection Engine:** 44 tests (`E2_Threat_Detection/tests/test_e2.py`, `test_e3_real_integration.py`)
3. **E3 & E4 Backend Engines:** 46 tests (`E3_E4_Backend/backend/tests/`)
4. **Integration Orchestrator:** 3 tests (`Integration/Orchestration/test_coordinator.py`)
**Total: 100 / 100 tests passing (100% pass rate).**

---

## 5. Launching the Web Dashboard

### On Windows
```cmd
cd version2
run_dashboard.bat
```

### On Linux / macOS
```bash
cd version2
chmod +x run_dashboard.sh
./run_dashboard.sh
```

Open your browser to: **`http://127.0.0.1:8000`**

### Pre-configured Accounts:
- **System Admin:** `admin` / `Demo@12345`
- **Security Analyst:** `analyst` / `Demo@12345`
- **Network Operator:** `netops` / `Demo@12345`
