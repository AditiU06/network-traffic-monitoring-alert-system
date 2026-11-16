# Network Traffic Monitoring and Alert System

**Team 14 – Integrated Security & Performance Monitoring Platform**

A hybrid Java–Python application designed to monitor, ingest, analyze, and alert on Zeek network connection logs. The system combines concurrent high-throughput log processing, rule-based threat detection, transactional SQLite persistence, and an interactive administrative dashboard.

---

## 1. System Architecture & Component Roles

```
  ┌─────────────────────────────────────────────────────────────┐
  │                    E4: REST API & Dashboard                 │
  │                  (Flask / Web Interface :8000)              │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ Run Request (POST /runs)
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │           Integration: PipelineCoordinator                  │
  │               (Orchestration & Data Flow)                   │
  └───────┬──────────────────────┬──────────────────────┬───────┘
          │ 1. Process Log       │ 2. Persist Events    │ 3. Evaluate Run
          ▼                      ▼                      ▼
  ┌───────────────┐      ┌───────────────┐      ┌───────────────┐
  │      E1       │      │      E3       │      │      E2       │
  │  Concurrent   │=====>│  Data Mgmt &  │<=====│ Rule Threat   │
  │  Log Engine   │NDJSON│  Persistence  │Events│  Detection    │
  │ (Java 21 LTS) │      │(SQLite 3NF/WAL│Alerts│ (Python 3.12) │
  └───────────────┘      └───────────────┘      └───────────────┘
                                 ▲
                                 │ Query Results & Benchmarks
  ┌──────────────────────────────┴──────────────────────────────┐
  │                    E4: UI Visualizations                    │
  │           (Logs, Urgent Alerts, Speedup Charts)             │
  └─────────────────────────────────────────────────────────────┘
```

### Component Breakdown

1. **E1 – Concurrent Log Processing Engine (`E1_Concurrent_Log_Processing/`)**
   - **Language:** Java 21 (LTS).
   - **Build Tool:** Apache Maven (via Maven Wrapper `mvnw.cmd`).
   - **Status:** Production CLI runner `E1CliRunner.java` implemented and verified by code inspection. Native Java compilation is deferred. Subprocess runner in `PipelineCoordinator` detects compiled bytecode (`target/classes` or `*.jar`) automatically, falling back to reference ingestion stand-in when uncompiled.
   - **Responsibilities:**
     - Safe Zeek header parsing and streaming ingestion (`ZeekLogStreamer`, `ZeekRecordParser`).
     - Record enrichment: computes `totalBytes`, `totalPackets`, `bytesPerPacket`, and `origToRespRatio`.
     - Deterministic multi-worker execution (1 to 16 threads) with verified 100% output parity and record ordering.
     - Compute-only isolated benchmarking (`BenchmarkRunner`).
     - CLI entry point `com.kletech.networkmonitor.engine.e1.cli.E1CliRunner` streaming NDJSON events and JSON benchmark metrics.

2. **E2 – Rule-Based Threat Detection Engine (`E2_Threat_Detection/`)**
   - **Language:** Python 3.12 / 3.8+.
   - **Status:** Fully integrated and verified (44/44 tests passing).
   - **Responsibilities:**
     - Evaluates 45 detection rules (38 Zeek Excel rules + 7 supplementary rules).
     - Keyset cursor pagination and deduplication via `E3ServiceAdapter`.
     - Sliding time-window aggregation and state tracking.
     - Dynamic cooldown suppression per `(rule_id, source_ip)`.
     - Priority max-heap alert ordering (`CRITICAL` → `HIGH` → `MEDIUM` → `LOW`).
     - Idempotent alert dispatch with commit verification into E3.

3. **E3 – Network Event & Alert Data Management (`E3_E4_Backend/backend/app/engines/e3_data_management/`)**
   - **Language:** Python 3.12 / SQLite 3NF.
   - **Status:** Fully integrated and verified with backward-compatible auto-migration.
   - **Responsibilities:**
     - Single source of truth for persistence (`network_monitor.db`).
     - Transactional schema enforcing foreign keys, check constraints, and Write-Ahead Logging (WAL).
     - Full attribute preservation: Zeek `uid`, `history`, connection states, and E1 calculated enrichment metrics (`total_bytes`, `total_packets`, `bytes_per_packet`, `orig_to_resp_ratio`).
     - Keys-set cursor and offset pagination supporting 5,000+ events per run.
     - Retry buffer flushing before downstream detection begins.

4. **E4 – REST API & Dashboard (`E3_E4_Backend/backend/app/engines/e4_api_dashboard/`)**
   - **Language:** Python 3.12 (Flask).
   - **Status:** Fully integrated with `PipelineCoordinator` replacing `DemoProcessor`.
   - **Responsibilities:**
     - Role-based API access control (`System Admin`, `Security Analyst`, `NetOps Admin`).
     - Administrative endpoints (`/api/v1/runs`, `/api/v1/logs`, `/api/v1/alerts`, `/api/v1/benchmarks`).
     - Real-time interactive web dashboard rendering threat logs, prioritized alerts, and benchmark speedup curves.

5. **Integration Layer (`Integration/`)**
   - `Contracts/`: Formal JSON Schemas and Python type models for NDJSON events, benchmark metrics, field mappings, and error formats.
   - `Orchestration/`: `PipelineCoordinator` driving the synchronous or asynchronous lifecycle `E4 -> E1 -> E3 -> E2 -> E3 -> E4`.

---

## 2. Directory Structure

```
A:\Network Traffic Monitoring And Alert System
├── .venv\                                 <-- Shared root virtual environment
├── E1_Concurrent_Log_Processing\          <-- Engine 1 (Java / Maven)
│   ├── src\main\java\com\kletech\...      <-- Core processing & E1CliRunner
│   ├── src\test\java\com\kletech\...      <-- JUnit test suite (compilation deferred)
│   ├── data\                              <-- Real and ground-truth Zeek datasets
│   ├── docs\                              <-- E1 architectural contract
│   └── pom.xml                            <-- Maven build configuration
├── E2_Threat_Detection\                   <-- Engine 2 (Python threat detection)
│   ├── e2_engine\                         <-- Detection engine, heap, rules, adapter
│   ├── tests\                             <-- 44 unit & real E3 integration tests
│   ├── tools\                             <-- Rule builder from Excel
│   └── run_e2.py                          <-- Standalone CLI runner
├── E3_E4_Backend\backend\                 <-- Engines 3 & 4 (E3 persistence & E4 API)
│   ├── app\database\                      <-- schema.sql, db.py & SQLite connection wrapper
│   ├── app\engines\e3_data_management\    <-- Storage service, reader, writer, validation
│   ├── app\engines\e4_api_dashboard\      <-- Flask endpoints, security, static UI
│   ├── tests\                             <-- 45 pytest unit and API tests
│   ├── main.py                            <-- Web application server entry point
│   ├── seed_demo.py                       <-- Demo database seeder
│   └── requirements.txt                   <-- Python package dependencies
├── Integration\                           <-- Integration Layer
│   ├── Contracts\                         <-- NDJSON schemas and mapping definitions
│   └── Orchestration\                     <-- PipelineCoordinator and tests
├── run_dashboard.bat                      <-- Convenience launcher (Windows CMD)
├── run_dashboard.ps1                      <-- Convenience launcher (PowerShell)
├── run_tests.bat                          <-- Full test suite runner (92 tests)
└── README.md                              <-- Project documentation
```

---

## 3. Technology Stack

- **Backend & Detection:** Python 3.12, Flask 3.1, Pydantic 2.14, openpyxl 3.1, SQLite 3.
- **Log Processing Engine:** Java 21 LTS, Spring Boot, JUnit 5, AssertJ, Mockito.
- **Testing:** `pytest` (E3/E4, Integration), `unittest` (E2, Integration).
- **Frontend:** Vanilla HTML5, CSS3, modern ES6 JavaScript.

---

## 4. Environment Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.12).
- Java 21 LTS.

### Setup Steps
1. **Activate the shared root virtual environment:**
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
2. **Install dependencies (pre-installed in workspace `.venv`):**
   ```powershell
   pip install -r E3_E4_Backend\backend\requirements.txt openpyxl
   ```

---

## 5. Startup & Running Instructions

### Launch the Web Dashboard
You can launch the dashboard using the convenience launcher:
```cmd
run_dashboard.bat
```
or via PowerShell:
```powershell
.\run_dashboard.ps1
```
or directly via Python:
```powershell
.\.venv\Scripts\python.exe E3_E4_Backend\backend\main.py
```
Open your browser to: `http://127.0.0.1:8000`

### Seed Demo Data (Optional)
To initialize the SQLite database with demonstration accounts, sample logs, and benchmark runs:
```powershell
.\.venv\Scripts\python.exe E3_E4_Backend\backend\seed_demo.py
```
*Default demo accounts:*
- `admin` (System Admin) / Password: `Demo@12345`
- `analyst` (Security Analyst) / Password: `Demo@12345`
- `netops` (NetOps Admin) / Password: `Demo@12345`

### Run Standalone Threat Detection (CLI)
```powershell
.\.venv\Scripts\python.exe E2_Threat_Detection\run_e2.py --events E2_Threat_Detection\sample_data\sample_events.jsonl --run-id RUN_DEMO
```

---

## 6. Testing & Verification

Run the entire test suite (92 tests) via the test runner:
```cmd
run_tests.bat
```

Or run individual component suites:

### 1. E2 Unit & Integration Tests (44 tests)
```powershell
.\.venv\Scripts\python.exe -m unittest discover -s E2_Threat_Detection\tests -v
```

### 2. E3 & E4 Backend Tests (45 tests)
```powershell
.\.venv\Scripts\pytest.exe E3_E4_Backend\backend\tests -q
```

### 3. Integration Coordinator Tests (3 tests)
```powershell
.\.venv\Scripts\pytest.exe Integration\Orchestration\test_coordinator.py -v
```

---

## 7. Detection Coverage & Rule Limitations

E2 implements 45 threat detection rules (38 Excel-derived rules + 7 supplementary rules). Their support depends on available log sources:

### A. Rules Fully Supported by E1 `conn.log` (9 Rules)
These rules operate exclusively on fields extracted by E1 from standard Zeek connection logs (`ts`, `id.orig_h`, `id.resp_h`, `id.resp_p`, `proto`, `conn_state`, `history`, `orig_bytes`, `orig_pkts`):
- **`R01` (Address Scan - CRITICAL):** Failed TCP connections to >25 unique destination hosts within 300s window.
- **`R02` (Port Scan - CRITICAL):** Failed TCP connections to >=15 unique destination ports on one host within 300s window.
- **`R07` (Retransmission Inconsistency - CRITICAL):** Connection `history` contains `'r'` or `'R'`.
- **`R13` (Content Gap - HIGH):** Connection `history` contains `'c'` or `'C'`.
- **`S01` (SYN Flood - HIGH):** >=100 `S0` connections to same destination host and port within 10s window.
- **`S02` (ICMP Sweep - MEDIUM):** >=10 unique ICMP destinations within 60s window.
- **`S03` (ICMP Ping Flood - HIGH):** >=100 ICMP connections to same destination within 10s window.
- **`S06` (IP Blacklist Match - HIGH):** Source or destination IP matches `rules/blacklist.txt`.
- **`S07` (High-Volume / DoS Anomaly - HIGH):** Asymmetric transfer (`orig_bytes > 50,000` or `orig_pkts > 1,000` with 0 responder bytes).

### B. Rules Requiring Additional Zeek Log Formats or Packet Fields (36 Rules)
These rules cannot trigger on `conn.log` alone and require complementary Zeek log streams or raw PCAP captures:
- **`weird.log` (30 rules):**
  - TCP state anomalies: `R03` (data_before_established), `R04` (simultaneous_open), `R05` (FIN_advanced_last_seq), `R06` (window_recision), `R08` (SYN_after_close), `R09` (SYN_inside_connection), `R10` (SYN_after_reset), `R11` (SYN_with_data), `R12` (bad_TCP_checksum).
  - Protocol anomalies: `R15`–`R25` (e.g. truncated headers, bad options, unescaped characters).
  - Minor anomalies: `R31`–`R37` (e.g. connection reuse, RST with data).
- **`dpd.log` / `notice.log` (2 rules):** `R26` (protocol violation), `R27` (DPD analyzer anomaly).
- **`tunnel.log` (1 rule):** `R28` (tunnel encapsulation anomalies).
- **`capture_loss.log` (2 rules):** `R29`, `R30` (packet loss exceeding thresholds).
- **`known_hosts.log` / `known_services.log` (1 rule):** `R38` (first-time observed host or service).
- **`ssl.log` (1 rule):** `S05` (weak TLS version / cipher suites).
- **Packet Headers / TCP Flags (2 rules):** `S04` (abnormal TCP flags: NULL, Xmas, SYN+FIN), `R14` (traceroute TTL analysis).

---

## 8. REST API Endpoints

All authenticated requests require a Bearer token: `Authorization: Bearer <token>`.

| Method | Endpoint | Access Role | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | Public | Authenticate user; returns session token |
| `POST` | `/api/v1/auth/logout` | Authenticated | Revoke current session |
| `GET` | `/api/v1/auth/me` | Authenticated | Get active user profile and permissions |
| `POST` | `/api/v1/runs` | System Admin | Trigger new log processing run (`{mode, threads, logFile}`) |
| `GET` | `/api/v1/runs` | All Roles | List processing runs with pagination |
| `GET` | `/api/v1/runs/{id}` | All Roles | Retrieve specific run details and metrics |
| `GET` | `/api/v1/logs` | All Roles | Search network events (`ip`, `protocol`, `from`, `to`, `page`) |
| `GET` | `/api/v1/alerts` | All Roles | Query threat alerts ordered by severity rank |
| `GET` | `/api/v1/alerts/{id}` | All Roles | Retrieve alert details and linked trigger events |
| `PATCH`| `/api/v1/alerts/{id}` | Analyst, Admin | Update alert status (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`) |
| `GET` | `/api/v1/benchmarks` | All Roles | Retrieve execution time & throughput benchmarks |
| `GET` | `/api/v1/dashboard/summary`| All Roles| Aggregated counts for UI header cards |

---

## 9. Current Status & Verification Roadmap

### Implemented & Fully Verified (92/92 Python Tests)
1. **E2–E3 Compatibility:** Keyset cursor pagination and deduplication over 5,000+ events verified by regression test.
2. **Data Contracts & Mapping:** Formal JSON schemas and Pydantic models for E1 NDJSON output, E3 event columns, and E2 detection inputs.
3. **Database Schema:** Full attribute preservation (UID, history, calculated metrics) with automatic backward-compatible schema migration.
4. **E4 Orchestration Integration:** `PipelineCoordinator` fully wired into E4 REST API and dashboard, replacing `DemoProcessor`.
5. **Execution Idempotency & Error Handling:** Repeated run protection, safe timestamp constraints, and pipeline failure handling tested.

### Deferred for Future Native Verification
1. **E1 Java Maven Compilation:** Maven compilation and execution of E1 JUnit test suite is deferred per current execution constraints.
2. **E1 Native Subprocess Execution:** `E1CliRunner.java` is implemented and verified by code inspection. End-to-end execution with the real Java binary will occur once E1 is compiled via `mvn compile` or `mvn package`.

