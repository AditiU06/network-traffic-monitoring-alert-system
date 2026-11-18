# Network Traffic Monitoring and Alert System

**Team 14 – Integrated Security & Performance Monitoring Platform**

This repository hosts the source code, multi-engine architecture, datasets, tests, and documentation for the Network Traffic Monitoring and Alert System across two maintained versions.

---

## Repository Structure & Versions

```
network-traffic-monitoring-alert-system/
├── version1/                      # Version 1 (Baseline integrated 4-engine platform)
│   ├── E1_Concurrent_Log_Processing/   # Log streamer, parser, and models
│   ├── E2_Threat_Detection/            # Rule-based detection engine (38 Excel rules)
│   ├── E3_E4_Backend/                  # SQLite persistence & Flask web dashboard
│   ├── Integration/                    # Orchestration & Cross-engine contracts
│   ├── logs/                           # Supported Zeek test logs (conn, weird, tunnel)
│   ├── network_monitor.db              # Pre-seeded SQLite database
│   ├── run_dashboard.bat               # Dashboard launcher (:8000)
│   ├── run_tests.bat                   # Test suite runner (92 tests passing)
│   ├── test_live_system.py             # Live end-to-end multi-log verification
│   └── README.md                       # Comprehensive Version 1 documentation
│
├── version2/                      # Version 2 (Pure Python E1 Engine & Full Architecture Refinement)
│   ├── E1_Concurrent_Log_Processing/   # Exclusive Python E1 concurrent parser (18 Zeek types)
│   │   ├── e1_processor.py             # Multi-format parser, parallel worker pool, psutil benchmark
│   │   ├── models.py                   # ParseErrorRecord, BenchmarkResult models
│   │   └── tests/                      # 7 E1 parser and equivalence tests
│   ├── E2_Threat_Detection/            # Rule-based threat detection (38 Excel rules)
│   ├── E3_E4_Backend/                  # SQLite WAL persistence (E3) & Flask REST API / Web Dashboard (E4)
│   ├── Integration/                    # Formal contracts & PipelineCoordinator orchestrator
│   ├── logs/                           # Multi-format Zeek logs
│   ├── run_dashboard.bat               # Dashboard launcher (:8000)
│   ├── run_dashboard.ps1               # PowerShell launcher
│   ├── run_dashboard.sh                # Linux/macOS launcher
│   ├── run_tests.bat                   # Test suite runner (100/100 tests passing)
│   ├── run_tests.sh                    # Linux/macOS test suite runner
│   ├── test_live_system.py             # Live end-to-end multi-log verification
│   └── README.md                       # Comprehensive Version 2 documentation
│
└── .gitignore                     # Repository-wide ignore rules
```

---

## Versions Overview

### Version 1 (`version1/` & branch `version1`)
- **Engine Interaction Pipeline:** Direct in-memory coordination ($E1 \to E3 \to E2 \to E3 \to E4$).
- **Multi-Log Parsing:** Dynamic `#path` and `#fields` auto-detection for Zeek log files (`conn.log`, `weird.log`, `tunnel.log`, `dpd.log`, `capture_loss.log`, etc.).
- **Threat Detection:** Complete coverage of all **38 Zeek Excel rules** + supplementary heuristics, with sliding cooldown suppression and max-heap priority ordering.
- **Concurrency & Performance:** Parallel worker pool (`ProcessPoolExecutor`), delivering **2.1x speedup** on multi-core execution (exceeding NFR-01 target of $\ge 1.5\times$).
- **Data Management & API:** SQLite 3NF schema with Write-Ahead Logging (WAL), REST API, and interactive Web Dashboard with Role-Based Access Control (`admin`, `analyst`, `netops`).
- **Test Pass Rate:** **92 / 92 unit and integration tests passing**.

### Version 2 (`version2/`)
- **Exclusive Python E1 Log Processing:** Pure Python multi-format concurrent log engine completely decoupled from legacy JVM/Maven artifacts. Located directly in `E1_Concurrent_Log_Processing/`.
- **Expanded Zeek Format Support (18 Types):** `conn`, `weird`, `notice`, `tunnel`, `dns`, `http`, `ssl`, `x509`, `files`, `ssh`, `ftp`, `smtp`, `dhcp`, `arp`, `dpd`, `capture_loss`, `known_hosts`, and `known_services`.
- **Strict Data Validation & Precision:**
  - Preserves fractional microsecond timestamps without fabrication.
  - Distinguishes missing values (`-`, `(empty)`) from zeros; preserves missing IPs as `None` (no `0.0.0.0` spoofing).
  - Explicitly separates boolean `notice` (weird.log) from `notice_type` (notice.log).
  - Persists parsing errors (`parse_error` table) with original line numbers for complete debuggability.
- **Genuine Benchmarking:**
  - Removed artificial speedup multipliers and hardcoded CPU/memory numbers.
  - Real hardware telemetry measured using `psutil`.
  - Sequential vs. parallel equivalence verified via complete normalized event dictionary comparisons.
- **Engine Reliability & Dispatch:**
  - Eliminated silent fallback to `DemoProcessor` during normal execution.
  - E2 retry logic with quadratic backoff ensures zero dropped alerts when SQLite is busy (`QUEUED`).
- **Test Pass Rate:** **100 / 100 unit and integration tests passing (100% pass rate)**.

---

## Quickstart

### Running Version 2 (Recommended)

#### 1. Run Complete Test Suite (100 tests)
```cmd
cd version2
run_tests.bat
```

#### 2. Launch the Web Dashboard
```cmd
cd version2
run_dashboard.bat
```
Navigate to: **`http://127.0.0.1:8000`**
- **Admin Login:** `admin` / `Demo@12345`
- **Analyst Login:** `analyst` / `Demo@12345`
- **NetOps Login:** `netops` / `Demo@12345`

### Running Version 1
```cmd
cd version1
run_tests.bat
run_dashboard.bat
```
