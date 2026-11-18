# Network Traffic Monitoring and Alert System

**Team 14 – Integrated Security & Performance Monitoring Platform**

This repository hosts the source code, multi-engine architecture, datasets, tests, and documentation for the Network Traffic Monitoring and Alert System.

---

## Repository Structure & Versions

```
network-traffic-monitoring-alert-system/
├── version1/                      # Version 1 (Integrated 4-Engine System)
│   ├── E1_Concurrent_Log_Processing/   # Log streamer, parser, and models
│   ├── E2_Threat_Detection/            # Rule-based detection engine (38 Excel rules)
│   ├── E3_E4_Backend/                  # SQLite persistence & Flask web dashboard
│   ├── Integration/                    # Orchestration & Cross-engine contracts
│   ├── logs/                           # Supported Zeek test logs (conn, weird, tunnel)
│   ├── network_monitor.db              # Pre-seeded SQLite database
│   ├── run_dashboard.bat               # Dashboard launcher (:8000)
│   ├── run_tests.bat                   # Test suite runner (92/92 tests passing)
│   ├── test_live_system.py             # Live end-to-end multi-log verification
│   └── README.md                       # Comprehensive Version 1 documentation
│
├── version2/                      # Version 2 (Upcoming updates & enhancements)
│
└── .gitignore                     # Repository-wide ignore rules
```

---

## Versions Overview

### Version 1 (`version1/` & branch `version1`)
- **Engine Interaction Pipeline:** Direct in-memory coordination ($E1 \to E3 \to E2 \to E3 \to E4$).
- **Multi-Log Parsing:** Dynamic `#path` and `#fields` auto-detection for **any** Zeek log file (`conn.log`, `weird.log`, `tunnel.log`, `dpd.log`, `capture_loss.log`, etc.).
- **Threat Detection:** Complete coverage of all **38 Zeek Excel rules** + supplementary heuristics, with sliding cooldown suppression and max-heap priority ordering.
- **Concurrency & Performance:** Pure Python parallel worker pool (`ProcessPoolExecutor` - Option A), delivering **2.1x speedup** on multi-core execution (exceeding NFR-01 target of $\ge 1.5\times$).
- **Data Management & API:** SQLite 3NF schema with Write-Ahead Logging (WAL), REST API, and interactive Web Dashboard with Role-Based Access Control (`admin`, `analyst`, `netops`).
- **Test Pass Rate:** **92 / 92 unit and integration tests passing (100%)**.

### Version 2 (`version2/`)
- Reserved for subsequent feature enhancements, rule expansions, or architectural updates.

---

## Quickstart for Version 1

### 1. Launch the Web Dashboard
```cmd
cd version1
run_dashboard.bat
```
Open your browser to: **`http://127.0.0.1:8000`**
- **Default logins:** `admin` / `analyst` / `netops`
- **Password:** `Demo@12345`

### 2. Run Test Suite
```cmd
cd version1
run_tests.bat
```

For complete architectural details, REST API references, and rule listings, see [version1/README.md](version1/README.md).
