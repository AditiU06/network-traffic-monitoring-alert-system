# Team 14 - Engines 3 and 4 (data management, REST API and dashboard)

E3 is the **only** part of the system that touches the database. E1, E2 and E4 call `DataManagementService`.
E4 is the REST API (`/api/v1/*`) and the web dashboard. It never reads logs or the database itself: it calls E3.

## Quick start
```
pip install -r requirements.txt
python -m pytest -q                      # 43 tests
python seed_demo.py                      # demo users, sample log, one finished run
python main.py                           # open http://127.0.0.1:8000  (admin / analyst / netops, password Demo@12345)
python create_user.py <user> <email> "System Admin"     # real accounts (asks for the password)
```
The demo passwords are public: use `create_user.py` for anything real.

## Folder map
```
backend/
├── demo.py                         # one full run: E1 -> E3 -> E2 -> E3 -> E4
├── app/database/
│   ├── schema.sql                  # 13 tables, keys, constraints, indexes, starting data
│   └── db.py                       # opens SQLite, foreign keys ON, WAL, transaction()
├── main.py  seed_demo.py  create_user.py  requirements.txt
├── app/engines/e3_data_management/
│   ├── validation.py               # checks one record (IPs, ports, times) before saving
│   ├── writer.py                   # everything that changes data (one transaction each)
│   ├── reader.py                   # searches, filters, paging, dashboard totals, 3 s timeout
│   ├── monitor.py                  # records read times (target: mean < 50 ms)
│   ├── errors.py                   # clear error types for E4 to turn into 400/404/504
│   └── service.py                  # the front door: thread-safe, retry buffer, used by other engines
├── app/engines/e4_api_dashboard/
│   ├── routes.py                   # all /api/v1 endpoints
│   ├── schemas.py                  # checks incoming JSON (Pydantic): threads 1-16, mode, status
│   ├── security.py                 # scrypt password hashes, token hashing, roles, login limiter
│   ├── errors.py                   # one error format + handlers (no stack traces leak)
│   ├── serializer.py               # snake_case -> camelCase for JSON
│   ├── processor.py                # hand-off to E1; DemoProcessor is a stand-in until E1 exists
│   └── static/                     # dashboard: index.html, app.js, style.css
└── tests/                          # 43 tests: E3 (30) and E4 API (13)
```
Run: `python -m pytest -q` and `python demo.py` from `backend/` (Python 3.10+, no extra packages).

## Who calls what
| Caller | Methods |
|---|---|
| E1 | save_processing_run, insert_events_batch, save_parse_errors, save_performance_results |
| E2 | get_events_for_detection, save_alerts, mark_events_evaluated |
| E4 | search_events, search_alerts, get_alert, update_alert_status, get_run, list_runs, get_performance_results, get_dashboard_summary |
| Login | create_user, get_user_by_username, create_session, revoke_session |

## E4 API
| Method and path | Who | What |
|---|---|---|
| POST /auth/login, /auth/logout, GET /auth/me | anyone / logged in | Bearer-token login |
| POST /runs | System Admin | `{mode, threads 1-16, logFile}` -> 202 `{runId, status}`; 400 bad threads; 404 file missing |
| GET /runs, /runs/{id} | any role | runs and their metrics |
| GET /logs | any role | filters: ip, sourceIp, destinationIp, protocol, runId, from, to, page, size |
| GET /alerts, /alerts/{id} | any role | filters: severity, status, ip, runId, ruleCode, from, to; most urgent first |
| PATCH /alerts/{id} | Security Analyst, System Admin | `{status}` |
| GET /benchmarks, /dashboard/summary | any role | speedup chart data, totals |
Errors always look like `{"error": {"code", "message"}}`. Log files are only read from the `logs/` folder, by file name.

## Handing over to E1 & E2 (Integration Complete)
E4 calls `processor.start(run_id, log_path, mode, threads)`. In `main.py`, `DemoProcessor` has been replaced with `PipelineCoordinator` (`Integration.Orchestration.PipelineCoordinator`). 
`PipelineCoordinator` invokes `E1ParallelProcessor` (multi-process parsing across CPU cores), streams parsed events into E3 (`insert_events_batch`), calls E2's detection engine (`E2Engine`), and saves generated alerts and benchmark speedup metrics directly into E3 for dashboard visualization in E4.

## Error types (E3 -> E4)
InvalidInput / InvalidFilterError -> 400 | RunNotFound / AlertNotFound -> 404 | QueryTimeout -> 504
