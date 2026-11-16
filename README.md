# E2 – Rule-Based Threat Detection & Alert Prioritization Engine

Language: **Python 3.8+** (inferred from the Gate-0 doc: psutil, threads). No third-party packages at runtime
(`openpyxl` only for `tools/build_rules_from_excel.py`).

> **Read section 7 first.** No E1/E3 source code was uploaded, so E2 talks to E3 through a small
> interface (`e2_engine/e3_client.py`) that E3 must satisfy. Nothing about E3's real API or schema was assumed silently.

## 1. Workflow

```
E1 parses logs ──► E3 stores events ──► E2.run(run_id) ──► E3 stores alerts ──► E4 shows them
                                          │
   get_run_status == COMPLETED ◄──────────┤ 1 fetch pages of events via E3 interface
                                          │ 2 normalise each record (bad record -> skipped, counted)
                                          │ 3 sort by (timestamp, event_id)   <- same order in every E1 mode
                                          │ 4 rules: single-event + time-window detectors (hash-map dispatch)
                                          │ 5 cooldown check per (rule, source IP)  -> suppress or keep
                                          │ 6 push kept alerts into the priority MAX-HEAP
                                          │ 7 pop heap (CRITICAL first) and send to E3 in batches, retry on failure
                                          └ 8 return DetectionSummary
```

## 2. Rules (from your Excel) → event fields

Rules live in `e2_engine/rules/rules.json`, generated from the Excel by `tools/build_rules_from_excel.py`.
Severity/name/trigger text are copied from the Excel; the script **stops** if an Excel row has no machine condition,
and a test checks all 38 rows (name + severity) against the Excel.

| Excel rows | Severity | How E2 detects it | Fields needed in the E3 event |
|---|---|---|---|
| R01 Address_Scan | CRITICAL | window 300 s: failed TCP conns, per (src_ip, dst_port), **> 25** unique dst_ip | proto, conn_state, src_ip, dst_ip, dst_port |
| R02 Port_Scan | CRITICAL | window 300 s: failed TCP conns, per (src_ip, dst_ip), **≥ 15** unique dst_port | same |
| R03–R06 fragment_* | CRITICAL | single event: weird name | `weird_name` (or `name` when log_source=weird) |
| R07 Retransmission_Inconsistency | CRITICAL | notice/weird name **or** conn.log `history` contains `'r'` (responder retransmission) | `history`, `notice_type` / `weird_name` |
| R08 FIN_storm, R09 SYN_after_partial, R11 SYN_with_data, R12 RST_storm | HIGH | weird name | `weird_name` |
| R10 TCP_christmas | HIGH | weird name **or** flags ⊇ {FIN,URG,PSH} | `tcp_flags` |
| R13 Content_Gap | HIGH | notice/weird name **or** conn.log `history` contains `'c'` (bad checksum/sequence gap) | `history`, `notice_type` |
| R14 Traceroute | HIGH | window 180 s: packet with TTL < 10 **and** ≥ 3 ICMP Time-Exceeded to the same host | `ttl`, `icmp_type`, src_ip, dst_ip |
| R15–R25 weirds | MEDIUM | weird name | `weird_name` |
| R26/R27 DPD | MEDIUM | notice name | `notice_type` |
| R28 Tunnel | MEDIUM | any record from tunnel.log | `log_source` |
| R29 Too_Much_Loss | LOW | capture_loss record, `percent_lost > 10` | `log_source`, `percent_lost` |
| R30 Too_Little_Traffic | LOW | capture_loss record, `acks < 1` | `log_source`, `acks` |
| R31–R34 checksums | LOW | weird name **or** checksum flag invalid (IP / TCP / UDP / ICMP) | `checksum_valid`, `ip_checksum_valid`, proto |
| R35–R37 weirds | LOW | weird name | `weird_name` |
| R38 new host/service | LOW | any record from known_hosts / known_services | `log_source` |

**Severity / priority:** severity = the Excel "Priority" column (CRITICAL/HIGH/MEDIUM/LOW). Numeric priority =
4/3/2/1 (higher = more urgent, used by the max-heap). The Excel has one column, so priority is derived from it; a
rule may override `priority` in `rules.json`.

### Rules in your documents (FR-04) that are NOT in the Excel – added as *proposed defaults*
| ID | Rule | Proposed condition | Sev. |
|---|---|---|---|
| S01 | SYN flood | ≥ 100 SYN-only (or conn_state S0) from one src to one dst:port in 10 s | HIGH |
| S02 | ICMP sweep | ICMP echo to ≥ 10 unique hosts from one src in 60 s | MEDIUM |
| S03 | Ping flood | ≥ 100 ICMP echo from one src to one dst in 10 s | HIGH |
| S04 | Abnormal TCP flags | NULL, SYN+FIN, SYN+RST (Xmas is R10) | HIGH |
| S05 | Weak TLS | SSLv2, SSLv3, TLSv1.0, TLSv1.1 | MEDIUM |
| S06 | Blacklisted IP | src or dst in `rules/blacklist.txt` (IPv4+IPv6, hash set) | HIGH |
| S07 | High Volume / DoS Anomaly | `orig_bytes > 50,000` or `orig_pkts > 1,000` with 0 responder bytes/packets | HIGH |

All of these numbers are **my suggestions, not from your documents** – confirm or edit in
`tools/build_rules_from_excel.py` (then re-run it). Set `include_supplementary_rules=False` to switch them off.

## 3. Missing values (decide / confirm)
1. **Cooldown length** – docs say "cooldown timer", no value. Default **300 s** (`E2Config.cooldown_sec`), per-rule override possible.
2. **Supplementary rule thresholds/severities** – table above.
3. **Blacklist content** – `rules/blacklist.txt` contains only two documentation-range placeholders (203.0.113.66, 2001:db8::bad).
4. **"Failed connection" states** for R01/R02 – Zeek's own script counts REJ-type failures only; I also include `S0` and `RSTOS0` so filtered-port scans are caught. One line (`FAILED`) in the build script.
5. **R29 boundary** – Excel says "more than 10 %" (I use `>`); Zeek's script uses `>=`.
6. **R30** – Excel says "fewer ACKs than minimum_acks" without a number; Zeek's default is 1, used here.
7. **Priority vs severity** – only one column in the Excel (see above).

## 4. Folder structure
```
e2_project/
├─ run_e2.py                       command-line runner
├─ e2_engine/
│  ├─ config.py       E2Config (cooldown, batch sizes, retries ...)
│  ├─ models.py       Severity, NetEvent, Rule, Hit, Alert, DetectionSummary
│  ├─ normalizer.py   raw E3 record -> NetEvent (field-name ALIASES live here)
│  ├─ rules_loader.py rules.json + blacklist loader/validator
│  ├─ detectors.py    single-event + window detectors, hash-map DetectorSet
│  ├─ cooldown.py     (rule, ip) -> last alert time
│  ├─ heap.py         hand-written priority max-heap
│  ├─ engine.py       E2Engine.process_events() / run()
│  ├─ e3_client.py    E3Interface (what E3 must provide) + InMemoryE3 test stand-in
│  └─ rules/          rules.json, blacklist.txt, the Excel
├─ tools/             build_rules_from_excel.py, make_sample_data.py
├─ sample_data/sample_events.jsonl
└─ tests/test_e2.py   40 tests
```

## 5. How the code works (beginner view)
* **normalizer** – E3 may call a field `id.orig_h`, `src_ip` or `source_ip`; `ALIASES` maps all to one `NetEvent`. Missing/invalid core fields (event_id, timestamp, malformed IP/port) raise `EventValidationError`; the engine catches it, counts an error, and moves on. Optional fields simply become `None`.
* **rules.json** – each rule has a list of *detectors*. Types: `label` (weird/notice name), `log_source`, `match` (field conditions), `blacklist`, `window_unique`, `window_combo`.
* **DetectorSet** – builds hash maps `label → detectors`, `log_source → detectors`, `proto → detectors`, so an event only runs the few detectors that could apply, not all 44 rules.
* **Window detectors** – per key (e.g. `(src_ip, dst_ip)`) keep a `deque` of recent events plus a count map; old entries leave when `now − ts > window`. Events must be time-sorted, which the engine does.
* **Cooldown** – dict `(rule_id, source_ip) → time of last alert`; a repeat within the cooldown is *suppressed* (counted, not stored). Uses event time, so results don't depend on machine speed.
* **Heap** – binary max-heap: higher priority first; ties → earlier event, rule id, IP, alert id (deterministic).
* **Alert ID** – hash of (run, rule, IP, trigger event) so a retry/re-run yields the *same* ID and E3 can ignore the duplicate.
* **Consistency (NFR-03)** – events are sorted by `(ts, event_id)` before detection, so sequential and multithreaded E1 runs give identical alerts (tested by shuffling input).

## 6. Run & verify
```bash
python -m unittest discover -s tests -v          # 40 tests, all should pass
python run_e2.py --events sample_data/sample_events.jsonl --run-id RUN1
python tools/build_rules_from_excel.py           # only after editing the Excel/specs
```
Expected demo result (84 events incl. 1 invalid): **12 alerts** – CRITICAL: R02 port scan, R01 address scan, R03 fragment_overlap;
HIGH: R10 Xmas, 2× S06 blacklist (IPv4+IPv6), R08 FIN_storm; MEDIUM: S05 TLS1.0, S02 ICMP sweep, R28 tunnel; LOW: R32 bad TCP checksum, R29 capture loss;
**3 suppressed** (2 repeat FIN_storm, 1 continuing port scan), **1 error** (bad timestamp). Alerts print CRITICAL → LOW.

Test coverage: one positive test for **every one of the 38 Excel rules** + 6 supplementary; boundaries (25/26 hosts, 14/15 ports, 300 s window edge, 10.0/10.1 % loss, TTL 10, 99/100 SYN); negatives (successful conns, same port repeated, different sources); invalid records; missing optional fields; cooldown (inside / exactly at / different IP / different rule); heap vs `sorted()` on 500 random alerts; shuffled input parity; re-run idempotency; pagination; E3 retry and queueing.
Speed: ~17k events/s for E2 alone on this sandbox (NFR-02 asks ≥ 10k/s for the whole pipeline – measure on your laptop).

## 7. Connecting E2 to E3 – what is needed
E2 connects to E3 via `E3Interface` (`e2_engine/e3_client.py`) or the built-in `E3ServiceAdapter` (`e2_engine/e3_adapter.py`) that speaks directly to Team 14's `DataManagementService`.

Run against real E3 SQLite database:
```bash
python run_e2.py --e3-db path/to/network_monitor.db --run-id <run_id>
```
Or via custom adapter:
```bash
python run_e2.py --e3 my_adapter:MyE3 --run-id <run_id>
```

### Status of Team 14 (E3) Integration:
1. **Run Status:** E3 provides `get_run(run_id)["status"] == "COMPLETED"`. `E3ServiceAdapter` maps this transparently.
2. **Fetch Events:** E3 returns unevaluated events via `get_events_for_detection(run_id)`. The column names `event_timestamp`, `conn_state_code`, and `protocol_name` are registered in `e2_engine/normalizer.py`.
3. **Save Alerts:** `save_alerts` in `E3ServiceAdapter` transforms alerts to E3's schema (`alert_id`, `run_id`, `severity`, `rule_code`, `affected_ip`, `window_start`, `detected_at`, `related_event_ids`, `suppression_count`).
4. **Mark Evaluated:** Evaluated events are updated via `e3.mark_events_evaluated(event_ids)`.

### Status of Team (E1) Integration:
1. **Deterministic event_id:** Fulfilled (monotonic 0-based record ordinals).
2. **Log Sources Limitation:** E1 currently parses only `conn.log` / `conn.txt`. Rules R01 (Address Scan), R02 (Port Scan), S01 (SYN Flood), and S06 (IP Blacklist) function fully with E1's data. Rules R03–R38 require additional log sources (`weird.log`, `notice.log`, `capture_loss.log`, etc.) that E1 does not yet parse.
3. **TCP flags:** E1 does not extract per-packet TCP flags; connection-level states (`S0`, `REJ`, etc.) are provided.
4. **Timestamps:** Compatible (UTC ISO-8601 strings and epoch seconds).

## 8. Known limitations
* S01 SYN flood is per source; spoofed-source floods need a per-victim rule (easy extension).
* R14 traceroute simplifies Zeek's src-dst pair to "originator IP".
* All events of a run are loaded and sorted in memory (≈ fine for 500k records; for bigger runs ask E3 for `ORDER BY ts, event_id` paging and stream).
