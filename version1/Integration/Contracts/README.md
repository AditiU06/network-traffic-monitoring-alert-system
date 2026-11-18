# Integration Contracts: Network Traffic Monitoring & Alert System

This directory documents the shared interfaces, payload schemas, field mappings, and protocols connecting:
- **E1:** Concurrent Log Processing Engine (Java)
- **E2:** Threat Detection Engine (Python)
- **E3:** Network Event & Alert Data Management (Python / SQLite)
- **E4:** REST API & Web Dashboard (Python / Flask)

---

## 1. E1 Processed Event NDJSON Contract

When processing a log file, E1 outputs processed and enriched network events either to standard output or to a dedicated `.ndjson` (JSON Lines) file. Each line is a valid JSON object matching [`e1_processed_event.schema.json`](e1_processed_event.schema.json).

### Example Record:
```json
{
  "record_ordinal": 0,
  "timestamp": "2018-05-19T20:57:19.123456Z",
  "uid": "C1001",
  "source_ip": "192.168.2.5",
  "source_port": 50000,
  "destination_ip": "10.0.0.1",
  "destination_port": 443,
  "protocol": "tcp",
  "service": "ssl",
  "duration": 0.045,
  "orig_bytes": 520,
  "resp_bytes": 4890,
  "conn_state": "SF",
  "history": "ShADadFf",
  "orig_pkts": 8,
  "resp_pkts": 12,
  "total_bytes": 5410,
  "total_packets": 20,
  "bytes_per_packet": 270.5,
  "orig_to_resp_ratio": 0.1063
}
```

---

## 2. E1 Benchmark Metrics JSON Contract

When executed in benchmark mode, E1 outputs performance metrics matching [`e1_benchmark_metrics.schema.json`](e1_benchmark_metrics.schema.json).

### Example Metrics:
```json
{
  "record_count": 100000,
  "worker_count": 4,
  "sequential_duration_ms": 12450.5,
  "multithreaded_duration_ms": 4890.2,
  "sequential_throughput": 8031.8,
  "multithreaded_throughput": 20448.9,
  "speedup": 2.55,
  "sequential_cpu_load": 95.5,
  "multithreaded_cpu_load": 380.2,
  "sequential_observed_heap_bytes": 245000000,
  "multithreaded_observed_heap_bytes": 268000000,
  "output_parity": true
}
```

---

## 3. Field Mappings

### E1 to E3 (`network_event` Table)

| E1 Field | E3 Column | Type | Description |
|---|---|---|---|
| `record_ordinal` | (Derived `event_id`) | TEXT | Constructed as `{run_id}-{record_ordinal}` |
| - | `run_id` | TEXT | Identifier of the processing run |
| `timestamp` | `event_timestamp` | TEXT | UTC ISO-8601 string |
| `source_ip` | `source_ip` | TEXT | IPv4/IPv6 source address |
| `source_port` | `source_port` | INTEGER | Port number or NULL |
| `destination_ip` | `destination_ip` | TEXT | IPv4/IPv6 destination address |
| `destination_port` | `destination_port` | INTEGER | Port number or NULL |
| `protocol` | `protocol_id` | INTEGER | Foreign key to `protocol` lookup table |
| `conn_state` | `conn_state_code` | TEXT | Zeek state code (SF, S0, REJ, etc.) |
| `service` | `service` | TEXT | Application service name |
| `duration` | `duration` | REAL | Duration in seconds |
| `orig_bytes` | `orig_bytes` | INTEGER | Originator bytes |
| `resp_bytes` | `resp_bytes` | INTEGER | Responder bytes |
| `orig_pkts` | `orig_pkts` | INTEGER | Originator packets |
| `resp_pkts` | `resp_pkts` | INTEGER | Responder packets |
| `uid` | `uid` | TEXT | Zeek unique identifier |
| `history` | `history` | TEXT | TCP flag history sequence |
| `total_bytes` | `total_bytes` | INTEGER | Enriched total byte count |
| `total_packets` | `total_packets` | INTEGER | Enriched total packet count |
| `bytes_per_packet` | `bytes_per_packet` | REAL | Enriched byte/packet ratio |
| `orig_to_resp_ratio` | `orig_to_resp_ratio` | REAL | Enriched payload ratio |
| `log_source` | `log_source` | TEXT | Source log file type (`conn`, `weird`, `tunnel`, etc.) |
| `weird_name` | `weird_name` | TEXT | Zeek anomaly name (`fragment_overlap`, `FIN_storm`, etc.) |
| `notice_type` | `notice_type` | TEXT | Zeek notice type or trigger label |
| `percent_lost` | `percent_lost` | REAL | Packet loss percentage (capture_loss.log) |
| `acks` | `acks` | INTEGER | TCP acknowledgement count |

### E3 to E2 (`NetEvent` Object)

E2's `normalizer.py` maps database rows returned by E3's `get_events_for_detection(run_id)` via its alias dictionary:
- `event_id` → `event_id`
- `run_id` → `run_id`
- `event_timestamp` → `ts` (parsed to epoch float)
- `protocol_name` → `proto`
- `source_ip` → `src_ip`
- `source_port` → `src_port`
- `destination_ip` → `dst_ip`
- `destination_port` → `dst_port`
- `conn_state_code` → `conn_state`
- `history` → `history` (enables R07 & R13 rules)
- `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts`

---

## 4. Run Statuses & Lifecycle

```
[ POST /runs ] ──> Status: RUNNING
       │
       ▼
 [ E1 Processing ] ──(Fail)──> Status: FAILED
       │ (Success)
       ▼
 [ E3 Event Ingestion ]
       │
       ▼
 [ E2 Threat Detection ] ──(Fail)──> Status: FAILED
       │ (Success)
       ▼
 [ E3 Alert Persistence ] ──> Status: COMPLETED
```

Allowed Status Values:
- `RUNNING`: Ingestion, parsing, or threat detection active.
- `COMPLETED`: Ingestion and detection completed successfully; results persisted.
- `FAILED`: Unrecoverable exception during log parsing, validation, or persistence.

---

## 5. Standard Error Representation

All REST API errors and integration pipeline failures conform to:
```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable description",
    "details": {}
  }
}
```
Common Error Codes:
- `RUN_NOT_FOUND`: Specified run ID does not exist.
- `INVALID_INPUT`: Malformed parameters or file path outside containment root.
- `E1_EXECUTION_FAILURE`: Non-zero exit code or timeout from Java processing engine.
- `E2_DETECTION_FAILURE`: Unhandled error during threat detection evaluation.
