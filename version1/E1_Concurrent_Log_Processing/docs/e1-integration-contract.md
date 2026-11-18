# Engine 1 (E1) Integration Contract

## A. E1 Responsibilities

Engine 1 (E1: Concurrent Log Processing Engine) is the entry-point ingestion and processing component of the Network Traffic Monitoring and Alert System. Its responsibilities are:

1. **Zeek Log Input Validation & Safe File Handling:**
   - Validates file paths against configured directory containment roots using `InputValidator`.
   - Prevents directory traversal attacks, enforces file existence, readability, regular-file checks, and maximum file-size limits (default 1 GB).
   - Rejects unpermitted, missing, or oversized files before reading.

2. **Dynamic Header & Record Parsing:**
   - Interprets Zeek `#fields` and `#types` metadata dynamically via `ZeekHeaderParser` and `ZeekHeader`.
   - Streams log records line-by-line via `ZeekLogStreamer` without loading entire log files into memory during streaming.
   - Converts individual data rows into strongly-typed, immutable `NetworkEvent` records via `ZeekRecordParser`.
   - Safely skips blank lines, comment lines, and malformed rows (with sanitized error tracking) without crashing the ingestion process.

3. **Deterministic Record Processing & Enrichment:**
   - Enriches parsed network events with computed transmission metrics: `totalBytes`, `totalPackets`, `bytesPerPacket`, and `origToRespRatio`.
   - Provides two execution strategies using identical transformation logic (`EventTransformer`):
     - `SequentialProcessor`: Deterministic single-threaded baseline.
     - `MultithreadedProcessor`: Chunk-based concurrent processing using a bounded worker pool (1 to 16 threads).
   - Guarantees 100% output parity and deterministic record ordering across all worker counts.
   - Enforces result immutability: returns unmodifiable `List<ProcessedNetworkEvent>` collections for both empty and non-empty inputs.

4. **Compute-Only Benchmarking:**
   - Measures isolated compute performance between sequential and multithreaded processing modes using `BenchmarkRunner`.
   - Parses the input dataset exactly once prior to benchmarking; file I/O and parsing are strictly excluded from timed benchmark loops.
   - Performs unmetered warm-up runs, alternating iterations, parity checks on every measured iteration, and median duration/throughput/speedup calculations.

---

## B. Public API: `LogProcessingEngine`

`com.kletech.networkmonitor.engine.e1.LogProcessingEngine` serves as the primary facade and coordination entry point for E1.

### Constructors

```java
// Full dependency injection constructor
public LogProcessingEngine(ZeekLogStreamer streamer, BenchmarkRunner benchmarkRunner)

// Constructor with custom streamer and default BenchmarkRunner
public LogProcessingEngine(ZeekLogStreamer streamer)

// Constructor with custom InputValidator
public LogProcessingEngine(InputValidator validator)

// Constructor with permitted directory root for file validation
public LogProcessingEngine(Path permittedRoot)

// Default constructor permitting files in the current working directory (".")
public LogProcessingEngine()
```

### Ingestion & Parsing Methods

```java
// Parses a Zeek log file once, returning all successfully parsed valid events
public List<NetworkEvent> parseLog(Path logPath)
public List<NetworkEvent> parseLog(String rawPath)
```
- **Throws:**
  - `NullPointerException` if path is null.
  - `ValidationException` if path validation fails (traversal, inaccessible, outside root).
  - `UncheckedIOException` if an I/O error occurs while reading the file.

### Standard Processing Methods (Normal Run)

Normal processing runs once without benchmark warm-up runs, iterations, or profiling overhead.

```java
// Sequential processing
public List<ProcessedNetworkEvent> processSequentially(List<NetworkEvent> events)
public List<ProcessedNetworkEvent> processSequentially(Path logPath)
public List<ProcessedNetworkEvent> processSequentially(String rawPath)

// Multithreaded processing (workerCount in range 1..16)
public List<ProcessedNetworkEvent> processMultithreaded(List<NetworkEvent> events, int workerCount)
public List<ProcessedNetworkEvent> processMultithreaded(Path logPath, int workerCount)
public List<ProcessedNetworkEvent> processMultithreaded(String rawPath, int workerCount)

// Configurable processing router
public List<ProcessedNetworkEvent> process(List<NetworkEvent> events, boolean multithreaded, int workerCount)
public List<ProcessedNetworkEvent> process(Path logPath, boolean multithreaded, int workerCount)
```
- **Return Type:** Unmodifiable `List<ProcessedNetworkEvent>`.
- **Throws:**
  - `NullPointerException` if input events or path is null, or if list contains null elements.
  - `IllegalArgumentException` if `workerCount` is not within `[1, 16]`.
  - `ValidationException` / `UncheckedIOException` on file errors.

### Benchmarking Methods (Compute-Only Performance Measurement)

```java
// Benchmarks already-parsed in-memory events
public BenchmarkMetrics benchmarkEvents(List<NetworkEvent> events, int workerCount)

// Parses a log file once, then benchmarks sequential vs. multithreaded processing
public BenchmarkMetrics benchmarkLog(Path logPath, int workerCount)
public BenchmarkMetrics benchmarkLog(String rawPath, int workerCount)
```
- **Return Type:** Immutable `BenchmarkMetrics` record.
- **Single-Parse Guarantee:** The file is parsed once into an immutable `List<NetworkEvent>` before benchmarking starts. The exact same in-memory list reference is passed to `BenchmarkRunner`.
- **Throws:**
  - `NullPointerException` if input is null.
  - `IllegalArgumentException` if `events` is empty or `workerCount` is not within `[1, 16]`.

---

## C. Data Contract

### 1. `NetworkEvent` (Immutable Java Record)
Package: `com.kletech.networkmonitor.engine.e1.model.NetworkEvent`

| Field | Java Type | Description | Nullability |
|---|---|---|---|
| `recordOrdinal` | `long` | 0-based index of the data record in the stream | Non-null ($\ge 0$) |
| `timestamp` | `Instant` | Event timestamp parsed from Zeek `ts` | Non-null |
| `uid` | `String` | Zeek unique connection identifier | Non-null, non-blank |
| `sourceAddress` | `InetAddress` | Originator IP address (`id.orig_h`) | Non-null (IPv4/IPv6) |
| `sourcePort` | `Integer` | Originator port (`id.orig_p`) | Nullable for ICMP; $1..65535$ for TCP/UDP |
| `destinationAddress`| `InetAddress` | Responder IP address (`id.resp_h`) | Non-null (IPv4/IPv6) |
| `destinationPort` | `Integer` | Responder port (`id.resp_p`) | Nullable for ICMP; $1..65535$ for TCP/UDP |
| `protocol` | `TransportProtocol` | Transport protocol enum (`TCP`, `UDP`, `ICMP`) | Non-null |
| `service` | `String` | Application protocol detected by Zeek | Nullable |
| `duration` | `Double` | Connection duration in seconds | Nullable ($\ge 0.0$ if present) |
| `origBytes` | `Long` | Originator payload bytes | Nullable ($\ge 0$ if present) |
| `respBytes` | `Long` | Responder payload bytes | Nullable ($\ge 0$ if present) |
| `connectionState` | `ConnectionState` | Zeek connection state enum (e.g. `SF`, `S0`, `REJ`) | Non-null |
| `history` | `String` | TCP state history flags | Nullable |
| `origPkts` | `Long` | Originator packet count | Nullable ($\ge 0$ if present) |
| `respPkts` | `Long` | Responder packet count | Nullable ($\ge 0$ if present) |

### 2. `ProcessedNetworkEvent` (Immutable Java Record)
Package: `com.kletech.networkmonitor.engine.e1.model.ProcessedNetworkEvent`

| Field | Java Type | Description | Accessor / Semantics |
|---|---|---|---|
| `recordOrdinal` | `long` | 0-based data record ordinal | Must match `originalEvent.recordOrdinal()` |
| `originalEvent` | `NetworkEvent` | Reference to the underlying parsed event | Direct zero-copy access to all raw connection fields |
| `totalBytes` | `Long` | Sum of `origBytes` and `respBytes` | Null if both are absent; overflow-safe sum |
| `totalPackets` | `Long` | Sum of `origPkts` and `respPkts` | Null if both are absent; overflow-safe sum |
| `bytesPerPacket` | `Double` | `totalBytes / totalPackets` | Null if `totalPackets` is absent or $\le 0$ |
| `origToRespRatio`| `Double` | `origBytes / respBytes` | Null if `respBytes` is absent or $\le 0$ |

#### Accessing Connection and Enriched Data from E2:
```java
ProcessedNetworkEvent event = ...;

// Calculated enrichment metrics:
Long totalBytes = event.totalBytes();
Double bytesPerPacket = event.bytesPerPacket();

// Raw connection details (zero-copy delegation):
String uid = event.originalEvent().uid();
InetAddress srcIp = event.originalEvent().sourceAddress();
Integer dstPort = event.originalEvent().destinationPort();
TransportProtocol proto = event.originalEvent().protocol();
```

---

## D. E2 Integration Boundary (Anomaly & Threat Detection)

Engine 2 (E2) consumes the output of E1 to evaluate detection rules (e.g. port scans, high-traffic volume anomalies, brute force attempts).

### Contractual Rules for E2:
1. **Input Format:** E2 must consume `List<ProcessedNetworkEvent>`.
2. **No Re-Parsing:** E2 must never re-parse raw Zeek `conn.log` files or invoke file I/O for records already processed by E1.
3. **No Thread-Pool Coupling:** E2 is decoupled from E1's worker threads and executor lifecycle. E1 finishes batch processing and returns an immutable list before E2 executes.
4. **Result Immutability:** E2 must not attempt to mutate the returned `List<ProcessedNetworkEvent>` or its constituent objects.
5. **Separation from Persistence (E3):** E2 evaluates detection rules and emits alerts. E2 does not implement database operations directly; persistence of events and alerts is coordinated via E3.

---

## E. E3 and E4 Integration Boundaries

- **Engine 3 (E3: Data Persistence):**
  - E3 receives verified `ProcessedNetworkEvent` lists and `BenchmarkMetrics` from the orchestration layer for database persistence.
  - E1 does not include database drivers, JPA, SQL schemas, or repository layers.
- **Engine 4 (E4: Dashboard & Alerting):**
  - E4 retrieves processed events, active alerts (from E2), and benchmark performance stats (from E3) to render on the UI dashboard.
  - E1 does not include HTTP controllers, REST endpoints, HTML templates, or frontend assets.

---

## F. Benchmark Limitations & Pending Validations

1. **Current Benchmark State:**
   - Benchmarking infrastructure (`BenchmarkRunner` and `BenchmarkMetrics`) is fully verified on existing small real-world datasets and unit test vectors.
   - Single-parse reuse, alternating execution order, median duration, throughput, speedup, and 100% output parity assertions are fully functional.

2. **Pending Performance Targets (Phase 7 Step 2):**
   - **NFR-01 (Speedup $\ge 1.5\times$ on $\ge 500,000$ records with 4 worker threads):** Pending generation and execution of the dedicated 500,000-record dataset.
   - **NFR-02 (Throughput $\ge 10,000$ records/sec):** Pending formal evaluation on the 100k and 500k datasets.

3. **Memory & CPU Metric Limitations:**
   - **Observed Heap Usage (`sequentialObservedHeapBytes`, `multithreadedObservedHeapBytes`):** Sampled via `ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed()` before and after processing. Due to background JVM threads and GC non-determinism, these values represent observed heap occupancy at checkpoints, not exact isolated peak memory.
   - **NFR-04 (Peak Memory $\le 2\text{ GB}$):** Pending formal heap profiling under full 500k-record load.
   - **CPU Load (`sequentialCpuLoad`, `multithreadedCpuLoad`):** Calculated from process CPU time normalized across all logical CPU cores. Returns `null` if the underlying JVM or operating system bean does not support `getProcessCpuTime()`.
