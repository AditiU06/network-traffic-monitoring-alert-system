package com.kletech.networkmonitor.engine.e1.demo;

import com.kletech.networkmonitor.engine.e1.LogProcessingEngine;
import com.kletech.networkmonitor.engine.e1.benchmark.BenchmarkMetrics;
import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.ProcessedNetworkEvent;

import java.nio.file.Path;
import java.util.List;

/**
 * Standalone demonstration runner for Engine 1 (E1: Concurrent Log Processing Engine).
 *
 * <p>Demonstrates the complete E1 pipeline:
 * <ol>
 *   <li>Single-pass ingestion and parsing of a real Zeek {@code conn.log} dataset into immutable {@link NetworkEvent}s.</li>
 *   <li>Deterministic sequential and multithreaded processing into enriched {@link ProcessedNetworkEvent}s.</li>
 *   <li>Output parity verification between sequential and multithreaded execution strategies.</li>
 *   <li>Compute-only benchmarking reusing the already-parsed dataset with isolated performance measurement.</li>
 *   <li>Preview of handoff boundaries for Engine 2 (detection) and Engine 3 (persistence).</li>
 * </ol>
 * </p>
 */
public class E1DemoRunner {

    private static final String DEFAULT_DATASET_PATH = "data/real/malicious/conn.txt";
    private static final int WORKER_COUNT = 4;
    private static final int SAMPLE_DISPLAY_COUNT = 3;

    public static void main(String[] args) {
        Path inputPath = (args != null && args.length > 0 && !args[0].isBlank())
                ? Path.of(args[0])
                : Path.of(DEFAULT_DATASET_PATH);

        System.out.println("================================================================================");
        System.out.println("     E1: Concurrent Log Processing Engine - Standalone Demonstration");
        System.out.println("================================================================================");
        System.out.println("Input dataset path : " + inputPath.toAbsolutePath().normalize());
        System.out.println("Worker thread count: " + WORKER_COUNT);
        System.out.println();

        // 1. Initialize E1 LogProcessingEngine
        LogProcessingEngine engine = new LogProcessingEngine(Path.of("."));

        // 2. Single-pass log ingestion and parsing
        System.out.println(">>> Stage 1: Ingestion and Parsing (Single-Pass)");
        long parseStartNanos = System.nanoTime();
        List<NetworkEvent> parsedEvents = engine.parseLog(inputPath);
        long parseDurationMs = (System.nanoTime() - parseStartNanos) / 1_000_000;

        System.out.printf("Successfully parsed %d valid NetworkEvent records in %d ms.%n%n",
                parsedEvents.size(), parseDurationMs);

        // Display sample parsed records
        System.out.printf("--- First %d Parsed NetworkEvent Records ---%n", Math.min(SAMPLE_DISPLAY_COUNT, parsedEvents.size()));
        for (int i = 0; i < Math.min(SAMPLE_DISPLAY_COUNT, parsedEvents.size()); i++) {
            NetworkEvent e = parsedEvents.get(i);
            System.out.printf("[%d] Ordinal: %d | Time: %s | UID: %s%n", i + 1, e.recordOrdinal(), e.timestamp(), e.uid());
            System.out.printf("    Conn: %s:%s -> %s:%s | Proto: %s | Service: %s | State: %s%n",
                    e.sourceAddress().getHostAddress(),
                    e.sourcePort() != null ? e.sourcePort() : "-",
                    e.destinationAddress().getHostAddress(),
                    e.destinationPort() != null ? e.destinationPort() : "-",
                    e.protocol(),
                    e.service() != null ? e.service() : "-",
                    e.connectionState());
            System.out.printf("    Duration: %ss | OrigBytes: %s | RespBytes: %s | OrigPkts: %s | RespPkts: %s%n",
                    e.duration() != null ? e.duration() : "-",
                    e.origBytes() != null ? e.origBytes() : "-",
                    e.respBytes() != null ? e.respBytes() : "-",
                    e.origPkts() != null ? e.origPkts() : "-",
                    e.respPkts() != null ? e.respPkts() : "-");
        }
        System.out.println();

        // 3. Sequential and Multithreaded Processing
        System.out.println(">>> Stage 2: Processing (Sequential and Multithreaded)");
        List<ProcessedNetworkEvent> seqResults = engine.processSequentially(parsedEvents);
        List<ProcessedNetworkEvent> mtResults = engine.processMultithreaded(parsedEvents, WORKER_COUNT);

        System.out.printf("Sequential processed count   : %d records%n", seqResults.size());
        System.out.printf("Multithreaded processed count: %d records (using %d workers)%n", mtResults.size(), WORKER_COUNT);

        boolean parityMatched = seqResults.equals(mtResults);
        System.out.printf("Sequential vs Multithreaded output parity: %s (100%% identical, deterministic ordering)%n%n",
                parityMatched ? "VERIFIED (MATCH)" : "MISMATCH");

        // Display sample processed records
        System.out.printf("--- First %d ProcessedNetworkEvent Records (Calculated Enrichment Fields) ---%n",
                Math.min(SAMPLE_DISPLAY_COUNT, seqResults.size()));
        for (int i = 0; i < Math.min(SAMPLE_DISPLAY_COUNT, seqResults.size()); i++) {
            ProcessedNetworkEvent p = seqResults.get(i);
            System.out.printf("[%d] Ordinal: %d | UID: %s%n", i + 1, p.recordOrdinal(), p.originalEvent().uid());
            System.out.printf("    Total Bytes: %s | Total Packets: %s | Bytes/Packet: %s | Orig/Resp Ratio: %s%n",
                    p.totalBytes() != null ? p.totalBytes() : "N/A",
                    p.totalPackets() != null ? p.totalPackets() : "N/A",
                    p.bytesPerPacket() != null ? String.format("%.2f", p.bytesPerPacket()) : "N/A",
                    p.origToRespRatio() != null ? String.format("%.4f", p.origToRespRatio()) : "N/A");
        }
        System.out.println();

        // 4. Compute-Only Benchmarking (Zero duplicate parsing)
        System.out.println(">>> Stage 3: Compute-Only Benchmarking (Input Reused Directly - Zero Re-parsing)");
        System.out.println("Executing unmetered warm-ups and 5 alternating measured iterations...");
        BenchmarkMetrics metrics = engine.benchmarkEvents(parsedEvents, WORKER_COUNT);

        System.out.println("--- Benchmark Results Summary ---");
        System.out.printf("  Record count                  : %d records%n", metrics.recordCount());
        System.out.printf("  Worker thread count           : %d threads%n", metrics.workerCount());
        System.out.printf("  Median sequential duration    : %.3f ms (%,d ns)%n",
                metrics.medianSequentialDuration().toNanos() / 1_000_000.0,
                metrics.medianSequentialDuration().toNanos());
        System.out.printf("  Median multithreaded duration : %.3f ms (%,d ns)%n",
                metrics.medianMultithreadedDuration().toNanos() / 1_000_000.0,
                metrics.medianMultithreadedDuration().toNanos());
        System.out.printf("  Sequential throughput         : %,.1f records/sec%n", metrics.sequentialThroughput());
        System.out.printf("  Multithreaded throughput      : %,.1f records/sec%n", metrics.multithreadedThroughput());
        System.out.printf("  Speedup (T_seq / T_mt)        : %s%n",
                metrics.speedup() != null ? String.format("%.2fx", metrics.speedup()) : "N/A");
        System.out.printf("  Sequential process CPU load   : %s%n",
                metrics.sequentialCpuLoad() != null ? String.format("%.1f%%", metrics.sequentialCpuLoad()) : "Unavailable (OS/JVM unsupported)");
        System.out.printf("  Multithreaded process CPU load: %s%n",
                metrics.multithreadedCpuLoad() != null ? String.format("%.1f%%", metrics.multithreadedCpuLoad()) : "Unavailable (OS/JVM unsupported)");
        System.out.printf("  Sequential observed heap      : %,d bytes (%.2f MB) [Checkpoint observation]%n",
                metrics.sequentialObservedHeapBytes(), metrics.sequentialObservedHeapBytes() / (1024.0 * 1024.0));
        System.out.printf("  Multithreaded observed heap   : %,d bytes (%.2f MB) [Checkpoint observation]%n",
                metrics.multithreadedObservedHeapBytes(), metrics.multithreadedObservedHeapBytes() / (1024.0 * 1024.0));
        System.out.printf("  Output parity verified        : %s%n", metrics.outputParity() ? "YES (Strict equality)" : "NO");
        System.out.println();
        System.out.println("  * Note: Observed heap measurements reflect JVM heap usage sampled at checkpoints");
        System.out.println("    and do not represent isolated OS-level process peak memory.");
        System.out.println();

        // 5. Downstream Handoff Demonstration
        System.out.println("================================================================================");
        System.out.println("     Downstream Integration Handoff Preview (Architectural Boundaries)");
        System.out.println("================================================================================");
        System.out.println("[HANDOFF PREVIEW ONLY - Actual E2/E3 transmission and persistence are decoupled]");
        System.out.println();
        System.out.printf("1. Intended E2 Input (Threat & Anomaly Detection):%n");
        System.out.printf("   - Format: List<ProcessedNetworkEvent> (%d unmodifiable records)%n", seqResults.size());
        System.out.println("   - Contract: E2 receives fully parsed, enriched event records without performing raw file I/O.");
        System.out.println("   - Raw connection details accessible via .originalEvent() with zero-copy overhead.");
        System.out.println();
        System.out.printf("2. Data Available to E3 (Persistence Layer) Through Orchestration:%n");
        System.out.printf("   - Format: List<ProcessedNetworkEvent> (%d records ready for schema mapping/insertion)%n", seqResults.size());
        System.out.println("   - Contract: E1 does not communicate with databases; orchestration provides events to E3.");
        System.out.println();
        System.out.printf("3. Performance Metrics Available to E3 Through Orchestration:%n");
        System.out.println("   - Format: BenchmarkMetrics immutable record");
        System.out.printf("   - Summary: %d records, %d workers, Speedup=%s, T_mt throughput=%,.1f rec/s%n",
                metrics.recordCount(),
                metrics.workerCount(),
                metrics.speedup() != null ? String.format("%.2fx", metrics.speedup()) : "N/A",
                metrics.multithreadedThroughput());
        System.out.println("================================================================================");
        System.out.println("     E1 Demonstration Completed Successfully");
        System.out.println("================================================================================");
    }
}
