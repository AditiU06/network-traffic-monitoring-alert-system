package com.kletech.networkmonitor.engine.e1.benchmark;

import com.kletech.networkmonitor.engine.e1.processing.MultithreadedProcessor;

import java.time.Duration;
import java.util.Objects;

/**
 * Immutable measurement results from an E1 compute-only processing benchmark run.
 *
 * <p>Encapsulates execution duration, throughput, speedup, process-wide CPU utilization,
 * observed heap usage, and output parity across sequential and multithreaded processing modes.</p>
 *
 * <p><strong>Measurement Characteristics and Limitations:</strong></p>
 * <ul>
 *   <li><strong>Process-Wide CPU Utilization:</strong> Calculated from process CPU time
 *       ({@code getProcessCpuTime()}) before and after each processing run, divided by elapsed
 *       wall-clock time and normalized by available logical processor cores. If the JVM or
 *       host OS does not support process CPU time, or if duration is non-positive, this metric
 *       is reported as {@code null}. This reflects process-wide CPU usage across all JVM threads,
 *       not thread-isolated or CPU-core-pinned execution.</li>
 *   <li><strong>Observed Heap Usage:</strong> Sampled from {@code MemoryMXBean.getHeapMemoryUsage().getUsed()}
 *       at execution checkpoints. Due to background JVM threads, memory allocator behavior, and
 *       non-deterministic garbage collection cycles, this represents observed heap occupancy
 *       rather than an exact isolated peak memory footprint.</li>
 *   <li><strong>Speedup Availability:</strong> Speedup is the ratio of median sequential duration
 *       to median multithreaded duration. If durations are zero or unavailable, speedup is {@code null}.</li>
 * </ul>
 *
 * @param recordCount                  total number of NetworkEvent records processed
 * @param workerCount                  number of worker threads configured for multithreaded processing
 * @param medianSequentialDuration     median sequential execution duration across measured iterations
 * @param medianMultithreadedDuration  median multithreaded execution duration across measured iterations
 * @param sequentialThroughput         sequential processing throughput in records per second
 * @param multithreadedThroughput      multithreaded processing throughput in records per second
 * @param speedup                      speedup ratio (sequential / multithreaded); null if unavailable
 * @param sequentialCpuLoad            sequential process-wide CPU utilization percentage (0.0 to 100.0); null if unavailable
 * @param multithreadedCpuLoad         multithreaded process-wide CPU utilization percentage (0.0 to 100.0); null if unavailable
 * @param sequentialObservedHeapBytes  observed JVM heap usage during sequential processing in bytes
 * @param multithreadedObservedHeapBytes observed JVM heap usage during multithreaded processing in bytes
 * @param outputParity                 true if sequential and multithreaded outputs are 100% equivalent
 */
public record BenchmarkMetrics(
    int recordCount,
    int workerCount,
    Duration medianSequentialDuration,
    Duration medianMultithreadedDuration,
    double sequentialThroughput,
    double multithreadedThroughput,
    Double speedup,
    Double sequentialCpuLoad,
    Double multithreadedCpuLoad,
    long sequentialObservedHeapBytes,
    long multithreadedObservedHeapBytes,
    boolean outputParity
) {
    /**
     * Compact constructor validating metric constraints and bounds.
     */
    public BenchmarkMetrics {
        if (recordCount <= 0) {
            throw new IllegalArgumentException("recordCount must be positive for a benchmark run: " + recordCount);
        }
        if (workerCount < MultithreadedProcessor.MIN_WORKERS || workerCount > MultithreadedProcessor.MAX_WORKERS) {
            throw new IllegalArgumentException(
                "workerCount must be between " + MultithreadedProcessor.MIN_WORKERS
                + " and " + MultithreadedProcessor.MAX_WORKERS + ": " + workerCount
            );
        }
        Objects.requireNonNull(medianSequentialDuration, "medianSequentialDuration must not be null");
        if (medianSequentialDuration.isNegative()) {
            throw new IllegalArgumentException("medianSequentialDuration must not be negative");
        }
        Objects.requireNonNull(medianMultithreadedDuration, "medianMultithreadedDuration must not be null");
        if (medianMultithreadedDuration.isNegative()) {
            throw new IllegalArgumentException("medianMultithreadedDuration must not be negative");
        }
        if (!Double.isFinite(sequentialThroughput) || sequentialThroughput < 0.0) {
            throw new IllegalArgumentException("sequentialThroughput must be a finite non-negative number: " + sequentialThroughput);
        }
        if (!Double.isFinite(multithreadedThroughput) || multithreadedThroughput < 0.0) {
            throw new IllegalArgumentException("multithreadedThroughput must be a finite non-negative number: " + multithreadedThroughput);
        }
        if (speedup != null) {
            if (!Double.isFinite(speedup) || speedup < 0.0) {
                throw new IllegalArgumentException("speedup must be a finite non-negative number: " + speedup);
            }
        }
        if (sequentialCpuLoad != null) {
            if (!Double.isFinite(sequentialCpuLoad) || sequentialCpuLoad < 0.0 || sequentialCpuLoad > 100.0) {
                throw new IllegalArgumentException("sequentialCpuLoad must be between 0.0 and 100.0%: " + sequentialCpuLoad);
            }
        }
        if (multithreadedCpuLoad != null) {
            if (!Double.isFinite(multithreadedCpuLoad) || multithreadedCpuLoad < 0.0 || multithreadedCpuLoad > 100.0) {
                throw new IllegalArgumentException("multithreadedCpuLoad must be between 0.0 and 100.0%: " + multithreadedCpuLoad);
            }
        }
        if (sequentialObservedHeapBytes < 0) {
            throw new IllegalArgumentException("sequentialObservedHeapBytes must be non-negative: " + sequentialObservedHeapBytes);
        }
        if (multithreadedObservedHeapBytes < 0) {
            throw new IllegalArgumentException("multithreadedObservedHeapBytes must be non-negative: " + multithreadedObservedHeapBytes);
        }
        if (!outputParity) {
            throw new IllegalArgumentException("outputParity must be true for a valid benchmark result");
        }
    }
}
