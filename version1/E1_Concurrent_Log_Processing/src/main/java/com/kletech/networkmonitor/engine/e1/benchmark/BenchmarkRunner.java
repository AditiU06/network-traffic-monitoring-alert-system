package com.kletech.networkmonitor.engine.e1.benchmark;

import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.ProcessedNetworkEvent;
import com.kletech.networkmonitor.engine.e1.processing.MultithreadedProcessor;
import com.kletech.networkmonitor.engine.e1.processing.SequentialProcessor;

import java.lang.management.ManagementFactory;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Executes compute-only performance benchmarks comparing sequential and multithreaded
 * processing on identical in-memory {@link NetworkEvent} datasets.
 *
 * <p><strong>Key Measurement Rules:</strong></p>
 * <ul>
 *   <li><strong>Compute-Only Isolation:</strong> The benchmark accepts already-parsed datasets;
 *       file I/O, Zeek TSV parsing, and database interactions are completely excluded.</li>
 *   <li><strong>Input Parity:</strong> The exact same in-memory {@code List<NetworkEvent>} reference
 *       is supplied to both processors.</li>
 *   <li><strong>Warm-up & Measurement:</strong> Performs 3 unmetered warm-up runs to prime JIT
 *       compilation, followed by 5 timed iterations. Execution order is alternated between
 *       sequential and multithreaded runs across measured iterations to mitigate ordering and
 *       cache-warming bias (without claiming to eliminate all measurement noise or platform bias).</li>
 *   <li><strong>Statistical Stability:</strong> Calculates median execution duration across measured
 *       iterations rather than single-sample times to mitigate GC jitter.</li>
 *   <li><strong>Strict Output Parity:</strong> Output parity is asserted for every measured
 *       sequential/multithreaded pair outside timed processing sections. Any parity mismatch throws
 *       {@link IllegalStateException}.</li>
 *   <li><strong>Process-Wide CPU Utilization:</strong> Samples process CPU time before and after
 *       each run via {@code com.sun.management.OperatingSystemMXBean.getProcessCpuTime()}, normalized
 *       by elapsed wall-clock duration and available processor cores. Returns {@code null} if unsupported.</li>
 *   <li><strong>Observed Heap Usage:</strong> Captures observed heap usage at checkpoints via
 *       {@code MemoryMXBean.getHeapMemoryUsage().getUsed()} without claiming to represent exact isolated peak memory.</li>
 * </ul>
 */
public class BenchmarkRunner {

    /** Default number of warm-up iterations executed prior to measurement. */
    public static final int DEFAULT_WARMUP_ITERATIONS = 3;

    /** Default number of measured iterations used for median calculation. */
    public static final int DEFAULT_MEASURED_ITERATIONS = 5;

    private final int warmupIterations;
    private final int measuredIterations;

    /**
     * Constructs a BenchmarkRunner with default warm-up (3) and measurement (5) iterations.
     */
    public BenchmarkRunner() {
        this(DEFAULT_WARMUP_ITERATIONS, DEFAULT_MEASURED_ITERATIONS);
    }

    /**
     * Constructs a BenchmarkRunner with custom iteration counts.
     *
     * @param warmupIterations   number of unmetered warm-up iterations (>= 0)
     * @param measuredIterations number of measured iterations (>= 1)
     */
    public BenchmarkRunner(int warmupIterations, int measuredIterations) {
        if (warmupIterations < 0) {
            throw new IllegalArgumentException("warmupIterations must be non-negative: " + warmupIterations);
        }
        if (measuredIterations < 1) {
            throw new IllegalArgumentException("measuredIterations must be at least 1: " + measuredIterations);
        }
        this.warmupIterations = warmupIterations;
        this.measuredIterations = measuredIterations;
    }

    /**
     * Returns the configured number of warm-up iterations.
     *
     * @return warm-up iteration count
     */
    public int getWarmupIterations() {
        return warmupIterations;
    }

    /**
     * Returns the configured number of measured iterations.
     *
     * @return measured iteration count
     */
    public int getMeasuredIterations() {
        return measuredIterations;
    }

    /**
     * Executes a compute-only benchmark across sequential and multithreaded processing modes.
     *
     * @param dataset     non-empty pre-parsed immutable network event dataset
     * @param workerCount worker thread count for multithreaded processing (1 to 16)
     * @return immutable benchmark measurement results
     * @throws NullPointerException     if {@code dataset} is null or contains null elements
     * @throws IllegalArgumentException if {@code dataset} is empty or {@code workerCount} is outside [1, 16]
     * @throws IllegalStateException    if output parity between processors fails on any measured iteration
     */
    public BenchmarkMetrics runComputeBenchmark(List<NetworkEvent> dataset, int workerCount) {
        Objects.requireNonNull(dataset, "dataset must not be null");
        if (dataset.isEmpty()) {
            throw new IllegalArgumentException("dataset must not be empty for performance benchmarking");
        }
        if (workerCount < MultithreadedProcessor.MIN_WORKERS || workerCount > MultithreadedProcessor.MAX_WORKERS) {
            throw new IllegalArgumentException(
                "workerCount must be between " + MultithreadedProcessor.MIN_WORKERS
                + " and " + MultithreadedProcessor.MAX_WORKERS + ": " + workerCount
            );
        }

        // Validate that no elements in dataset are null
        for (int i = 0; i < dataset.size(); i++) {
            if (dataset.get(i) == null) {
                throw new NullPointerException("dataset element at index " + i + " must not be null");
            }
        }

        SequentialProcessor sequentialProcessor = new SequentialProcessor();
        try (MultithreadedProcessor multithreadedProcessor = new MultithreadedProcessor(workerCount)) {

            // 1. Warm-up iterations (unmetered, triggers JIT compilation)
            for (int i = 0; i < warmupIterations; i++) {
                sequentialProcessor.process(dataset);
                multithreadedProcessor.process(dataset);
            }

            // 2. Measured iterations with alternating execution order
            List<Long> seqDurationsNanos = new ArrayList<>(measuredIterations);
            List<Long> mtDurationsNanos = new ArrayList<>(measuredIterations);
            List<Double> seqCpuSamples = new ArrayList<>(measuredIterations);
            List<Double> mtCpuSamples = new ArrayList<>(measuredIterations);

            long seqObservedHeapBytes = 0;
            long mtObservedHeapBytes = 0;

            for (int i = 0; i < measuredIterations; i++) {
                boolean runSequentialFirst = (i % 2 == 0);
                IterationResult seqRun;
                IterationResult mtRun;

                if (runSequentialFirst) {
                    seqRun = measureExecution(sequentialProcessor, dataset);
                    mtRun = measureExecution(multithreadedProcessor, dataset);
                } else {
                    mtRun = measureExecution(multithreadedProcessor, dataset);
                    seqRun = measureExecution(sequentialProcessor, dataset);
                }

                // Verify output parity for EVERY measured iteration pair outside timed sections
                if (!Objects.equals(seqRun.output, mtRun.output)) {
                    throw new IllegalStateException(
                        "Output parity verification failed at measured iteration " + i
                        + ": multithreaded processing results do not match sequential results"
                    );
                }

                seqDurationsNanos.add(seqRun.durationNanos);
                if (seqRun.cpuLoadPercent != null) {
                    seqCpuSamples.add(seqRun.cpuLoadPercent);
                }
                seqObservedHeapBytes = Math.max(seqObservedHeapBytes, seqRun.observedHeapBytes);

                mtDurationsNanos.add(mtRun.durationNanos);
                if (mtRun.cpuLoadPercent != null) {
                    mtCpuSamples.add(mtRun.cpuLoadPercent);
                }
                mtObservedHeapBytes = Math.max(mtObservedHeapBytes, mtRun.observedHeapBytes);
            }

            // 3. Calculate Medians, Throughput, and Speedup
            long medianSeqDurationNanos = calculateMedian(seqDurationsNanos);
            long medianMtDurationNanos = calculateMedian(mtDurationsNanos);

            Duration medianSeqDuration = Duration.ofNanos(medianSeqDurationNanos);
            Duration medianMtDuration = Duration.ofNanos(medianMtDurationNanos);

            int recordCount = dataset.size();
            double seqThroughput = calculateThroughput(recordCount, medianSeqDuration);
            double mtThroughput = calculateThroughput(recordCount, medianMtDuration);
            Double speedup = calculateSpeedup(medianSeqDuration, medianMtDuration);

            Double avgSeqCpu = seqCpuSamples.isEmpty()
                ? null
                : seqCpuSamples.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);

            Double avgMtCpu = mtCpuSamples.isEmpty()
                ? null
                : mtCpuSamples.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);

            return new BenchmarkMetrics(
                recordCount,
                workerCount,
                medianSeqDuration,
                medianMtDuration,
                seqThroughput,
                mtThroughput,
                speedup,
                avgSeqCpu,
                avgMtCpu,
                seqObservedHeapBytes,
                mtObservedHeapBytes,
                true // parity strictly verified across all iterations
            );
        }
    }

    private static IterationResult measureExecution(
        com.kletech.networkmonitor.engine.e1.processing.NetworkEventProcessor processor,
        List<NetworkEvent> dataset
    ) {
        long heapBefore = getHeapMemoryUsage();
        long cpuTimeBefore = getProcessCpuTime();

        long startNanos = System.nanoTime();
        List<ProcessedNetworkEvent> output = processor.process(dataset);
        long durationNanos = System.nanoTime() - startNanos;

        long cpuTimeAfter = getProcessCpuTime();
        long heapAfter = getHeapMemoryUsage();

        Double cpuLoad = calculateCpuUtilization(cpuTimeBefore, cpuTimeAfter, durationNanos);
        long observedHeap = Math.max(heapBefore, heapAfter);

        return new IterationResult(durationNanos, cpuLoad, observedHeap, output);
    }

    /**
     * Computes the median value of a non-empty list of {@link Long} numbers.
     *
     * @param values list of long values
     * @return median value
     * @throws IllegalArgumentException if values is null or empty
     */
    public static long calculateMedian(List<Long> values) {
        if (values == null || values.isEmpty()) {
            throw new IllegalArgumentException("values list must not be null or empty");
        }
        List<Long> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        int n = sorted.size();
        if (n % 2 == 1) {
            return sorted.get(n / 2);
        } else {
            return (sorted.get(n / 2 - 1) + sorted.get(n / 2)) / 2;
        }
    }

    /**
     * Calculates processing throughput in records per second.
     *
     * @param recordCount total record count
     * @param duration    elapsed duration
     * @return throughput in records/second (0.0 if duration is 0 or negative)
     */
    public static double calculateThroughput(int recordCount, Duration duration) {
        if (duration == null || duration.isZero() || duration.isNegative() || recordCount <= 0) {
            return 0.0;
        }
        double seconds = duration.toNanos() / 1_000_000_000.0;
        return (double) recordCount / seconds;
    }

    /**
     * Calculates speedup ratio as sequential duration divided by multithreaded duration.
     *
     * @param sequentialDuration    sequential execution duration
     * @param multithreadedDuration multithreaded execution duration
     * @return speedup ratio, or null if duration is zero, negative, or unavailable
     */
    public static Double calculateSpeedup(Duration sequentialDuration, Duration multithreadedDuration) {
        if (sequentialDuration == null || multithreadedDuration == null) {
            return null;
        }
        long seqNanos = sequentialDuration.toNanos();
        long mtNanos = multithreadedDuration.toNanos();
        if (seqNanos <= 0 || mtNanos <= 0) {
            return null;
        }
        return (double) seqNanos / mtNanos;
    }

    private static Double calculateCpuUtilization(long cpuTimeBefore, long cpuTimeAfter, long durationNanos) {
        if (cpuTimeBefore < 0 || cpuTimeAfter < 0 || cpuTimeAfter < cpuTimeBefore || durationNanos <= 0) {
            return null;
        }
        int processors = Runtime.getRuntime().availableProcessors();
        if (processors <= 0) {
            return null;
        }
        long cpuDurationNanos = cpuTimeAfter - cpuTimeBefore;
        double load = ((double) cpuDurationNanos / (durationNanos * (long) processors)) * 100.0;
        if (!Double.isFinite(load) || load < 0.0) {
            return null;
        }
        return Math.min(100.0, load);
    }

    private static long getProcessCpuTime() {
        try {
            java.lang.management.OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
            if (osBean instanceof com.sun.management.OperatingSystemMXBean sunBean) {
                return sunBean.getProcessCpuTime();
            }
        } catch (Exception ignored) {
        }
        return -1L;
    }

    private static long getHeapMemoryUsage() {
        try {
            return ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
        } catch (Exception ignored) {
            return 0L;
        }
    }

    private record IterationResult(
        long durationNanos,
        Double cpuLoadPercent,
        long observedHeapBytes,
        List<ProcessedNetworkEvent> output
    ) {}
}
