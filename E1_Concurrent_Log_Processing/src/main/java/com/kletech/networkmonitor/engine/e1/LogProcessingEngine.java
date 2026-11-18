package com.kletech.networkmonitor.engine.e1;

import com.kletech.networkmonitor.engine.e1.benchmark.BenchmarkMetrics;
import com.kletech.networkmonitor.engine.e1.benchmark.BenchmarkRunner;
import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.ProcessedNetworkEvent;
import com.kletech.networkmonitor.engine.e1.parser.ZeekLogStreamer;
import com.kletech.networkmonitor.engine.e1.processing.MultithreadedProcessor;
import com.kletech.networkmonitor.engine.e1.processing.SequentialProcessor;
import com.kletech.networkmonitor.engine.e1.validation.InputValidator;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/**
 * Primary coordinator and facade for Engine 1 (E1: Concurrent Log Processing Engine).
 *
 * <p>Orchestrates the three core stages of E1:</p>
 * <ol>
 *   <li><strong>Ingestion and Parsing:</strong> Reads and parses Zeek log files line-by-line via
 *       {@link ZeekLogStreamer}, converting valid records into immutable {@link NetworkEvent}s.</li>
 *   <li><strong>Standard Processing:</strong> Transforms {@link NetworkEvent}s into {@link ProcessedNetworkEvent}s
 *       using either {@link SequentialProcessor} or {@link MultithreadedProcessor} with configurable
 *       worker threads (1 to 16). Normal processing is strictly single-run and independent of benchmarking.</li>
 *   <li><strong>Benchmarking:</strong> Executes compute-only performance benchmarks via {@link BenchmarkRunner}.
 *       When benchmarking a log file, the file is parsed exactly once; the resulting in-memory
 *       {@code List<NetworkEvent>} is passed to {@link BenchmarkRunner#runComputeBenchmark(List, int)}.
 *       File I/O and parsing remain strictly outside the timed benchmark section.</li>
 * </ol>
 *
 * <p><strong>Key Architectural Guarantees:</strong></p>
 * <ul>
 *   <li><strong>Single-Parse Reuse:</strong> Log files are parsed only once. Parsers and I/O are
 *       never invoked inside benchmark measurement loops.</li>
 *   <li><strong>Zero External Dependencies:</strong> Uses standard Java 21 APIs without Spring or
 *       database coupling.</li>
 *   <li><strong>Separation of Concerns:</strong> Normal processing runs without benchmark overhead
 *       (no warmups, no statistical iterations). Benchmarking is explicitly invoked on demand.</li>
 *   <li><strong>Deterministic Output Parity:</strong> Both sequential and multithreaded modes share
 *       the identical record transformation and produce matching outputs.</li>
 * </ul>
 */
public class LogProcessingEngine {

    private final ZeekLogStreamer streamer;
    private final BenchmarkRunner benchmarkRunner;

    /**
     * Constructs a {@code LogProcessingEngine} with the specified log streamer and benchmark runner.
     *
     * @param streamer        log streamer for file ingestion and parsing
     * @param benchmarkRunner compute-only benchmark runner
     * @throws NullPointerException if {@code streamer} or {@code benchmarkRunner} is null
     */
    public LogProcessingEngine(ZeekLogStreamer streamer, BenchmarkRunner benchmarkRunner) {
        this.streamer = Objects.requireNonNull(streamer, "streamer must not be null");
        this.benchmarkRunner = Objects.requireNonNull(benchmarkRunner, "benchmarkRunner must not be null");
    }

    /**
     * Constructs a {@code LogProcessingEngine} with the specified log streamer and default benchmark runner.
     *
     * @param streamer log streamer for file ingestion and parsing
     * @throws NullPointerException if {@code streamer} is null
     */
    public LogProcessingEngine(ZeekLogStreamer streamer) {
        this(streamer, new BenchmarkRunner());
    }

    /**
     * Constructs a {@code LogProcessingEngine} with a log streamer bound to the specified validator
     * and a default benchmark runner.
     *
     * @param validator input validator for path checks
     * @throws NullPointerException if {@code validator} is null
     */
    public LogProcessingEngine(InputValidator validator) {
        this(new ZeekLogStreamer(validator), new BenchmarkRunner());
    }

    /**
     * Constructs a {@code LogProcessingEngine} with a log streamer permitted under the specified root directory
     * and a default benchmark runner.
     *
     * @param permittedRoot root directory under which input files must reside
     * @throws IllegalArgumentException if {@code permittedRoot} is null, does not exist, or is not a directory
     *                                  (delegated to {@link InputValidator})
     */
    public LogProcessingEngine(Path permittedRoot) {
        this(new ZeekLogStreamer(permittedRoot), new BenchmarkRunner());
    }

    /**
     * Constructs a {@code LogProcessingEngine} permitting files in the current working directory.
     */
    public LogProcessingEngine() {
        this(Path.of("."));
    }

    /**
     * Ingests and parses a Zeek log file once, returning all successfully parsed {@link NetworkEvent}s.
     *
     * @param logPath path to the Zeek log file
     * @return unmodifiable list of valid network events in original file order
     * @throws NullPointerException if {@code logPath} is null
     */
    public List<NetworkEvent> parseLog(Path logPath) {
        Objects.requireNonNull(logPath, "logPath must not be null");
        return streamer.parseValidEvents(logPath);
    }

    /**
     * Ingests and parses a Zeek log file once from a raw path string.
     *
     * @param rawPath user-supplied path string
     * @return unmodifiable list of valid network events in original file order
     * @throws NullPointerException if {@code rawPath} is null
     */
    public List<NetworkEvent> parseLog(String rawPath) {
        Objects.requireNonNull(rawPath, "rawPath must not be null");
        return streamer.parseValidEvents(rawPath);
    }

    /**
     * Processes already-parsed events sequentially.
     *
     * @param events immutable list of parsed network events
     * @return unmodifiable list of processed network events in original order
     * @throws NullPointerException if {@code events} is null
     */
    public List<ProcessedNetworkEvent> processSequentially(List<NetworkEvent> events) {
        Objects.requireNonNull(events, "events must not be null");
        SequentialProcessor processor = new SequentialProcessor();
        return processor.process(events);
    }

    /**
     * Parses a Zeek log file once and processes its records sequentially.
     *
     * @param logPath path to the Zeek log file
     * @return unmodifiable list of processed network events in original order
     * @throws NullPointerException if {@code logPath} is null
     */
    public List<ProcessedNetworkEvent> processSequentially(Path logPath) {
        List<NetworkEvent> events = parseLog(logPath);
        return processSequentially(events);
    }

    /**
     * Parses a Zeek log file once from a raw path string and processes its records sequentially.
     *
     * @param rawPath user-supplied path string
     * @return unmodifiable list of processed network events in original order
     * @throws NullPointerException if {@code rawPath} is null
     */
    public List<ProcessedNetworkEvent> processSequentially(String rawPath) {
        List<NetworkEvent> events = parseLog(rawPath);
        return processSequentially(events);
    }

    /**
     * Processes already-parsed events multithreadedly using the specified worker count.
     *
     * @param events      immutable list of parsed network events
     * @param workerCount number of worker threads (1 to 16)
     * @return unmodifiable list of processed network events in original order
     * @throws NullPointerException     if {@code events} is null
     * @throws IllegalArgumentException if {@code workerCount} is outside [1, 16]
     */
    public List<ProcessedNetworkEvent> processMultithreaded(List<NetworkEvent> events, int workerCount) {
        Objects.requireNonNull(events, "events must not be null");
        try (MultithreadedProcessor processor = new MultithreadedProcessor(workerCount)) {
            return processor.process(events);
        }
    }

    /**
     * Parses a Zeek log file once and processes its records multithreadedly.
     *
     * @param logPath     path to the Zeek log file
     * @param workerCount number of worker threads (1 to 16)
     * @return unmodifiable list of processed network events in original order
     * @throws NullPointerException     if {@code logPath} is null
     * @throws IllegalArgumentException if {@code workerCount} is outside [1, 16]
     */
    public List<ProcessedNetworkEvent> processMultithreaded(Path logPath, int workerCount) {
        List<NetworkEvent> events = parseLog(logPath);
        return processMultithreaded(events, workerCount);
    }

    /**
     * Parses a Zeek log file once from a raw path string and processes its records multithreadedly.
     *
     * @param rawPath     user-supplied path string
     * @param workerCount number of worker threads (1 to 16)
     * @return unmodifiable list of processed network events in original order
     * @throws NullPointerException     if {@code rawPath} is null
     * @throws IllegalArgumentException if {@code workerCount} is outside [1, 16]
     */
    public List<ProcessedNetworkEvent> processMultithreaded(String rawPath, int workerCount) {
        List<NetworkEvent> events = parseLog(rawPath);
        return processMultithreaded(events, workerCount);
    }

    /**
     * Configurable processing method that routes already-parsed events to either sequential
     * or multithreaded processing mode.
     *
     * @param events        immutable list of parsed network events
     * @param multithreaded true for multithreaded execution, false for sequential
     * @param workerCount   worker thread count if multithreaded (ignored if sequential)
     * @return unmodifiable list of processed network events in original order
     */
    public List<ProcessedNetworkEvent> process(List<NetworkEvent> events, boolean multithreaded, int workerCount) {
        if (multithreaded) {
            return processMultithreaded(events, workerCount);
        } else {
            return processSequentially(events);
        }
    }

    /**
     * Parses a Zeek log file once and routes records to either sequential or multithreaded processing mode.
     *
     * @param logPath       path to the Zeek log file
     * @param multithreaded true for multithreaded execution, false for sequential
     * @param workerCount   worker thread count if multithreaded (ignored if sequential)
     * @return unmodifiable list of processed network events in original order
     */
    public List<ProcessedNetworkEvent> process(Path logPath, boolean multithreaded, int workerCount) {
        List<NetworkEvent> events = parseLog(logPath);
        return process(events, multithreaded, workerCount);
    }

    /**
     * Executes a compute-only benchmark on already-parsed network events.
     *
     * <p>Excludes file I/O and parsing; runs sequential and multithreaded processing with warmup,
     * alternating iterations, parity verification, and statistical aggregation.</p>
     *
     * @param events      non-empty list of parsed network events
     * @param workerCount worker thread count for multithreaded comparison (1 to 16)
     * @return immutable benchmark measurement results
     * @throws NullPointerException     if {@code events} is null
     * @throws IllegalArgumentException if {@code events} is empty or {@code workerCount} is outside [1, 16]
     */
    public BenchmarkMetrics benchmarkEvents(List<NetworkEvent> events, int workerCount) {
        Objects.requireNonNull(events, "events must not be null");
        return benchmarkRunner.runComputeBenchmark(events, workerCount);
    }

    /**
     * Parses a Zeek log file exactly once and benchmarks sequential vs. multithreaded processing
     * on the resulting parsed events.
     *
     * <p><strong>Key Performance Rule:</strong> The file is parsed once into memory before
     * benchmarking begins. The exact same in-memory {@code List<NetworkEvent>} reference is passed
     * to {@link BenchmarkRunner}, ensuring file I/O and Zeek parsing are entirely excluded from
     * the compute benchmark.</p>
     *
     * @param logPath     path to the Zeek log file
     * @param workerCount worker thread count for multithreaded comparison (1 to 16)
     * @return immutable benchmark measurement results
     * @throws NullPointerException     if {@code logPath} is null
     * @throws IllegalArgumentException if log contains no valid events or {@code workerCount} is outside [1, 16]
     */
    public BenchmarkMetrics benchmarkLog(Path logPath, int workerCount) {
        Objects.requireNonNull(logPath, "logPath must not be null");
        List<NetworkEvent> events = parseLog(logPath);
        return benchmarkRunner.runComputeBenchmark(events, workerCount);
    }

    /**
     * Same as {@link #benchmarkLog(Path, int)} but takes a raw path string.
     *
     * @param rawPath     user-supplied path string
     * @param workerCount worker thread count for multithreaded comparison (1 to 16)
     * @return immutable benchmark measurement results
     * @throws NullPointerException     if {@code rawPath} is null
     * @throws IllegalArgumentException if log contains no valid events or {@code workerCount} is outside [1, 16]
     */
    public BenchmarkMetrics benchmarkLog(String rawPath, int workerCount) {
        Objects.requireNonNull(rawPath, "rawPath must not be null");
        List<NetworkEvent> events = parseLog(rawPath);
        return benchmarkRunner.runComputeBenchmark(events, workerCount);
    }

    /**
     * Returns the underlying {@link ZeekLogStreamer}.
     *
     * @return configured streamer
     */
    public ZeekLogStreamer getStreamer() {
        return streamer;
    }

    /**
     * Returns the underlying {@link BenchmarkRunner}.
     *
     * @return configured benchmark runner
     */
    public BenchmarkRunner getBenchmarkRunner() {
        return benchmarkRunner;
    }
}
