package com.kletech.networkmonitor.engine.e1.processing;

import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.ProcessedNetworkEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Concurrent, chunk-based implementation of {@link NetworkEventProcessor}.
 *
 * <p>Divides a pre-parsed list of {@link NetworkEvent} records into contiguous,
 * non-overlapping slices and processes each chunk using a fixed pool of worker threads.
 * Uses the exact same {@link EventTransformer#transform(NetworkEvent)} logic as
 * {@link SequentialProcessor}, guaranteeing 100% output parity.</p>
 *
 * <p>Features:</p>
 * <ul>
 *   <li>Configurable worker count in range [1, 16] per Gate 1 requirements.</li>
 *   <li>Fixed worker pool lifecycle management with graceful shutdown via {@link AutoCloseable}.</li>
 *   <li>Bounded task submission (at most {@code workerCount} tasks per run) and zero full-list copying.</li>
 *   <li>Preserves each event's original {@code recordOrdinal} without assuming it equals the list index.</li>
 *   <li>Deterministic output assembly maintaining exact input ordering.</li>
 * </ul>
 */
public class MultithreadedProcessor implements NetworkEventProcessor, AutoCloseable {

    /** Minimum permitted worker thread count. */
    public static final int MIN_WORKERS = 1;

    /** Maximum permitted worker thread count. */
    public static final int MAX_WORKERS = 16;

    private final int workerCount;
    private final ExecutorService executor;
    private final boolean managedExecutor;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    /**
     * Constructs a MultithreadedProcessor with default worker count based on available cores (bounded [1, 16]).
     */
    public MultithreadedProcessor() {
        this(Math.clamp(Runtime.getRuntime().availableProcessors(), MIN_WORKERS, MAX_WORKERS));
    }

    /**
     * Constructs a MultithreadedProcessor with a specified worker thread count.
     *
     * @param workerCount number of worker threads (must be between 1 and 16)
     * @throws IllegalArgumentException if workerCount is less than 1 or greater than 16
     */
    public MultithreadedProcessor(int workerCount) {
        if (workerCount < MIN_WORKERS || workerCount > MAX_WORKERS) {
            throw new IllegalArgumentException(
                "workerCount must be between " + MIN_WORKERS + " and " + MAX_WORKERS + ": " + workerCount
            );
        }
        this.workerCount = workerCount;
        this.executor = Executors.newFixedThreadPool(workerCount, new NamedDaemonThreadFactory("e1-worker-"));
        this.managedExecutor = true;
    }

    /**
     * Constructs a MultithreadedProcessor with an externally provided {@link ExecutorService}.
     *
     * @param workerCount worker count (must be between 1 and 16)
     * @param executor    external executor service
     */
    public MultithreadedProcessor(int workerCount, ExecutorService executor) {
        if (workerCount < MIN_WORKERS || workerCount > MAX_WORKERS) {
            throw new IllegalArgumentException(
                "workerCount must be between " + MIN_WORKERS + " and " + MAX_WORKERS + ": " + workerCount
            );
        }
        this.workerCount = workerCount;
        this.executor = Objects.requireNonNull(executor, "executor must not be null");
        this.managedExecutor = false;
    }

    /**
     * Returns the configured worker count.
     *
     * @return worker thread count
     */
    public int getWorkerCount() {
        return workerCount;
    }

    @Override
    public List<ProcessedNetworkEvent> process(List<NetworkEvent> events) {
        Objects.requireNonNull(events, "events must not be null");
        if (closed.get()) {
            throw new IllegalStateException("MultithreadedProcessor is closed");
        }

        int totalSize = events.size();
        if (totalSize == 0) {
            return Collections.emptyList();
        }

        // Validate that no elements are null
        for (int i = 0; i < totalSize; i++) {
            if (events.get(i) == null) {
                throw new NullPointerException("event element at index " + i + " must not be null");
            }
        }

        int numChunks = Math.min(workerCount, totalSize);
        int chunkSize = totalSize / numChunks;
        int remainder = totalSize % numChunks;

        List<Callable<List<ProcessedNetworkEvent>>> tasks = new ArrayList<>(numChunks);
        int startIndex = 0;

        for (int i = 0; i < numChunks; i++) {
            int extra = (i < remainder) ? 1 : 0;
            int endIndex = startIndex + chunkSize + extra;
            List<NetworkEvent> chunkSlice = events.subList(startIndex, endIndex);

            tasks.add(() -> {
                List<ProcessedNetworkEvent> chunkResults = new ArrayList<>(chunkSlice.size());
                for (NetworkEvent ev : chunkSlice) {
                    chunkResults.add(EventTransformer.transform(ev));
                }
                return chunkResults;
            });

            startIndex = endIndex;
        }

        List<Future<List<ProcessedNetworkEvent>>> futures = new ArrayList<>(numChunks);
        boolean success = false;
        try {
            for (Callable<List<ProcessedNetworkEvent>> task : tasks) {
                futures.add(executor.submit(task));
            }

            List<ProcessedNetworkEvent> results = new ArrayList<>(totalSize);
            for (Future<List<ProcessedNetworkEvent>> future : futures) {
                results.addAll(future.get());
            }
            success = true;
            return Collections.unmodifiableList(results);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Multithreaded processing was interrupted", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw new RuntimeException("Error during multithreaded processing", cause);
        } finally {
            if (!success) {
                cancelRemaining(futures);
            }
        }
    }

    private static void cancelRemaining(List<Future<List<ProcessedNetworkEvent>>> futures) {
        for (Future<?> f : futures) {
            f.cancel(true);
        }
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            if (managedExecutor) {
                executor.shutdown();
                try {
                    if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                        executor.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    executor.shutdownNow();
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    private static class NamedDaemonThreadFactory implements ThreadFactory {
        private final String prefix;
        private final AtomicInteger threadNum = new AtomicInteger(1);

        NamedDaemonThreadFactory(String prefix) {
            this.prefix = prefix;
        }

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, prefix + threadNum.getAndIncrement());
            t.setDaemon(true);
            return t;
        }
    }
}
