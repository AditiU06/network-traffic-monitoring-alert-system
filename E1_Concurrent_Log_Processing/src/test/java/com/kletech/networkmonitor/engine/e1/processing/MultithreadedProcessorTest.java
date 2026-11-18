package com.kletech.networkmonitor.engine.e1.processing;

import com.kletech.networkmonitor.engine.e1.model.ConnectionState;
import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.ProcessedNetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.TransportProtocol;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("MultithreadedProcessor unit tests")
class MultithreadedProcessorTest {

    private NetworkEvent createEvent(long ordinal, Long origBytes, Long respBytes) {
        try {
            return new NetworkEvent(
                ordinal,
                Instant.ofEpochSecond(1600000000L + ordinal),
                "Cuid_" + ordinal,
                InetAddress.getByAddress(new byte[]{(byte) 192, (byte) 168, 1, 1}),
                1024,
                InetAddress.getByAddress(new byte[]{10, 0, 0, 1}),
                80,
                TransportProtocol.TCP,
                "http",
                1.0,
                origBytes,
                respBytes,
                ConnectionState.SF,
                "S",
                1L,
                1L
            );
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, -10, 17, 32, 100})
    @DisplayName("Rejects worker count outside [1, 16]")
    void testInvalidWorkerCounts(int workers) {
        assertThatThrownBy(() -> new MultithreadedProcessor(workers))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("workerCount must be between 1 and 16");
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 4, 8, 16})
    @DisplayName("Accepts valid worker counts in [1, 16]")
    void testValidWorkerCounts(int workers) {
        try (MultithreadedProcessor processor = new MultithreadedProcessor(workers)) {
            assertThat(processor.getWorkerCount()).isEqualTo(workers);
        }
    }

    @Test
    @DisplayName("Processes empty list gracefully and returns unmodifiable list")
    void testEmptyList() {
        try (MultithreadedProcessor processor = new MultithreadedProcessor(4)) {
            List<ProcessedNetworkEvent> results = processor.process(Collections.emptyList());
            assertThat(results).isEmpty();
            assertThatThrownBy(() -> results.add(null))
                .isInstanceOf(UnsupportedOperationException.class);
        }
    }

    @Test
    @DisplayName("Returns unmodifiable result list for non-empty input")
    void testResultListIsUnmodifiable() {
        try (MultithreadedProcessor processor = new MultithreadedProcessor(2)) {
            List<NetworkEvent> events = List.of(createEvent(1L, 100L, 200L));
            List<ProcessedNetworkEvent> results = processor.process(events);
            assertThat(results).hasSize(1);
            assertThatThrownBy(() -> results.add(null))
                .isInstanceOf(UnsupportedOperationException.class);
            assertThatThrownBy(() -> results.remove(0))
                .isInstanceOf(UnsupportedOperationException.class);
        }
    }

    @Test
    @DisplayName("Processes list smaller than worker count")
    void testListSmallerThanWorkerCount() {
        try (MultithreadedProcessor processor = new MultithreadedProcessor(8)) {
            List<NetworkEvent> events = List.of(
                createEvent(100L, 50L, 50L),
                createEvent(200L, 100L, 200L)
            );
            List<ProcessedNetworkEvent> results = processor.process(events);
            assertThat(results).hasSize(2);
            assertThat(results.get(0).recordOrdinal()).isEqualTo(100L);
            assertThat(results.get(0).totalBytes()).isEqualTo(100L);
            assertThat(results.get(1).recordOrdinal()).isEqualTo(200L);
            assertThat(results.get(1).totalBytes()).isEqualTo(300L);
        }
    }

    @Test
    @DisplayName("Processes list with more elements than worker count")
    void testListLargerThanWorkerCount() {
        try (MultithreadedProcessor processor = new MultithreadedProcessor(4)) {
            List<NetworkEvent> events = new ArrayList<>();
            for (int i = 0; i < 50; i++) {
                events.add(createEvent(i * 10L, (long) i, (long) (i * 2)));
            }
            List<ProcessedNetworkEvent> results = processor.process(events);
            assertThat(results).hasSize(50);
            for (int i = 0; i < 50; i++) {
                assertThat(results.get(i).recordOrdinal()).isEqualTo(i * 10L);
                assertThat(results.get(i).totalBytes()).isEqualTo((long) (i * 3));
            }
        }
    }

    @Test
    @DisplayName("Propagates ArithmeticException from worker when overflow occurs")
    void testPropagatesWorkerException() {
        try (MultithreadedProcessor processor = new MultithreadedProcessor(4)) {
            List<NetworkEvent> events = List.of(
                createEvent(1L, 10L, 10L),
                createEvent(2L, Long.MAX_VALUE, 1L) // triggers overflow
            );
            assertThatThrownBy(() -> processor.process(events))
                .isInstanceOf(ArithmeticException.class);
        }
    }

    @Test
    @DisplayName("Rejects processing after close()")
    void testRejectAfterClose() {
        MultithreadedProcessor processor = new MultithreadedProcessor(2);
        processor.close();

        assertThatThrownBy(() -> processor.process(List.of(createEvent(1L, 10L, 10L))))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("MultithreadedProcessor is closed");
    }

    @Test
    @DisplayName("Rejects null list input")
    void testNullList() {
        try (MultithreadedProcessor processor = new MultithreadedProcessor(2)) {
            assertThatThrownBy(() -> processor.process(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("events must not be null");
        }
    }

    @Test
    @DisplayName("Rejects list containing null elements")
    void testListWithNullElement() {
        try (MultithreadedProcessor processor = new MultithreadedProcessor(2)) {
            List<NetworkEvent> events = new ArrayList<>();
            events.add(createEvent(1L, 10L, 10L));
            events.add(null);

            assertThatThrownBy(() -> processor.process(events))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("must not be null");
        }
    }

    @Test
    @DisplayName("External executor processor marks processor closed on close() without shutting down external executor")
    void testExternalExecutorCloseDoesNotShutdownExecutor() {
        ExecutorService externalExecutor = Executors.newFixedThreadPool(2);
        try {
            MultithreadedProcessor processor = new MultithreadedProcessor(2, externalExecutor);
            processor.close();

            // 1. Processor is marked closed and rejects subsequent process calls
            assertThatThrownBy(() -> processor.process(List.of(createEvent(1L, 10L, 10L))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("MultithreadedProcessor is closed");

            // 2. External executor is NOT shut down
            assertThat(externalExecutor.isShutdown()).isFalse();
        } finally {
            externalExecutor.shutdownNow();
        }
    }

    @Test
    @DisplayName("Cancels previously submitted futures if task submission fails partway through")
    @SuppressWarnings("unchecked")
    void testTaskSubmissionFailureCancelsAlreadySubmittedFutures() {
        ExecutorService mockExecutor = mock(ExecutorService.class);
        Future<List<ProcessedNetworkEvent>> mockFuture1 = (Future<List<ProcessedNetworkEvent>>) mock(Future.class);

        when(mockExecutor.submit(any(Callable.class)))
            .thenReturn(mockFuture1)
            .thenThrow(new RejectedExecutionException("Executor queue capacity reached"));

        MultithreadedProcessor processor = new MultithreadedProcessor(2, mockExecutor);
        List<NetworkEvent> events = List.of(
            createEvent(1L, 10L, 10L),
            createEvent(2L, 20L, 20L)
        );

        assertThatThrownBy(() -> processor.process(events))
            .isInstanceOf(RejectedExecutionException.class)
            .hasMessageContaining("Executor queue capacity reached");

        // Verify that the already submitted future was cancelled
        verify(mockFuture1).cancel(true);
    }
}
