package com.kletech.networkmonitor.engine.e1.benchmark;

import com.kletech.networkmonitor.engine.e1.model.ConnectionState;
import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.TransportProtocol;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("BenchmarkRunner unit tests")
class BenchmarkRunnerTest {

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

    private List<NetworkEvent> createDataset(int count) {
        List<NetworkEvent> list = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            list.add(createEvent(i * 3L + 1L, (long) (i * 10), (long) (i * 20)));
        }
        return list;
    }

    @Test
    @DisplayName("calculateMedian correctly computes median for odd and even size collections")
    void testCalculateMedian() {
        // Odd count: 5 elements
        List<Long> odd = List.of(50L, 10L, 40L, 20L, 30L);
        assertThat(BenchmarkRunner.calculateMedian(odd)).isEqualTo(30L);

        // Even count: 4 elements -> average of 20 and 30 = 25
        List<Long> even = List.of(40L, 10L, 20L, 30L);
        assertThat(BenchmarkRunner.calculateMedian(even)).isEqualTo(25L);

        // Single element
        assertThat(BenchmarkRunner.calculateMedian(List.of(42L))).isEqualTo(42L);

        // Empty and null checks
        assertThatThrownBy(() -> BenchmarkRunner.calculateMedian(Collections.emptyList()))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> BenchmarkRunner.calculateMedian(null))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("calculateThroughput handles normal, zero, and negative durations")
    void testCalculateThroughput() {
        // 1000 records in 100ms = 10,000 records/sec
        double throughput = BenchmarkRunner.calculateThroughput(1000, Duration.ofMillis(100));
        assertThat(throughput).isEqualTo(10_000.0);

        // 0 records
        assertThat(BenchmarkRunner.calculateThroughput(0, Duration.ofSeconds(1))).isZero();

        // 0 or negative duration
        assertThat(BenchmarkRunner.calculateThroughput(100, Duration.ZERO)).isZero();
        assertThat(BenchmarkRunner.calculateThroughput(100, Duration.ofMillis(-5))).isZero();
        assertThat(BenchmarkRunner.calculateThroughput(100, null)).isZero();
    }

    @Test
    @DisplayName("calculateSpeedup computes ratio and returns null for zero, negative, or unavailable durations")
    void testCalculateSpeedup() {
        // 100ms seq / 50ms mt = 2.0x
        assertThat(BenchmarkRunner.calculateSpeedup(Duration.ofMillis(100), Duration.ofMillis(50)))
            .isEqualTo(2.0);

        // 50ms seq / 100ms mt = 0.5x
        assertThat(BenchmarkRunner.calculateSpeedup(Duration.ofMillis(50), Duration.ofMillis(100)))
            .isEqualTo(0.5);

        // Zero multithreaded duration returns null (not artificial 1.0)
        assertThat(BenchmarkRunner.calculateSpeedup(Duration.ofMillis(100), Duration.ZERO))
            .isNull();

        // Zero sequential duration returns null
        assertThat(BenchmarkRunner.calculateSpeedup(Duration.ZERO, Duration.ofMillis(50)))
            .isNull();

        // Null duration returns null
        assertThat(BenchmarkRunner.calculateSpeedup(null, Duration.ofMillis(50))).isNull();
        assertThat(BenchmarkRunner.calculateSpeedup(Duration.ofMillis(100), null)).isNull();
    }

    @Test
    @DisplayName("Rejects empty dataset for performance benchmarking")
    void testRejectsEmptyDataset() {
        BenchmarkRunner runner = new BenchmarkRunner(1, 1);
        assertThatThrownBy(() -> runner.runComputeBenchmark(Collections.emptyList(), 2))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("dataset must not be empty for performance benchmarking");
    }

    @Test
    @DisplayName("Executes benchmark on small dataset with default iterations and verifies output parity")
    void testSmallDatasetBenchmark() {
        List<NetworkEvent> dataset = createDataset(20);
        BenchmarkRunner runner = new BenchmarkRunner();

        BenchmarkMetrics metrics = runner.runComputeBenchmark(dataset, 4);

        assertThat(metrics.recordCount()).isEqualTo(20);
        assertThat(metrics.workerCount()).isEqualTo(4);
        assertThat(metrics.medianSequentialDuration()).isGreaterThanOrEqualTo(Duration.ZERO);
        assertThat(metrics.medianMultithreadedDuration()).isGreaterThanOrEqualTo(Duration.ZERO);
        assertThat(metrics.sequentialThroughput()).isPositive();
        assertThat(metrics.multithreadedThroughput()).isPositive();
        assertThat(metrics.outputParity()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 8, 16})
    @DisplayName("Executes benchmark across various valid worker counts")
    void testVariousWorkerCounts(int workers) {
        List<NetworkEvent> dataset = createDataset(50);
        BenchmarkRunner runner = new BenchmarkRunner(1, 2);

        BenchmarkMetrics metrics = runner.runComputeBenchmark(dataset, workers);

        assertThat(metrics.recordCount()).isEqualTo(50);
        assertThat(metrics.workerCount()).isEqualTo(workers);
        assertThat(metrics.outputParity()).isTrue();
    }

    @Test
    @DisplayName("Rejects worker count outside [1, 16]")
    void testInvalidWorkerCounts() {
        BenchmarkRunner runner = new BenchmarkRunner();
        List<NetworkEvent> dataset = createDataset(10);

        assertThatThrownBy(() -> runner.runComputeBenchmark(dataset, 0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("workerCount must be between 1 and 16");

        assertThatThrownBy(() -> runner.runComputeBenchmark(dataset, 17))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("workerCount must be between 1 and 16");
    }

    @Test
    @DisplayName("Rejects null dataset or dataset with null element")
    void testNullDatasetHandling() {
        BenchmarkRunner runner = new BenchmarkRunner();

        assertThatThrownBy(() -> runner.runComputeBenchmark(null, 2))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("dataset must not be null");

        List<NetworkEvent> datasetWithNull = new ArrayList<>();
        datasetWithNull.add(createEvent(1L, 10L, 10L));
        datasetWithNull.add(null);

        assertThatThrownBy(() -> runner.runComputeBenchmark(datasetWithNull, 2))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("dataset element at index 1 must not be null");
    }

    @Test
    @DisplayName("Rejects invalid iteration constructor arguments")
    void testInvalidConstructorArgs() {
        assertThatThrownBy(() -> new BenchmarkRunner(-1, 5))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("warmupIterations must be non-negative");

        assertThatThrownBy(() -> new BenchmarkRunner(3, 0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("measuredIterations must be at least 1");
    }
}
