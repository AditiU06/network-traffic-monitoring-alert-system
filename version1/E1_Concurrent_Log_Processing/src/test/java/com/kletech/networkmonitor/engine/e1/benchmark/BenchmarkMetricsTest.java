package com.kletech.networkmonitor.engine.e1.benchmark;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("BenchmarkMetrics unit tests")
class BenchmarkMetricsTest {

    @Test
    @DisplayName("Successfully creates BenchmarkMetrics with valid values")
    void testValidConstruction() {
        BenchmarkMetrics metrics = new BenchmarkMetrics(
            1000,
            4,
            Duration.ofMillis(10),
            Duration.ofMillis(5),
            100_000.0,
            200_000.0,
            2.0,
            25.5,
            50.0,
            10_000_000L,
            12_000_000L,
            true
        );

        assertThat(metrics.recordCount()).isEqualTo(1000);
        assertThat(metrics.workerCount()).isEqualTo(4);
        assertThat(metrics.medianSequentialDuration()).isEqualTo(Duration.ofMillis(10));
        assertThat(metrics.medianMultithreadedDuration()).isEqualTo(Duration.ofMillis(5));
        assertThat(metrics.sequentialThroughput()).isEqualTo(100_000.0);
        assertThat(metrics.multithreadedThroughput()).isEqualTo(200_000.0);
        assertThat(metrics.speedup()).isEqualTo(2.0);
        assertThat(metrics.sequentialCpuLoad()).isEqualTo(25.5);
        assertThat(metrics.multithreadedCpuLoad()).isEqualTo(50.0);
        assertThat(metrics.sequentialObservedHeapBytes()).isEqualTo(10_000_000L);
        assertThat(metrics.multithreadedObservedHeapBytes()).isEqualTo(12_000_000L);
        assertThat(metrics.outputParity()).isTrue();
    }

    @Test
    @DisplayName("Allows null speedup and null CPU loads when metrics are unavailable")
    void testNullOptionalMetrics() {
        BenchmarkMetrics metrics = new BenchmarkMetrics(
            500,
            2,
            Duration.ofMillis(20),
            Duration.ofMillis(10),
            25_000.0,
            50_000.0,
            null,
            null,
            null,
            5_000_000L,
            6_000_000L,
            true
        );

        assertThat(metrics.speedup()).isNull();
        assertThat(metrics.sequentialCpuLoad()).isNull();
        assertThat(metrics.multithreadedCpuLoad()).isNull();
    }

    @Test
    @DisplayName("Rejects non-positive recordCount")
    void testNonPositiveRecordCount() {
        assertThatThrownBy(() -> new BenchmarkMetrics(
            0, 4, Duration.ofMillis(10), Duration.ofMillis(5),
            100.0, 200.0, 2.0, null, null, 1000L, 1000L, true
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("recordCount must be positive");

        assertThatThrownBy(() -> new BenchmarkMetrics(
            -1, 4, Duration.ofMillis(10), Duration.ofMillis(5),
            100.0, 200.0, 2.0, null, null, 1000L, 1000L, true
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("recordCount must be positive");
    }

    @Test
    @DisplayName("Rejects worker count outside [1, 16]")
    void testInvalidWorkerCounts() {
        assertThatThrownBy(() -> new BenchmarkMetrics(
            100, 0, Duration.ofMillis(10), Duration.ofMillis(5),
            100.0, 200.0, 2.0, null, null, 1000L, 1000L, true
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("workerCount must be between 1 and 16");

        assertThatThrownBy(() -> new BenchmarkMetrics(
            100, 17, Duration.ofMillis(10), Duration.ofMillis(5),
            100.0, 200.0, 2.0, null, null, 1000L, 1000L, true
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("workerCount must be between 1 and 16");
    }

    @Test
    @DisplayName("Rejects null or negative durations")
    void testInvalidDurations() {
        assertThatThrownBy(() -> new BenchmarkMetrics(
            100, 2, null, Duration.ofMillis(5),
            100.0, 200.0, 2.0, null, null, 1000L, 1000L, true
        )).isInstanceOf(NullPointerException.class);

        assertThatThrownBy(() -> new BenchmarkMetrics(
            100, 2, Duration.ofMillis(-1), Duration.ofMillis(5),
            100.0, 200.0, 2.0, null, null, 1000L, 1000L, true
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("medianSequentialDuration must not be negative");
    }

    @Test
    @DisplayName("Rejects negative or non-finite throughput or speedup")
    void testInvalidThroughputAndSpeedup() {
        assertThatThrownBy(() -> new BenchmarkMetrics(
            100, 2, Duration.ofMillis(10), Duration.ofMillis(5),
            -10.0, 200.0, 2.0, null, null, 1000L, 1000L, true
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("sequentialThroughput must be a finite non-negative number");

        assertThatThrownBy(() -> new BenchmarkMetrics(
            100, 2, Duration.ofMillis(10), Duration.ofMillis(5),
            100.0, Double.NaN, 2.0, null, null, 1000L, 1000L, true
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("multithreadedThroughput must be a finite non-negative number");

        assertThatThrownBy(() -> new BenchmarkMetrics(
            100, 2, Duration.ofMillis(10), Duration.ofMillis(5),
            100.0, 200.0, -1.0, null, null, 1000L, 1000L, true
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("speedup must be a finite non-negative number");
    }

    @Test
    @DisplayName("Rejects invalid CPU load percentage")
    void testInvalidCpuLoad() {
        assertThatThrownBy(() -> new BenchmarkMetrics(
            100, 2, Duration.ofMillis(10), Duration.ofMillis(5),
            100.0, 200.0, 2.0, 105.0, null, 1000L, 1000L, true
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("sequentialCpuLoad must be between 0.0 and 100.0%");

        assertThatThrownBy(() -> new BenchmarkMetrics(
            100, 2, Duration.ofMillis(10), Duration.ofMillis(5),
            100.0, 200.0, 2.0, null, -1.0, 1000L, 1000L, true
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("multithreadedCpuLoad must be between 0.0 and 100.0%");
    }

    @Test
    @DisplayName("Rejects negative observed heap bytes")
    void testNegativeObservedHeap() {
        assertThatThrownBy(() -> new BenchmarkMetrics(
            100, 2, Duration.ofMillis(10), Duration.ofMillis(5),
            100.0, 200.0, 2.0, null, null, -1L, 1000L, true
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("sequentialObservedHeapBytes must be non-negative");
    }

    @Test
    @DisplayName("Rejects false outputParity")
    void testFalseOutputParity() {
        assertThatThrownBy(() -> new BenchmarkMetrics(
            100, 2, Duration.ofMillis(10), Duration.ofMillis(5),
            100.0, 200.0, 2.0, null, null, 1000L, 1000L, false
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("outputParity must be true for a valid benchmark result");
    }
}
