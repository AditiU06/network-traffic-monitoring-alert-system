package com.kletech.networkmonitor.engine.e1;

import com.kletech.networkmonitor.engine.e1.benchmark.BenchmarkMetrics;
import com.kletech.networkmonitor.engine.e1.benchmark.BenchmarkRunner;
import com.kletech.networkmonitor.engine.e1.model.ConnectionState;
import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.ProcessedNetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.TransportProtocol;
import com.kletech.networkmonitor.engine.e1.parser.ZeekLogStreamer;
import com.kletech.networkmonitor.engine.e1.validation.InputValidator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.*;

@DisplayName("LogProcessingEngine Integration Tests")
class LogProcessingEngineTest {

    private static final String STANDARD_CONN_HEADER =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\tresp_pkts\ttunnel_parents\n" +
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tset[string]\n";

    private NetworkEvent createSampleEvent(long ordinal, String uid, Long origBytes, Long respBytes) {
        try {
            return new NetworkEvent(
                    ordinal,
                    Instant.parse("2026-03-09T23:00:00Z"),
                    uid,
                    InetAddress.getByAddress(new byte[]{10, 0, 0, 1}),
                    50000,
                    InetAddress.getByAddress(new byte[]{10, 0, 0, 2}),
                    80,
                    TransportProtocol.TCP,
                    "http",
                    1.5,
                    origBytes,
                    respBytes,
                    ConnectionState.SF,
                    "ShADdfFa",
                    10L,
                    20L
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Path createTestLogFile(int validRecords, boolean includeMalformed) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(STANDARD_CONN_HEADER);
        for (int i = 0; i < validRecords; i++) {
            sb.append(String.format(
                    "1537522822.%06d\tUID_%d\t192.168.1.10\t49152\t10.0.0.1\t443\ttcp\tssl\t1.0\t1000\t2000\tSF\t-\t-\t0\tShADdfFa\t10\t20\t-\n",
                    i, i
            ));
        }
        if (includeMalformed) {
            // Malformed record: port out of range
            sb.append("1537522822.0\tBADUID\t10.0.0.1\t99999\t10.0.0.2\t80\ttcp\tssl\t1.0\t10\t10\tSF\t-\t-\t0\t-\t1\t10\t-\n");
        }
        Path tempFile = Files.createTempFile("zeek-engine-test", ".log");
        Files.writeString(tempFile, sb.toString());
        return tempFile;
    }

    @Test
    @DisplayName("Single-Parse Reuse: benchmarkLog parses the file exactly once and passes the exact same dataset to BenchmarkRunner")
    void testSingleParseReuseInBenchmark() throws Exception {
        Path tempFile = createTestLogFile(5, true);
        try {
            ZeekLogStreamer spyStreamer = spy(new ZeekLogStreamer(tempFile.getParent()));
            BenchmarkRunner mockRunner = mock(BenchmarkRunner.class);

            BenchmarkMetrics dummyMetrics = new BenchmarkMetrics(
                    5, 4,
                    java.time.Duration.ofMillis(10), java.time.Duration.ofMillis(5),
                    500.0, 1000.0, 2.0,
                    15.0, 30.0,
                    1024L, 2048L, true
            );
            when(mockRunner.runComputeBenchmark(any(), anyInt())).thenReturn(dummyMetrics);

            LogProcessingEngine engine = new LogProcessingEngine(spyStreamer, mockRunner);

            BenchmarkMetrics result = engine.benchmarkLog(tempFile, 4);

            assertThat(result).isSameAs(dummyMetrics);

            // Verify file streaming/parsing was executed exactly ONCE
            verify(spyStreamer, times(1)).stream(eq(tempFile), any());

            // Capture the dataset passed to BenchmarkRunner
            @SuppressWarnings("unchecked")
            ArgumentCaptor<List<NetworkEvent>> captor = ArgumentCaptor.forClass(List.class);
            verify(mockRunner, times(1)).runComputeBenchmark(captor.capture(), eq(4));

            List<NetworkEvent> passedEvents = captor.getValue();
            assertThat(passedEvents).hasSize(5); // 5 valid records, 1 malformed skipped
            assertThat(passedEvents.get(0).uid()).isEqualTo("UID_0");
            assertThat(passedEvents.get(4).uid()).isEqualTo("UID_4");
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    @Test
    @DisplayName("Normal processing is separate from benchmarking: does not invoke BenchmarkRunner")
    void testNormalProcessingSeparation() throws Exception {
        Path tempFile = createTestLogFile(3, false);
        try {
            ZeekLogStreamer streamer = new ZeekLogStreamer(tempFile.getParent());
            BenchmarkRunner mockRunner = mock(BenchmarkRunner.class);
            LogProcessingEngine engine = new LogProcessingEngine(streamer, mockRunner);

            // Sequential processing
            List<ProcessedNetworkEvent> seqResults = engine.processSequentially(tempFile);
            assertThat(seqResults).hasSize(3);
            assertThatThrownBy(() -> seqResults.add(null))
                .isInstanceOf(UnsupportedOperationException.class);

            // Multithreaded processing
            List<ProcessedNetworkEvent> mtResults = engine.processMultithreaded(tempFile, 2);
            assertThat(mtResults).hasSize(3);
            assertThatThrownBy(() -> mtResults.add(null))
                .isInstanceOf(UnsupportedOperationException.class);

            // Output parity between sequential and multithreaded processing
            assertThat(seqResults).isEqualTo(mtResults);

            // Verify that BenchmarkRunner was NEVER invoked during normal processing
            verifyNoInteractions(mockRunner);
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    @Test
    @DisplayName("Process routing: correctly routes between sequential and multithreaded modes")
    void testProcessRouting() {
        LogProcessingEngine engine = new LogProcessingEngine(new ZeekLogStreamer(new InputValidator(Path.of("."))));

        List<NetworkEvent> events = List.of(
                createSampleEvent(0L, "UID_1", 100L, 200L),
                createSampleEvent(1L, "UID_2", 300L, 400L)
        );

        List<ProcessedNetworkEvent> seqOut = engine.process(events, false, 0);
        List<ProcessedNetworkEvent> mtOut = engine.process(events, true, 2);

        assertThat(seqOut).hasSize(2);
        assertThat(mtOut).hasSize(2);
        assertThat(seqOut).isEqualTo(mtOut);

        // Calculated fields check
        assertThat(seqOut.get(0).totalBytes()).isEqualTo(300L);
        assertThat(seqOut.get(1).totalBytes()).isEqualTo(700L);
    }

    @Test
    @DisplayName("End-to-End benchmarkLog returns real BenchmarkMetrics with strictly verified parity")
    void testBenchmarkLogEndToEnd() throws Exception {
        Path tempFile = createTestLogFile(10, false);
        try {
            // Using small warm-up and measured iterations for quick, focused test
            BenchmarkRunner fastRunner = new BenchmarkRunner(1, 2);
            LogProcessingEngine engine = new LogProcessingEngine(new ZeekLogStreamer(tempFile.getParent()), fastRunner);

            BenchmarkMetrics metrics = engine.benchmarkLog(tempFile, 2);

            assertThat(metrics).isNotNull();
            assertThat(metrics.recordCount()).isEqualTo(10);
            assertThat(metrics.workerCount()).isEqualTo(2);
            assertThat(metrics.outputParity()).isTrue();
            assertThat(metrics.sequentialThroughput()).isPositive();
            assertThat(metrics.multithreadedThroughput()).isPositive();
            assertThat(metrics.medianSequentialDuration().toNanos()).isPositive();
            assertThat(metrics.medianMultithreadedDuration().toNanos()).isPositive();
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    @Test
    @DisplayName("benchmarkEvents benchmarks in-memory events directly")
    void testBenchmarkEventsDirect() {
        BenchmarkRunner fastRunner = new BenchmarkRunner(1, 2);
        LogProcessingEngine engine = new LogProcessingEngine(new ZeekLogStreamer(new InputValidator(Path.of("."))), fastRunner);

        List<NetworkEvent> events = List.of(
                createSampleEvent(0L, "UID_1", 500L, 500L),
                createSampleEvent(1L, "UID_2", 1500L, 500L)
        );

        BenchmarkMetrics metrics = engine.benchmarkEvents(events, 4);

        assertThat(metrics).isNotNull();
        assertThat(metrics.recordCount()).isEqualTo(2);
        assertThat(metrics.workerCount()).isEqualTo(4);
        assertThat(metrics.outputParity()).isTrue();
    }

    @Test
    @DisplayName("Worker count configuration and validation across range [1, 16]")
    void testWorkerCountValidation() {
        LogProcessingEngine engine = new LogProcessingEngine(new ZeekLogStreamer(new InputValidator(Path.of("."))));

        List<NetworkEvent> events = List.of(createSampleEvent(0L, "UID_1", 100L, 100L));

        // Invalid worker counts
        assertThatThrownBy(() -> engine.processMultithreaded(events, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("workerCount");

        assertThatThrownBy(() -> engine.processMultithreaded(events, 17))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("workerCount");

        assertThatThrownBy(() -> engine.benchmarkEvents(events, -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("workerCount");

        assertThatThrownBy(() -> engine.benchmarkEvents(events, 20))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("workerCount");

        // Valid boundary worker counts
        assertThat(engine.processMultithreaded(events, 1)).hasSize(1);
        assertThat(engine.processMultithreaded(events, 16)).hasSize(1);
    }

    @Test
    @DisplayName("Constructors wire dependencies properly and reject null arguments")
    void testConstructorsAndNullChecks() {
        assertThatThrownBy(() -> new LogProcessingEngine(null, new BenchmarkRunner()))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("streamer must not be null");

        assertThatThrownBy(() -> new LogProcessingEngine(new ZeekLogStreamer(Path.of(".")), null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("benchmarkRunner must not be null");

        assertThatThrownBy(() -> new LogProcessingEngine((ZeekLogStreamer) null))
                .isInstanceOf(NullPointerException.class);

        assertThatThrownBy(() -> new LogProcessingEngine((InputValidator) null))
                .isInstanceOf(NullPointerException.class);

        // InputValidator(null) throws IllegalArgumentException per its established contract
        // (verified in InputValidatorTest.shouldRejectNullPermittedRoot)
        assertThatThrownBy(() -> new LogProcessingEngine((Path) null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("permittedRoot must not be null");

        LogProcessingEngine engine = new LogProcessingEngine();
        assertThat(engine.getStreamer()).isNotNull();
        assertThat(engine.getBenchmarkRunner()).isNotNull();

        assertThatThrownBy(() -> engine.parseLog((Path) null))
                .isInstanceOf(NullPointerException.class);

        assertThatThrownBy(() -> engine.processSequentially((List<NetworkEvent>) null))
                .isInstanceOf(NullPointerException.class);

        assertThatThrownBy(() -> engine.processMultithreaded((List<NetworkEvent>) null, 2))
                .isInstanceOf(NullPointerException.class);

        assertThatThrownBy(() -> engine.benchmarkEvents(null, 2))
                .isInstanceOf(NullPointerException.class);

        assertThatThrownBy(() -> engine.benchmarkLog((Path) null, 2))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("Empty dataset handling: benchmark throws IllegalArgumentException")
    void testEmptyDatasetHandling() {
        LogProcessingEngine engine = new LogProcessingEngine();
        List<NetworkEvent> emptyList = List.of();

        assertThatThrownBy(() -> engine.benchmarkEvents(emptyList, 4))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("dataset must not be empty");
    }
}
