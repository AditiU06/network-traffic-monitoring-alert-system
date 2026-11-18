
package com.kletech.networkmonitor.engine.e1.parser;

import java.io.BufferedWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.ProcessingResult;
import com.kletech.networkmonitor.engine.e1.validation.InputValidator;
import java.io.UncheckedIOException;

@DisplayName("ZeekLogStreamer integration tests")
class ZeekLogStreamerTest {

    // Header uses Zeek's escaped tab separator.
    private static final String STANDARD_CONN_HEADER =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\tresp_pkts\ttunnel_parents\n" +
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tset[string]\n";

    @Test
    @DisplayName("Stream parses records, reports line numbers, ordinals and handles errors")
    void testStreamingIntegration() throws Exception {

        // Build temporary file content.
        StringBuilder sb = new StringBuilder();
        sb.append(STANDARD_CONN_HEADER);

        // Valid record 1 (first data line after header): 19 columns.
        sb.append(
                "1537522822.965530\tCbpiuT1GMBGVeNJKa5\t192.168.1.10\t49152\t10.0.0.1\t443\ttcp\tssl\t12.345678\t1024\t4096\tSF\t-\t-\t0\tShADdfFa\t10\t12\t-\n"
        );

        // Blank line (ignored; does not consume a record ordinal).
        sb.append("\n");

        // Malformed record: invalid source port 99999, but exactly 19 columns.
        sb.append(
                "1537522822.0\tBADUID\t10.0.0.1\t99999\t10.0.0.2\t80\ttcp\tssl\t1.0\t10\t10\tSF\t-\t-\t0\t-\t1\t10\t-\n"
        );

        // Valid record 2: exactly 19 columns.
        sb.append(
                "1537522822.0\tC123\t10.0.0.1\t80\t10.0.0.2\t80\ttcp\t-\t-\t-\t-\tSF\t-\t-\t0\t-\t1\t10\t-\n"
        );

        // Trailing Zeek close directive (not a data record).
        sb.append("#close 2022-11-28-09-10-00\n");

        Path tempFile = Files.createTempFile("zeeklog", ".log");
        Path root = tempFile.getParent();

        try {
            try (BufferedWriter writer = Files.newBufferedWriter(tempFile)) {
                writer.write(sb.toString());
            }

            List<ProcessingResult> results = new ArrayList<>();
            ZeekLogStreamer streamer = new ZeekLogStreamer(root);

            streamer.stream(tempFile, results::add);

            // Three data records: two valid and one malformed.
            assertThat(results).hasSize(3);

            // Eight header directives precede the first data row.
            long headerLines = 8;
            long expectedFirstLine = headerLines + 1;

            // First valid record.
            ProcessingResult r0 = results.get(0);
            assertThat(r0.isSuccess()).isTrue();
            assertThat(r0.lineNumber()).isEqualTo(expectedFirstLine);
            assertThat(r0.recordOrdinal()).isZero();

            NetworkEvent ev0 = r0.event();
            assertThat(ev0.uid()).isEqualTo("CbpiuT1GMBGVeNJKa5");

            // Malformed record: failure is reported, and streaming continues.
            ProcessingResult r1 = results.get(1);
            assertThat(r1.isFailure()).isTrue();
            assertThat(r1.lineNumber()).isEqualTo(expectedFirstLine + 2);
            assertThat(r1.recordOrdinal()).isEqualTo(1L);
            assertThat(r1.errorMessage())
                    .contains("Port number in field 'id.orig_p' out of range");

            // Second valid record after the malformed record.
            ProcessingResult r2 = results.get(2);
            assertThat(r2.isSuccess()).isTrue();
            assertThat(r2.lineNumber()).isEqualTo(expectedFirstLine + 3);
            assertThat(r2.recordOrdinal()).isEqualTo(2L);
            assertThat(r2.event().uid()).isEqualTo("C123");

        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    @Test
    @DisplayName("Throws UncheckedIOException preserving cause when an I/O error occurs during streaming")
    void testThrowsUncheckedIOExceptionOnIoError() throws Exception {
        Path tempFile = Files.createTempFile("io-error-test", ".log");
        Files.deleteIfExists(tempFile); // file does not exist on disk

        InputValidator mockValidator = Mockito.mock(InputValidator.class);
        Mockito.when(mockValidator.validate(tempFile)).thenReturn(tempFile);

        ZeekLogStreamer streamer = new ZeekLogStreamer(mockValidator);
        assertThatThrownBy(() -> streamer.stream(tempFile, r -> {}))
                .isInstanceOf(UncheckedIOException.class)
                .hasMessageContaining("I/O error while reading Zeek log")
                .hasCauseInstanceOf(java.io.IOException.class);
    }

    @Test
    @DisplayName("parseValidEvents returns only valid NetworkEvents and skips malformed records")
    void testParseValidEvents() throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append(STANDARD_CONN_HEADER);
        sb.append("1537522822.965530\tCbpiuT1GMBGVeNJKa5\t192.168.1.10\t49152\t10.0.0.1\t443\ttcp\tssl\t12.345678\t1024\t4096\tSF\t-\t-\t0\tShADdfFa\t10\t12\t-\n");
        sb.append("1537522822.0\tBADUID\t10.0.0.1\t99999\t10.0.0.2\t80\ttcp\tssl\t1.0\t10\t10\tSF\t-\t-\t0\t-\t1\t10\t-\n");
        sb.append("1537522822.0\tC123\t10.0.0.1\t80\t10.0.0.2\t80\ttcp\t-\t-\t-\t-\tSF\t-\t-\t0\t-\t1\t10\t-\n");

        Path tempFile = Files.createTempFile("zeeklog-valid", ".log");
        try {
            Files.writeString(tempFile, sb.toString());
            ZeekLogStreamer streamer = new ZeekLogStreamer(tempFile.getParent());

            List<NetworkEvent> events = streamer.parseValidEvents(tempFile);
            assertThat(events).hasSize(2);
            assertThat(events.get(0).uid()).isEqualTo("CbpiuT1GMBGVeNJKa5");
            assertThat(events.get(1).uid()).isEqualTo("C123");

            // Also test string path overload
            List<NetworkEvent> eventsFromStr = streamer.parseValidEvents(tempFile.toString());
            assertThat(eventsFromStr).hasSize(2);
            assertThat(streamer.getValidator()).isNotNull();
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }
}
