package com.kletech.networkmonitor.engine.e1.parser;

import com.kletech.networkmonitor.engine.e1.exception.HeaderParseException;
import com.kletech.networkmonitor.engine.e1.exception.ValidationException;
import com.kletech.networkmonitor.engine.e1.validation.InputValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("ZeekHeaderParser unit tests")
class ZeekHeaderParserTest {

    private static final String STANDARD_CONN_HEADER =
        "#separator \\x09\n" +
        "#set_separator\t,\n" +
        "#empty_field\t(empty)\n" +
        "#unset_field\t-\n" +
        "#path\tconn\n" +
        "#open\t2022-11-28-09-08-17\n" +
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n" +
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\n" +
        "1537522822.965530\tCbpiuT1GMBGVeNJKa5\t0.0.0.0\t68\t255.255.255.255\t67\tudp\tdhcp\t8.322388\t600\t0\tS0\t-\t-\t0\tD\t2\t656\t0\t0\t-\n";

    @TempDir
    Path tempDir;

    private Path permittedRoot;
    private InputValidator validator;
    private ZeekHeaderParser parser;

    @BeforeEach
    void setUp() throws IOException {
        permittedRoot = tempDir.toRealPath().resolve("permitted-data");
        Files.createDirectories(permittedRoot);
        permittedRoot = permittedRoot.toRealPath();
        validator = new InputValidator(permittedRoot);
        parser = new ZeekHeaderParser(validator);
    }

    @Test
    @DisplayName("Should parse valid standard conn.log header")
    void shouldParseValidStandardConnLogHeader() {
        ZeekHeader header = parser.parse(new BufferedReader(new StringReader(STANDARD_CONN_HEADER)));

        assertThat(header).isNotNull();
        assertThat(header.separator()).isEqualTo("\t");
        assertThat(header.setSeparator()).isEqualTo(",");
        assertThat(header.emptyField()).isEqualTo("(empty)");
        assertThat(header.unsetField()).isEqualTo("-");
        assertThat(header.path()).isEqualTo("conn");
        assertThat(header.openTime()).isEqualTo(Instant.parse("2022-11-28T09:08:17Z"));
        assertThat(header.closeTime()).isNull();
        assertThat(header.fieldCount()).isEqualTo(21);

        // Verify key fields
        assertThat(header.hasField("ts")).isTrue();
        assertThat(header.hasField("uid")).isTrue();
        assertThat(header.hasField("id.orig_h")).isTrue();
        assertThat(header.hasField("conn_state")).isTrue();
        assertThat(header.getFieldIndex("ts")).isZero();
        assertThat(header.getFieldIndex("uid")).isEqualTo(1);
        assertThat(header.getFieldType("ts")).isEqualTo("time");
        assertThat(header.getFieldType("conn_state")).isEqualTo("string");
    }

    @Test
    @DisplayName("Should parse header with non-standard field order dynamically")
    void shouldParseHeaderWithDifferentFieldOrder() {
        String reorderedHeader =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#fields\tconn_state\tproto\tid.resp_p\tid.resp_h\tid.orig_p\tid.orig_h\tuid\tts\n" +
            "#types\tstring\tenum\tport\taddr\tport\taddr\tstring\ttime\n" +
            "S0\ttcp\t80\t10.0.0.2\t12345\t10.0.0.1\tC123\t1537522822.0\n";

        ZeekHeader header = parser.parse(new BufferedReader(new StringReader(reorderedHeader)));

        assertThat(header.fieldCount()).isEqualTo(8);
        assertThat(header.getFieldIndex("conn_state")).isZero();
        assertThat(header.getFieldIndex("proto")).isEqualTo(1);
        assertThat(header.getFieldIndex("ts")).isEqualTo(7);
        assertThat(header.getFieldType("conn_state")).isEqualTo("string");
        assertThat(header.getFieldType("ts")).isEqualTo("time");
    }

    @Test
    @DisplayName("Should preserve additional and optional columns without rejecting header")
    void shouldPreserveAdditionalAndOptionalColumns() {
        String extendedHeader =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\tcustom_score\tthreat_label\n" +
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tdouble\tstring\n";

        ZeekHeader header = parser.parse(new BufferedReader(new StringReader(extendedHeader)));

        assertThat(header.fieldCount()).isEqualTo(10);
        assertThat(header.hasField("custom_score")).isTrue();
        assertThat(header.hasField("threat_label")).isTrue();
        assertThat(header.getFieldIndex("custom_score")).isEqualTo(8);
        assertThat(header.getFieldType("custom_score")).isEqualTo("double");
    }

    @Test
    @DisplayName("Should reject header missing required conn.log fields")
    void shouldRejectHeaderMissingRequiredFields() {
        // Missing conn_state
        String missingConnState =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n" +
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\n";

        assertThatThrownBy(() -> parser.parse(new BufferedReader(new StringReader(missingConnState))))
            .isInstanceOf(HeaderParseException.class)
            .hasMessageContaining("Missing required connection log field(s)")
            .hasMessageContaining("conn_state");
    }

    @Test
    @DisplayName("Should reject header when #fields directive is missing")
    void shouldRejectMissingFieldsDirective() {
        String missingFields =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#types\ttime\tstring\n";

        assertThatThrownBy(() -> parser.parse(new BufferedReader(new StringReader(missingFields))))
            .isInstanceOf(HeaderParseException.class)
            .hasMessageContaining("Missing mandatory Zeek header directive: #fields");
    }

    @Test
    @DisplayName("Should reject header when #types directive is missing")
    void shouldRejectMissingTypesDirective() {
        String missingTypes =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n";

        assertThatThrownBy(() -> parser.parse(new BufferedReader(new StringReader(missingTypes))))
            .isInstanceOf(HeaderParseException.class)
            .hasMessageContaining("Missing mandatory Zeek header directive: #types");
    }

    @Test
    @DisplayName("Should reject header when #fields and #types counts do not match")
    void shouldRejectMismatchedFieldsAndTypesCount() {
        String mismatched =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n" +
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\n"; // 7 types for 8 fields

        assertThatThrownBy(() -> parser.parse(new BufferedReader(new StringReader(mismatched))))
            .isInstanceOf(HeaderParseException.class)
            .hasMessageContaining("field count (8) does not match type count (7)");
    }

    @Test
    @DisplayName("Should reject header with duplicate field names in #fields")
    void shouldRejectDuplicateFieldNames() {
        String duplicateFields =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\tts\n" +
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\ttime\n";

        assertThatThrownBy(() -> parser.parse(new BufferedReader(new StringReader(duplicateFields))))
            .isInstanceOf(HeaderParseException.class)
            .hasMessageContaining("Duplicate field name in #fields: 'ts'");
    }

    @Test
    @DisplayName("Should reject header with blank field name in #fields")
    void shouldRejectBlankFieldName() {
        String blankField =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#fields\tts\tuid\t\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n" +
            "#types\ttime\tstring\tstring\taddr\tport\taddr\tport\tenum\tstring\n";

        assertThatThrownBy(() -> parser.parse(new BufferedReader(new StringReader(blankField))))
            .isInstanceOf(HeaderParseException.class)
            .hasMessageContaining("Blank field name in #fields");
    }

    @Test
    @DisplayName("Should reject duplicate directives")
    void shouldRejectDuplicateDirectives() {
        String duplicateSeparator =
            "#separator \\x09\n" +
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n" +
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\n";

        assertThatThrownBy(() -> parser.parse(new BufferedReader(new StringReader(duplicateSeparator))))
            .isInstanceOf(HeaderParseException.class)
            .hasMessageContaining("Duplicate header directive: #separator");
    }

    @Test
    @DisplayName("Should decode escaped tab separator \\x09 and space separator \\x20")
    void shouldDecodeEscapedSeparators() {
        assertThat(ZeekHeaderParser.decodeSeparator("\\x09", 1)).isEqualTo("\t");
        assertThat(ZeekHeaderParser.decodeSeparator("\\x20", 1)).isEqualTo(" ");
        assertThat(ZeekHeaderParser.decodeSeparator("\\t", 1)).isEqualTo("\t");
        assertThat(ZeekHeaderParser.decodeSeparator(",", 1)).isEqualTo(",");
    }

    @Test
    @DisplayName("Should parse header with CRLF line endings cleanly")
    void shouldHandleCrlfLineEndings() {
        String crlfHeader = STANDARD_CONN_HEADER.replace("\n", "\r\n");
        ZeekHeader header = parser.parse(new BufferedReader(new StringReader(crlfHeader)));

        assertThat(header).isNotNull();
        assertThat(header.fieldCount()).isEqualTo(21);
    }

    @Test
    @DisplayName("Should reject invalid timestamp in #open directive")
    void shouldRejectInvalidOpenTimestamp() {
        String invalidTimestamp =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\tnot-a-valid-date-time\n" +
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n" +
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\n";

        assertThatThrownBy(() -> parser.parse(new BufferedReader(new StringReader(invalidTimestamp))))
            .isInstanceOf(HeaderParseException.class)
            .hasMessageContaining("Invalid timestamp format for #open");
    }

    @Test
    @DisplayName("Should parse optional #close directive when present in initial header section")
    void shouldParseOptionalCloseDirectiveWhenInHeader() {
        String headerWithClose =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#close\t2022-11-28-09-08-20\n" +
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n" +
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\n" +
            "1537522822.0\tC123\t10.0.0.1\t12345\t10.0.0.2\t80\ttcp\tS0\n";

        ZeekHeader header = parser.parse(new BufferedReader(new StringReader(headerWithClose)));

        assertThat(header.closeTime()).isNotNull();
        assertThat(header.closeTime()).isEqualTo(Instant.parse("2022-11-28T09:08:20Z"));
        assertThat(header.headerLinesCount()).isEqualTo(9);
    }

    @Test
    @DisplayName("Should leave closeTime as null when #close directive is absent or trailing after data rows")
    void shouldLeaveCloseTimeAsNullWhenAbsentOrTrailing() {
        ZeekHeader header = parser.parse(new BufferedReader(new StringReader(STANDARD_CONN_HEADER)));

        assertThat(header.closeTime()).isNull();
        assertThat(header.headerLinesCount()).isEqualTo(8);
    }

    @Test
    @DisplayName("Should leave BufferedReader positioned at beginning of first data row without consuming it")
    void shouldPreserveFirstDataRowAfterHeaderParsing() throws IOException {
        try (BufferedReader reader = new BufferedReader(new StringReader(STANDARD_CONN_HEADER))) {
            ZeekHeader header = parser.parse(reader);

            // Exactly 8 header directives consumed; data row excluded
            assertThat(header.headerLinesCount()).isEqualTo(8);

            // Next read must yield the exact first data row
            String firstDataRow = reader.readLine();
            assertThat(firstDataRow).isNotNull();
            assertThat(firstDataRow).startsWith("1537522822.965530\tCbpiuT1GMBGVeNJKa5\t0.0.0.0\t68\t255.255.255.255\t67\tudp\tdhcp");
        }
    }

    @Test
    @DisplayName("Should stop at first data row with trailing #close leaving data row unread and closeTime null")
    void shouldStopAtFirstDataRowWithTrailingClose() throws IOException {
        String logWithTrailingClose =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n" +
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\n" +
            "1537522822.0\tC123\t10.0.0.1\t12345\t10.0.0.2\t80\ttcp\tS0\n" +
            "#close\t2022-11-28-09-08-20\n";

        try (BufferedReader reader = new BufferedReader(new StringReader(logWithTrailingClose))) {
            ZeekHeader header = parser.parse(reader);

            // 1. closeTime() remains null because header parsing stops before data rows
            assertThat(header.closeTime()).isNull();

            // 2. headerLinesCount() counts header lines only (8 directives)
            assertThat(header.headerLinesCount()).isEqualTo(8);

            // 3. The first data row remains unread and available to the caller
            String firstDataRow = reader.readLine();
            assertThat(firstDataRow).isNotNull();
            assertThat(firstDataRow).isEqualTo("1537522822.0\tC123\t10.0.0.1\t12345\t10.0.0.2\t80\ttcp\tS0");

            // Subsequent read can read the trailing directive or next rows
            String trailingLine = reader.readLine();
            assertThat(trailingLine).isEqualTo("#close\t2022-11-28-09-08-20");
        }
    }

    @Test
    @DisplayName("Should reject malformed directive missing directive name")
    void shouldRejectMalformedDirectiveMissingName() {
        String malformed =
            "#separator \\x09\n" +
            "# \n" +
            "#set_separator\t,\n";

        assertThatThrownBy(() -> parser.parse(new BufferedReader(new StringReader(malformed))))
            .isInstanceOf(HeaderParseException.class)
            .hasMessageContaining("missing directive name");
    }

    @Test
    @DisplayName("Should reject malformed directive missing value")
    void shouldRejectMalformedDirectiveMissingValue() {
        String malformed =
            "#separator \\x09\n" +
            "#path\n" +
            "#set_separator\t,\n";

        assertThatThrownBy(() -> parser.parse(new BufferedReader(new StringReader(malformed))))
            .isInstanceOf(HeaderParseException.class)
            .hasMessageContaining("missing value for directive");
    }

    @Test
    @DisplayName("Should safely tolerate unknown metadata directives without invalidating header")
    void shouldTolerateUnknownMetadataDirectives() {
        String headerWithUnknown =
            "#separator \\x09\n" +
            "#unknown_directive\tcustom_value\n" +
            "#zeek_version\t5.0.0\n" +
            "#custom_flag\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n" +
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\n" +
            "1537522822.0\tC123\t10.0.0.1\t12345\t10.0.0.2\t80\ttcp\tS0\n";

        ZeekHeader header = parser.parse(new BufferedReader(new StringReader(headerWithUnknown)));

        assertThat(header).isNotNull();
        assertThat(header.path()).isEqualTo("conn");
        assertThat(header.fieldCount()).isEqualTo(8);
        // 8 standard directives + 3 unknown directives = 11 header lines consumed
        assertThat(header.headerLinesCount()).isEqualTo(11);
    }

    @Test
    @DisplayName("Should reject 0-byte empty file")
    void shouldRejectEmptyFile() throws IOException {
        Path emptyFile = permittedRoot.resolve("empty.log");
        Files.createFile(emptyFile);

        assertThatThrownBy(() -> parser.parse(emptyFile))
            .isInstanceOf(HeaderParseException.class)
            .hasMessageContaining("empty or does not contain a Zeek header");
    }

    @Test
    @DisplayName("Should reject file containing non-Zeek text")
    void shouldRejectNonZeekContent() throws IOException {
        Path nonZeek = permittedRoot.resolve("not-zeek.log");
        Files.writeString(nonZeek, "This is not a Zeek log file.\nLine two.\n");

        assertThatThrownBy(() -> parser.parse(nonZeek))
            .isInstanceOf(HeaderParseException.class)
            .hasMessageContaining("empty or does not contain a Zeek header");
    }

    @Test
    @DisplayName("Should accept .txt file with valid Zeek header (extension agnostic)")
    void shouldAcceptTxtFileWithValidHeader() throws IOException {
        Path txtFile = permittedRoot.resolve("conn.txt");
        Files.writeString(txtFile, STANDARD_CONN_HEADER);

        ZeekHeader header = parser.parse(txtFile);
        assertThat(header).isNotNull();
        assertThat(header.path()).isEqualTo("conn");
    }

    @Test
    @DisplayName("Should validate path using InputValidator before opening file")
    void shouldValidatePathUsingInputValidator() {
        // Path traversal escaping root
        assertThatThrownBy(() -> parser.parse("../secret.log"))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("Access denied");

        // Nonexistent file
        assertThatThrownBy(() -> parser.parse("nonexistent.log"))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("does not exist");
    }

    @Test
    @DisplayName("Should parse real benign dataset header successfully")
    void shouldParseRealBenignConnLog() {
        // Points to data/real/benign/conn.log
        Path realRoot = Path.of("data").toAbsolutePath().normalize();
        ZeekHeaderParser realParser = new ZeekHeaderParser(realRoot);

        ZeekHeader header = realParser.parse("real/benign/conn.log");
        assertThat(header).isNotNull();
        assertThat(header.separator()).isEqualTo("\t");
        assertThat(header.path()).isEqualTo("conn");
        assertThat(header.fieldCount()).isEqualTo(21);
        assertThat(header.hasField("ts")).isTrue();
        assertThat(header.hasField("uid")).isTrue();
        assertThat(header.hasField("id.orig_h")).isTrue();
        assertThat(header.hasField("conn_state")).isTrue();
        // #close is trailing in standard Zeek files; header parsing stops before data rows
        assertThat(header.closeTime()).isNull();
        assertThat(header.headerLinesCount()).isEqualTo(8);
    }

    @Test
    @DisplayName("Should parse real malicious dataset header successfully")
    void shouldParseRealMaliciousConnTxt() {
        // Points to data/real/malicious/conn.txt
        Path realRoot = Path.of("data").toAbsolutePath().normalize();
        ZeekHeaderParser realParser = new ZeekHeaderParser(realRoot);

        ZeekHeader header = realParser.parse("real/malicious/conn.txt");
        assertThat(header).isNotNull();
        assertThat(header.separator()).isEqualTo("\t");
        assertThat(header.path()).isEqualTo("conn");
        assertThat(header.fieldCount()).isEqualTo(21);
        assertThat(header.hasField("ts")).isTrue();
        assertThat(header.hasField("uid")).isTrue();
        // #close is trailing in standard Zeek files; header parsing stops before data rows
        assertThat(header.closeTime()).isNull();
        assertThat(header.headerLinesCount()).isEqualTo(8);
    }
}
