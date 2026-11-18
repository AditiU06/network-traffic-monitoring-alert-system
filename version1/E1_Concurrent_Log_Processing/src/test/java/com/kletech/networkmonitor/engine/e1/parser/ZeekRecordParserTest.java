package com.kletech.networkmonitor.engine.e1.parser;

import com.kletech.networkmonitor.engine.e1.exception.RecordParseException;
import com.kletech.networkmonitor.engine.e1.model.ConnectionState;
import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.TransportProtocol;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.BufferedReader;
import java.io.StringReader;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("ZeekRecordParser unit tests")
class ZeekRecordParserTest {

    private static final String STANDARD_CONN_HEADER =
        "#separator \\x09\n" +
        "#set_separator\t,\n" +
        "#empty_field\t(empty)\n" +
        "#unset_field\t-\n" +
        "#path\tconn\n" +
        "#open\t2022-11-28-09-08-17\n" +
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n" +
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\n";

    private ZeekHeader standardHeader;
    private ZeekRecordParser parser;

    @BeforeEach
    void setUp() {
        ZeekHeaderParser headerParser = new ZeekHeaderParser(java.nio.file.Path.of("."));
        standardHeader = headerParser.parse(new BufferedReader(new StringReader(STANDARD_CONN_HEADER)));
        parser = new ZeekRecordParser();
    }

    @Test
    @DisplayName("Should parse valid standard TCP record with all fields populated")
    void shouldParseValidTcpRecord() {
        String row = "1537522822.965530\tCbpiuT1GMBGVeNJKa5\t192.168.1.10\t49152\t10.0.0.1\t443\ttcp\tssl\t12.345678\t1024\t4096\tSF\t-\t-\t0\tShADdfFa\t10\t1424\t12\t4576\t-";

        NetworkEvent event = parser.parse(standardHeader, row, 0L);

        assertThat(event).isNotNull();
        assertThat(event.recordOrdinal()).isZero();
        assertThat(event.timestamp()).isEqualTo(Instant.ofEpochSecond(1537522822L, 965530000L));
        assertThat(event.uid()).isEqualTo("CbpiuT1GMBGVeNJKa5");
        assertThat(event.sourceAddress().getHostAddress()).isEqualTo("192.168.1.10");
        assertThat(event.sourcePort()).isEqualTo(49152);
        assertThat(event.destinationAddress().getHostAddress()).isEqualTo("10.0.0.1");
        assertThat(event.destinationPort()).isEqualTo(443);
        assertThat(event.protocol()).isEqualTo(TransportProtocol.TCP);
        assertThat(event.service()).isEqualTo("ssl");
        assertThat(event.duration()).isEqualTo(12.345678);
        assertThat(event.origBytes()).isEqualTo(1024L);
        assertThat(event.respBytes()).isEqualTo(4096L);
        assertThat(event.connectionState()).isEqualTo(ConnectionState.SF);
        assertThat(event.history()).isEqualTo("ShADdfFa");
        assertThat(event.origPkts()).isEqualTo(10L);
        assertThat(event.respPkts()).isEqualTo(12L);
    }

    @Test
    @DisplayName("Should parse valid standard UDP record")
    void shouldParseValidUdpRecord() {
        String row = "1537522897.732295\tC179s7RaGHGnXRX9f\t192.168.2.1\t5353\t224.0.0.251\t5353\tudp\tdns\t-\t-\t-\tS0\t-\t-\t0\tD\t1\t391\t0\t0\t-";

        NetworkEvent event = parser.parse(standardHeader, row, 1L);

        assertThat(event.recordOrdinal()).isEqualTo(1L);
        assertThat(event.protocol()).isEqualTo(TransportProtocol.UDP);
        assertThat(event.service()).isEqualTo("dns");
        assertThat(event.duration()).isNull();
        assertThat(event.origBytes()).isNull();
        assertThat(event.respBytes()).isNull();
        assertThat(event.connectionState()).isEqualTo(ConnectionState.S0);
        assertThat(event.history()).isEqualTo("D");
        assertThat(event.origPkts()).isEqualTo(1L);
        assertThat(event.respPkts()).isZero();
    }

    @Test
    @DisplayName("Should parse valid ICMP record with nullable or unset ports")
    void shouldParseValidIcmpRecordWithNullablePorts() {
        String rowUnsetPorts = "1537542573.267978\tCATZlA1hmUCqLTYUfa\t10.0.0.5\t-\t10.0.0.1\t-\ticmp\t-\t-\t-\t-\tOTH\t-\t-\t0\t-\t1\t76\t0\t0\t-";

        NetworkEvent event = parser.parse(standardHeader, rowUnsetPorts, 2L);

        assertThat(event.protocol()).isEqualTo(TransportProtocol.ICMP);
        assertThat(event.sourcePort()).isNull();
        assertThat(event.destinationPort()).isNull();
        assertThat(event.connectionState()).isEqualTo(ConnectionState.OTH);
    }

    @Test
    @DisplayName("Should parse ICMP record containing type and code in port columns")
    void shouldParseIcmpRecordWithTypeAndCodePorts() {
        // Zeek records ICMP type in id.orig_p and code in id.resp_p (e.g. 143 and 0)
        String row = "1537542573.267978\tCATZlA1hmUCqLTYUfa\t10.0.0.5\t143\t10.0.0.1\t0\ticmp\t-\t-\t-\t-\tOTH\t-\t-\t0\t-\t1\t76\t0\t0\t-";

        NetworkEvent event = parser.parse(standardHeader, row, 3L);

        assertThat(event.protocol()).isEqualTo(TransportProtocol.ICMP);
        assertThat(event.sourcePort()).isEqualTo(143);
        assertThat(event.destinationPort()).isZero();
    }

    @Test
    @DisplayName("Should parse IPv4 and IPv6 literals without DNS resolution")
    void shouldParseIpv4AndIpv6Literals() {
        String ipv6Row = "1537522897.732374\tCdW4Ek3cvnHC5jdh2f\tfe80::80e6:50ff:fe12:1464\t5353\tff02::fb\t5353\tudp\tdns\t-\t-\t-\tS0\t-\t-\t0\tD\t1\t411\t0\t0\t-";

        NetworkEvent event = parser.parse(standardHeader, ipv6Row, 4L);

        assertThat(event.sourceAddress()).isInstanceOf(Inet6Address.class);
        assertThat(event.sourceAddress().getHostAddress()).contains("fe80");
        assertThat(event.destinationAddress()).isInstanceOf(Inet6Address.class);
        assertThat(event.destinationAddress().getHostAddress()).contains("ff02");

        String ipv4Row = "1537522822.0\tC123\t127.0.0.1\t80\t10.0.0.1\t80\ttcp\t-\t-\t-\t-\tSF\t-\t-\t0\t-\t1\t10\t1\t10\t-";
        NetworkEvent ipv4Event = parser.parse(standardHeader, ipv4Row, 5L);
        assertThat(ipv4Event.sourceAddress()).isInstanceOf(Inet4Address.class);
        assertThat(ipv4Event.sourceAddress().getHostAddress()).isEqualTo("127.0.0.1");
    }

    @Test
    @DisplayName("Should parse dynamically reordered columns without hardcoding index")
    void shouldParseDynamicallyReorderedColumns() {
        String reorderedHeaderStr =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#fields\tconn_state\tproto\tid.resp_p\tid.resp_h\tid.orig_p\tid.orig_h\tuid\tts\n" +
            "#types\tstring\tenum\tport\taddr\tport\taddr\tstring\ttime\n";

        ZeekHeaderParser headerParser = new ZeekHeaderParser(java.nio.file.Path.of("."));
        ZeekHeader reorderedHeader = headerParser.parse(new BufferedReader(new StringReader(reorderedHeaderStr)));

        String row = "S0\ttcp\t80\t10.0.0.2\t12345\t10.0.0.1\tC_REORDER\t1537522822.123456";

        NetworkEvent event = parser.parse(reorderedHeader, row, 0L);

        assertThat(event.connectionState()).isEqualTo(ConnectionState.S0);
        assertThat(event.protocol()).isEqualTo(TransportProtocol.TCP);
        assertThat(event.destinationPort()).isEqualTo(80);
        assertThat(event.destinationAddress().getHostAddress()).isEqualTo("10.0.0.2");
        assertThat(event.sourcePort()).isEqualTo(12345);
        assertThat(event.sourceAddress().getHostAddress()).isEqualTo("10.0.0.1");
        assertThat(event.uid()).isEqualTo("C_REORDER");
        assertThat(event.timestamp()).isEqualTo(Instant.ofEpochSecond(1537522822L, 123456000L));
    }

    @Test
    @DisplayName("Should assign null to optional fields absent from header schema")
    void shouldAssignNullToOptionalFieldsAbsentFromHeader() {
        // Minimal header containing only the 8 mandatory fields
        String minimalHeaderStr =
            "#separator \\x09\n" +
            "#set_separator\t,\n" +
            "#empty_field\t(empty)\n" +
            "#unset_field\t-\n" +
            "#path\tconn\n" +
            "#open\t2022-11-28-09-08-17\n" +
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n" +
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\n";

        ZeekHeaderParser headerParser = new ZeekHeaderParser(java.nio.file.Path.of("."));
        ZeekHeader minimalHeader = headerParser.parse(new BufferedReader(new StringReader(minimalHeaderStr)));

        String row = "1537522822.0\tC_MINIMAL\t10.0.0.1\t12345\t10.0.0.2\t80\ttcp\tSF";

        NetworkEvent event = parser.parse(minimalHeader, row, 0L);

        assertThat(event.uid()).isEqualTo("C_MINIMAL");
        assertThat(event.service()).isNull();
        assertThat(event.duration()).isNull();
        assertThat(event.origBytes()).isNull();
        assertThat(event.respBytes()).isNull();
        assertThat(event.history()).isNull();
        assertThat(event.origPkts()).isNull();
        assertThat(event.respPkts()).isNull();
    }

    @Test
    @DisplayName("Should accurately parse decimal epoch timestamps without floating-point precision loss")
    void shouldAccuratelyParseDecimalEpochTimestamps() {
        // 6-digit microseconds
        Instant t1 = ZeekRecordParser.parseEpochTimestamp("1537522822.965530");
        assertThat(t1.getEpochSecond()).isEqualTo(1537522822L);
        assertThat(t1.getNano()).isEqualTo(965530000);

        // 3-digit milliseconds
        Instant t2 = ZeekRecordParser.parseEpochTimestamp("1537522822.123");
        assertThat(t2.getEpochSecond()).isEqualTo(1537522822L);
        assertThat(t2.getNano()).isEqualTo(123000000);

        // 9-digit nanoseconds
        Instant t3 = ZeekRecordParser.parseEpochTimestamp("1537522822.123456789");
        assertThat(t3.getEpochSecond()).isEqualTo(1537522822L);
        assertThat(t3.getNano()).isEqualTo(123456789);

        // Whole integer seconds without decimal point
        Instant t4 = ZeekRecordParser.parseEpochTimestamp("1537522822");
        assertThat(t4.getEpochSecond()).isEqualTo(1537522822L);
        assertThat(t4.getNano()).isZero();
    }

    @ParameterizedTest(name = "Invalid timestamp: {0}")
    @ValueSource(strings = {"", "   ", "abc", "-1537522822.0", "1537522822.", ".965530", "1537522822..123", "1537522822.abc"})
    @DisplayName("Should reject invalid timestamp formats")
    void shouldRejectInvalidTimestampFormats(String invalidTs) {
        assertThatThrownBy(() -> ZeekRecordParser.parseEpochTimestamp(invalidTs))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest(name = "Invalid IP literal: {0}")
    @ValueSource(strings = {
        "example.com", "not_an_ip", "192.168.1.300", "192.168.1", "192.168.1.1.1",
        "192.168.01.1", "fe80:::1", "1:2:3:4:5:6:7:8:9", "zz::1", "::ffff:300.1.1.1"
    })
    @DisplayName("Should reject invalid IP literals without issuing DNS queries")
    void shouldRejectInvalidIpLiterals(String invalidIp) {
        assertThatThrownBy(() -> ZeekRecordParser.parseIpLiteral(invalidIp, "id.orig_h", 0L))
            .isInstanceOf(RecordParseException.class)
            .hasMessageContaining("Invalid or malformed IP address in field 'id.orig_h'");
    }

    @Test
    @DisplayName("Should reject invalid port numbers (non-numeric, negative, or > 65535)")
    void shouldRejectInvalidPorts() {
        String nonNumericPort = "1537522822.0\tC123\t10.0.0.1\tabc\t10.0.0.2\t80\ttcp\tssl\t1.0\t10\t10\tSF\t-\t-\t0\t-\t1\t10\t1\t10\t-";
        assertThatThrownBy(() -> parser.parse(standardHeader, nonNumericPort, 0L))
            .isInstanceOf(RecordParseException.class)
            .hasMessageContaining("Invalid port number in field 'id.orig_p'");

        String outOfRangePort = "1537522822.0\tC123\t10.0.0.1\t65536\t10.0.0.2\t80\ttcp\tssl\t1.0\t10\t10\tSF\t-\t-\t0\t-\t1\t10\t1\t10\t-";
        assertThatThrownBy(() -> parser.parse(standardHeader, outOfRangePort, 0L))
            .isInstanceOf(RecordParseException.class)
            .hasMessageContaining("Port number in field 'id.orig_p' out of range");

        String negativePort = "1537522822.0\tC123\t10.0.0.1\t-1\t10.0.0.2\t80\ttcp\tssl\t1.0\t10\t10\tSF\t-\t-\t0\t-\t1\t10\t1\t10\t-";
        assertThatThrownBy(() -> parser.parse(standardHeader, negativePort, 0L))
            .isInstanceOf(RecordParseException.class)
            .hasMessageContaining("Port number in field 'id.orig_p' out of range");
    }

    @Test
    @DisplayName("Should reject invalid duration and counter values")
    void shouldRejectInvalidDurationAndCounters() {
        String negativeDuration = "1537522822.0\tC123\t10.0.0.1\t80\t10.0.0.2\t80\ttcp\tssl\t-1.5\t10\t10\tSF\t-\t-\t0\t-\t1\t10\t1\t10\t-";
        assertThatThrownBy(() -> parser.parse(standardHeader, negativeDuration, 0L))
            .isInstanceOf(RecordParseException.class)
            .hasMessageContaining("Duration in field 'duration' must be a finite, non-negative number");

        String negativeBytes = "1537522822.0\tC123\t10.0.0.1\t80\t10.0.0.2\t80\ttcp\tssl\t1.0\t-500\t10\tSF\t-\t-\t0\t-\t1\t10\t1\t10\t-";
        assertThatThrownBy(() -> parser.parse(standardHeader, negativeBytes, 0L))
            .isInstanceOf(RecordParseException.class)
            .hasMessageContaining("Count value in field 'orig_bytes' must not be negative");

        String nonNumericPackets = "1537522822.0\tC123\t10.0.0.1\t80\t10.0.0.2\t80\ttcp\tssl\t1.0\t10\t10\tSF\t-\t-\t0\t-\tinvalid\t10\t1\t10\t-";
        assertThatThrownBy(() -> parser.parse(standardHeader, nonNumericPackets, 0L))
            .isInstanceOf(RecordParseException.class)
            .hasMessageContaining("Invalid count format in field 'orig_pkts'");
    }

    @Test
    @DisplayName("Should reject unknown protocol")
    void shouldRejectUnknownProtocol() {
        String unknownProto = "1537522822.0\tC123\t10.0.0.1\t80\t10.0.0.2\t80\tsctp\tssl\t1.0\t10\t10\tSF\t-\t-\t0\t-\t1\t10\t1\t10\t-";
        assertThatThrownBy(() -> parser.parse(standardHeader, unknownProto, 0L))
            .isInstanceOf(RecordParseException.class)
            .hasMessageContaining("Unsupported or unknown transport protocol in field 'proto'");
    }

    @Test
    @DisplayName("Should reject unknown connection state")
    void shouldRejectUnknownConnectionState() {
        String unknownState = "1537522822.0\tC123\t10.0.0.1\t80\t10.0.0.2\t80\ttcp\tssl\t1.0\t10\t10\tESTABLISHED\t-\t-\t0\t-\t1\t10\t1\t10\t-";
        assertThatThrownBy(() -> parser.parse(standardHeader, unknownState, 0L))
            .isInstanceOf(RecordParseException.class)
            .hasMessageContaining("Unsupported or unknown connection state in field 'conn_state'");
    }

    @Test
    @DisplayName("Should reject row with too few or too many columns")
    void shouldRejectMismatchedColumnCount() {
        // 20 columns instead of 21
        String tooFew = "1537522822.0\tC123\t10.0.0.1\t80\t10.0.0.2\t80\ttcp\tssl\t1.0\t10\t10\tSF\t-\t-\t0\t-\t1\t10\t1\t10";
        assertThatThrownBy(() -> parser.parse(standardHeader, tooFew, 0L))
            .isInstanceOf(RecordParseException.class)
            .hasMessageContaining("token count (20) does not match header field count (21)");

        // 22 columns instead of 21
        String tooMany = tooFew + "\tEXTRA1\tEXTRA2";
        assertThatThrownBy(() -> parser.parse(standardHeader, tooMany, 0L))
            .isInstanceOf(RecordParseException.class)
            .hasMessageContaining("token count (22) does not match header field count (21)");
    }

    @Test
    @DisplayName("Should preserve trailing empty columns without losing column count")
    void shouldPreserveTrailingEmptyColumns() {
        // Last column (tunnel_parents) is empty string
        String rowWithTrailingEmpty = "1537522822.0\tC123\t10.0.0.1\t80\t10.0.0.2\t80\ttcp\tssl\t1.0\t10\t10\tSF\t-\t-\t0\t-\t1\t10\t1\t10\t";

        NetworkEvent event = parser.parse(standardHeader, rowWithTrailingEmpty, 0L);
        assertThat(event).isNotNull();
        assertThat(event.uid()).isEqualTo("C123");
    }

    @Test
    @DisplayName("Should reject null, blank, and comment rows")
    void shouldRejectNullBlankAndCommentRows() {
        assertThatThrownBy(() -> parser.parse(standardHeader, null, 0L))
            .isInstanceOf(RecordParseException.class)
            .hasMessageContaining("Raw data row must not be null");

        assertThatThrownBy(() -> parser.parse(standardHeader, "   ", 0L))
            .isInstanceOf(RecordParseException.class)
            .hasMessageContaining("Raw data row must not be blank");

        assertThatThrownBy(() -> parser.parse(standardHeader, "#close 2022-11-28-09-08-20", 0L))
            .isInstanceOf(RecordParseException.class)
            .hasMessageContaining("Comment line cannot be parsed as a data record");
    }

    @Test
    @DisplayName("Should reject negative record ordinal")
    void shouldRejectNegativeRecordOrdinal() {
        String validRow = "1537522822.0\tC123\t10.0.0.1\t80\t10.0.0.2\t80\ttcp\tssl\t1.0\t10\t10\tSF\t-\t-\t0\t-\t1\t10\t1\t10\t-";
        assertThatThrownBy(() -> parser.parse(standardHeader, validRow, -1L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("recordOrdinal must be non-negative");
    }

    @Test
    @DisplayName("Should never expose raw input line in error messages")
    void shouldNeverExposeRawInputRowInErrorMessages() {
        String sensitiveRow = "1537522822.0\tSUPER_SECRET_UID_999\tINVALID_IP\t80\t10.0.0.2\t80\ttcp\tssl\t1.0\t10\t10\tSF\t-\t-\t0\t-\t1\t10\t1\t10\t-";
        assertThatThrownBy(() -> parser.parse(standardHeader, sensitiveRow, 42L))
            .isInstanceOf(RecordParseException.class)
            .satisfies(e -> {
                assertThat(e.getMessage()).doesNotContain("SUPER_SECRET_UID_999");
                assertThat(e.getMessage()).doesNotContain("INVALID_IP");
                assertThat(e.getMessage()).contains("id.orig_h");
                assertThat(e.getMessage()).contains("record ordinal 42");
            });
    }

    @Test
    @DisplayName("Should parse real benign conn.log line successfully")
    void shouldParseRealBenignConnLogLine() {
        String realBenignLine = "1537522822.965530\tCbpiuT1GMBGVeNJKa5\t0.0.0.0\t68\t255.255.255.255\t67\tudp\tdhcp\t8.322388\t600\t0\tS0\t-\t-\t0\tD\t2\t656\t0\t0\t-";

        NetworkEvent event = ZeekRecordParser.parseRecord(standardHeader, realBenignLine, 0L);

        assertThat(event.uid()).isEqualTo("CbpiuT1GMBGVeNJKa5");
        assertThat(event.sourceAddress().getHostAddress()).isEqualTo("0.0.0.0");
        assertThat(event.sourcePort()).isEqualTo(68);
        assertThat(event.destinationAddress().getHostAddress()).isEqualTo("255.255.255.255");
        assertThat(event.destinationPort()).isEqualTo(67);
        assertThat(event.protocol()).isEqualTo(TransportProtocol.UDP);
        assertThat(event.service()).isEqualTo("dhcp");
        assertThat(event.duration()).isEqualTo(8.322388);
        assertThat(event.origBytes()).isEqualTo(600L);
        assertThat(event.respBytes()).isZero();
        assertThat(event.connectionState()).isEqualTo(ConnectionState.S0);
        assertThat(event.history()).isEqualTo("D");
        assertThat(event.origPkts()).isEqualTo(2L);
        assertThat(event.respPkts()).isZero();
    }
}
