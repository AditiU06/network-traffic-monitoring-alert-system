package com.kletech.networkmonitor.engine.e1.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("NetworkEvent model tests")
class NetworkEventTest {

    private static final Instant SAMPLE_TIME = Instant.parse("2026-11-13T00:00:00Z");

    private InetAddress ipv4(String ip) {
        try {
            return InetAddress.getByName(ip);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    private InetAddress ipv6(String ip) {
        try {
            return InetAddress.getByName(ip);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Should construct valid NetworkEvent with all fields populated")
    void shouldConstructValidFullEvent() {
        NetworkEvent event = new NetworkEvent(
            0L,
            SAMPLE_TIME,
            "C179s7RaGHGnXRX9f",
            ipv4("192.168.1.10"),
            54321,
            ipv4("10.0.0.1"),
            443,
            TransportProtocol.TCP,
            "ssl",
            12.345,
            1024L,
            4096L,
            ConnectionState.SF,
            "ShADdfFa",
            10L,
            12L
        );

        assertThat(event.recordOrdinal()).isZero();
        assertThat(event.timestamp()).isEqualTo(SAMPLE_TIME);
        assertThat(event.uid()).isEqualTo("C179s7RaGHGnXRX9f");
        assertThat(event.sourceAddress()).isEqualTo(ipv4("192.168.1.10"));
        assertThat(event.sourcePort()).isEqualTo(54321);
        assertThat(event.destinationAddress()).isEqualTo(ipv4("10.0.0.1"));
        assertThat(event.destinationPort()).isEqualTo(443);
        assertThat(event.protocol()).isEqualTo(TransportProtocol.TCP);
        assertThat(event.service()).isEqualTo("ssl");
        assertThat(event.duration()).isEqualTo(12.345);
        assertThat(event.origBytes()).isEqualTo(1024L);
        assertThat(event.respBytes()).isEqualTo(4096L);
        assertThat(event.connectionState()).isEqualTo(ConnectionState.SF);
        assertThat(event.history()).isEqualTo("ShADdfFa");
        assertThat(event.origPkts()).isEqualTo(10L);
        assertThat(event.respPkts()).isEqualTo(12L);
    }

    @Test
    @DisplayName("Should construct valid NetworkEvent with missing optional values as null")
    void shouldConstructEventWithNullOptionalValues() {
        NetworkEvent event = new NetworkEvent(
            42L,
            SAMPLE_TIME,
            "C_MINIMAL_UID",
            ipv4("192.168.2.1"),
            5353,
            ipv4("224.0.0.251"),
            5353,
            TransportProtocol.UDP,
            null, // missing service
            null, // missing duration
            null, // missing origBytes
            null, // missing respBytes
            ConnectionState.S0,
            null, // missing history
            null, // missing origPkts
            null  // missing respPkts
        );

        assertThat(event.recordOrdinal()).isEqualTo(42L);
        assertThat(event.service()).isNull();
        assertThat(event.duration()).isNull();
        assertThat(event.origBytes()).isNull();
        assertThat(event.respBytes()).isNull();
        assertThat(event.history()).isNull();
        assertThat(event.origPkts()).isNull();
        assertThat(event.respPkts()).isNull();
    }

    @Test
    @DisplayName("Should support IPv6 addresses for both source and destination")
    void shouldSupportIpv6Addresses() {
        InetAddress srcV6 = ipv6("fe80::80e6:50ff:fe12:1464");
        InetAddress dstV6 = ipv6("ff02::fb");

        NetworkEvent event = new NetworkEvent(
            1L,
            SAMPLE_TIME,
            "C_IPV6_UID",
            srcV6,
            5353,
            dstV6,
            5353,
            TransportProtocol.UDP,
            "dns",
            0.05,
            100L,
            200L,
            ConnectionState.SF,
            "Dd",
            1L,
            1L
        );

        assertThat(event.sourceAddress()).isEqualTo(srcV6);
        assertThat(event.destinationAddress()).isEqualTo(dstV6);
    }

    @Test
    @DisplayName("Should support ICMP records with null ports without fabricating port values")
    void shouldSupportIcmpWithNullPorts() {
        NetworkEvent event = new NetworkEvent(
            2L,
            SAMPLE_TIME,
            "C_ICMP_UID",
            ipv4("192.168.1.1"),
            null, // ICMP has no Layer 4 port
            ipv4("192.168.1.254"),
            null, // ICMP has no Layer 4 port
            TransportProtocol.ICMP,
            null,
            null,
            null,
            null,
            ConnectionState.OTH,
            null,
            1L,
            0L
        );

        assertThat(event.protocol()).isEqualTo(TransportProtocol.ICMP);
        assertThat(event.sourcePort()).isNull();
        assertThat(event.destinationPort()).isNull();
    }

    @Test
    @DisplayName("Should accept port boundary values: 0 and 65535")
    void shouldAcceptPortBoundaries() {
        NetworkEvent eventMin = new NetworkEvent(
            0L, SAMPLE_TIME, "UID_PORT_0",
            ipv4("10.0.0.1"), 0,
            ipv4("10.0.0.2"), 0,
            TransportProtocol.TCP, null, null, null, null,
            ConnectionState.SF, null, null, null
        );
        assertThat(eventMin.sourcePort()).isZero();
        assertThat(eventMin.destinationPort()).isZero();

        NetworkEvent eventMax = new NetworkEvent(
            1L, SAMPLE_TIME, "UID_PORT_MAX",
            ipv4("10.0.0.1"), 65535,
            ipv4("10.0.0.2"), 65535,
            TransportProtocol.UDP, null, null, null, null,
            ConnectionState.SF, null, null, null
        );
        assertThat(eventMax.sourcePort()).isEqualTo(65535);
        assertThat(eventMax.destinationPort()).isEqualTo(65535);
    }

    @Test
    @DisplayName("Should accept legitimate zero-valued duration, bytes, and packets")
    void shouldAcceptZeroValuedCountersAndDuration() {
        NetworkEvent event = new NetworkEvent(
            0L, SAMPLE_TIME, "UID_ZEROS",
            ipv4("10.0.0.1"), 1234,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null,
            0.0,  // zero duration
            0L,   // zero origBytes
            0L,   // zero respBytes
            ConnectionState.S0, null,
            0L,   // zero origPkts
            0L    // zero respPkts
        );

        assertThat(event.duration()).isEqualTo(0.0);
        assertThat(event.origBytes()).isZero();
        assertThat(event.respBytes()).isZero();
        assertThat(event.origPkts()).isZero();
        assertThat(event.respPkts()).isZero();
    }

    @Test
    @DisplayName("Should reject negative recordOrdinal")
    void shouldRejectNegativeRecordOrdinal() {
        assertThatThrownBy(() -> new NetworkEvent(
            -1L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null, null, null, null,
            ConnectionState.SF, null, null, null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("recordOrdinal must be non-negative");
    }

    @Test
    @DisplayName("Should reject null timestamp")
    void shouldRejectNullTimestamp() {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, null, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null, null, null, null,
            ConnectionState.SF, null, null, null
        )).isInstanceOf(NullPointerException.class)
          .hasMessageContaining("timestamp must not be null");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t", "\n"})
    @DisplayName("Should reject blank uid")
    void shouldRejectBlankUid(String blankUid) {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, blankUid,
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null, null, null, null,
            ConnectionState.SF, null, null, null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("uid must not be blank");
    }

    @Test
    @DisplayName("Should reject null uid")
    void shouldRejectNullUid() {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, null,
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null, null, null, null,
            ConnectionState.SF, null, null, null
        )).isInstanceOf(NullPointerException.class)
          .hasMessageContaining("uid must not be null");
    }

    @Test
    @DisplayName("Should reject null sourceAddress")
    void shouldRejectNullSourceAddress() {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            null, 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null, null, null, null,
            ConnectionState.SF, null, null, null
        )).isInstanceOf(NullPointerException.class)
          .hasMessageContaining("sourceAddress must not be null");
    }

    @Test
    @DisplayName("Should reject null destinationAddress")
    void shouldRejectNullDestinationAddress() {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            null, 80,
            TransportProtocol.TCP, null, null, null, null,
            ConnectionState.SF, null, null, null
        )).isInstanceOf(NullPointerException.class)
          .hasMessageContaining("destinationAddress must not be null");
    }

    @Test
    @DisplayName("Should reject null protocol")
    void shouldRejectNullProtocol() {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            null, null, null, null, null,
            ConnectionState.SF, null, null, null
        )).isInstanceOf(NullPointerException.class)
          .hasMessageContaining("protocol must not be null");
    }

    @Test
    @DisplayName("Should reject null connectionState")
    void shouldRejectNullConnectionState() {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null, null, null, null,
            null, null, null, null
        )).isInstanceOf(NullPointerException.class)
          .hasMessageContaining("connectionState must not be null");
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, -100, 65536, 70000})
    @DisplayName("Should reject invalid sourcePort numbers outside 0..65535")
    void shouldRejectInvalidSourcePort(int invalidPort) {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), invalidPort,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null, null, null, null,
            ConnectionState.SF, null, null, null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("sourcePort must be between 0 and 65535");
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, -500, 65536, 100000})
    @DisplayName("Should reject invalid destinationPort numbers outside 0..65535")
    void shouldRejectInvalidDestinationPort(int invalidPort) {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), invalidPort,
            TransportProtocol.TCP, null, null, null, null,
            ConnectionState.SF, null, null, null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("destinationPort must be between 0 and 65535");
    }

    @Test
    @DisplayName("Should reject negative duration")
    void shouldRejectNegativeDuration() {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null,
            -0.001,
            null, null,
            ConnectionState.SF, null, null, null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("duration must not be negative");
    }

    @Test
    @DisplayName("Should reject NaN or infinite duration")
    void shouldRejectNonFiniteDuration() {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null,
            Double.NaN,
            null, null,
            ConnectionState.SF, null, null, null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("duration must be a finite number");

        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null,
            Double.POSITIVE_INFINITY,
            null, null,
            ConnectionState.SF, null, null, null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("duration must be a finite number");
    }

    @Test
    @DisplayName("Should reject negative origBytes")
    void shouldRejectNegativeOrigBytes() {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null, null,
            -1L,
            null,
            ConnectionState.SF, null, null, null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("origBytes must not be negative");
    }

    @Test
    @DisplayName("Should reject negative respBytes")
    void shouldRejectNegativeRespBytes() {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null, null, null,
            -1L,
            ConnectionState.SF, null, null, null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("respBytes must not be negative");
    }

    @Test
    @DisplayName("Should reject negative origPkts")
    void shouldRejectNegativeOrigPkts() {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null, null, null, null,
            ConnectionState.SF, null,
            -1L,
            null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("origPkts must not be negative");
    }

    @Test
    @DisplayName("Should reject negative respPkts")
    void shouldRejectNegativeRespPkts() {
        assertThatThrownBy(() -> new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, null, null, null, null,
            ConnectionState.SF, null, null,
            -1L
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("respPkts must not be negative");
    }

    @Test
    @DisplayName("Should satisfy record equality, hashcode, and toString contract")
    void shouldSatisfyRecordEqualityContract() {
        NetworkEvent event1 = new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, "http", 1.0, 100L, 200L,
            ConnectionState.SF, "ShAD", 5L, 5L
        );

        NetworkEvent event2 = new NetworkEvent(
            0L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, "http", 1.0, 100L, 200L,
            ConnectionState.SF, "ShAD", 5L, 5L
        );

        NetworkEvent different = new NetworkEvent(
            1L, SAMPLE_TIME, "UID",
            ipv4("10.0.0.1"), 80,
            ipv4("10.0.0.2"), 80,
            TransportProtocol.TCP, "http", 1.0, 100L, 200L,
            ConnectionState.SF, "ShAD", 5L, 5L
        );

        assertThat(event1).isEqualTo(event2);
        assertThat(event1.hashCode()).isEqualTo(event2.hashCode());
        assertThat(event1).isNotEqualTo(different);
        assertThat(event1.toString()).contains("UID", "10.0.0.1", "TCP");
    }
}
