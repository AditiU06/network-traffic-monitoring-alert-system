package com.kletech.networkmonitor.engine.e1.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("TransportProtocol enum tests")
class TransportProtocolTest {

    @Test
    @DisplayName("Should contain all expected protocols (TCP, UDP, ICMP)")
    void shouldContainExpectedProtocols() {
        assertThat(TransportProtocol.values()).containsExactly(
            TransportProtocol.TCP,
            TransportProtocol.UDP,
            TransportProtocol.ICMP
        );
    }

    @ParameterizedTest
    @ValueSource(strings = {"tcp", "TCP", "  tcp  ", "Tcp"})
    @DisplayName("Should resolve TCP case-insensitively with trimming")
    void shouldResolveTcp(String input) {
        assertThat(TransportProtocol.fromString(input)).isEqualTo(TransportProtocol.TCP);
    }

    @ParameterizedTest
    @ValueSource(strings = {"udp", "UDP", "  udp  ", "Udp"})
    @DisplayName("Should resolve UDP case-insensitively with trimming")
    void shouldResolveUdp(String input) {
        assertThat(TransportProtocol.fromString(input)).isEqualTo(TransportProtocol.UDP);
    }

    @ParameterizedTest
    @ValueSource(strings = {"icmp", "ICMP", "  icmp  ", "Icmp"})
    @DisplayName("Should resolve ICMP case-insensitively with trimming")
    void shouldResolveIcmp(String input) {
        assertThat(TransportProtocol.fromString(input)).isEqualTo(TransportProtocol.ICMP);
    }

    @ParameterizedTest
    @ValueSource(strings = {"sctp", "igmp", "gre", "unknown", "123", "ip"})
    @DisplayName("Should reject unsupported or unknown protocols without defaulting")
    void shouldRejectUnsupportedProtocols(String input) {
        assertThatThrownBy(() -> TransportProtocol.fromString(input))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Unsupported or unknown transport protocol");
    }

    @Test
    @DisplayName("Should reject null protocol string")
    void shouldRejectNullString() {
        assertThatThrownBy(() -> TransportProtocol.fromString(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("must not be null or blank");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t", "\n"})
    @DisplayName("Should reject blank protocol string")
    void shouldRejectBlankString(String input) {
        assertThatThrownBy(() -> TransportProtocol.fromString(input))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("must not be null or blank");
    }
}
