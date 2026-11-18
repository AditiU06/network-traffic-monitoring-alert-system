package com.kletech.networkmonitor.engine.e1.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("ConnectionState enum tests")
class ConnectionStateTest {

    @Test
    @DisplayName("Should contain exactly the 13 documented Zeek conn_state values")
    void shouldContainExpectedZeekStates() {
        assertThat(ConnectionState.values()).containsExactly(
            ConnectionState.S0,
            ConnectionState.S1,
            ConnectionState.SF,
            ConnectionState.REJ,
            ConnectionState.S2,
            ConnectionState.S3,
            ConnectionState.RSTO,
            ConnectionState.RSTR,
            ConnectionState.RSTOS0,
            ConnectionState.RSTRH,
            ConnectionState.SH,
            ConnectionState.SHR,
            ConnectionState.OTH
        );
    }

    @ParameterizedTest
    @EnumSource(ConnectionState.class)
    @DisplayName("Should parse each exact connection state symbol")
    void shouldParseEachEnumState(ConnectionState state) {
        assertThat(ConnectionState.fromString(state.name())).isEqualTo(state);
    }

    @ParameterizedTest
    @ValueSource(strings = {"s0", "  S0  ", "sf", "Sf", "  rej  ", "rsto", "rstos0", "sh", "oth"})
    @DisplayName("Should parse connection states case-insensitively with trimming")
    void shouldParseCaseInsensitiveWithTrimming(String input) {
        ConnectionState state = ConnectionState.fromString(input);
        assertThat(state).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"CLOSED", "ESTABLISHED", "SYN_SENT", "LISTEN", "UNKNOWN", "INVALID", "s4", "FIN"})
    @DisplayName("Should reject unknown states without defaulting or inventing states")
    void shouldRejectUnknownStates(String input) {
        assertThatThrownBy(() -> ConnectionState.fromString(input))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Unsupported or unknown connection state");
    }

    @Test
    @DisplayName("Should reject null connection state string")
    void shouldRejectNullString() {
        assertThatThrownBy(() -> ConnectionState.fromString(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("must not be null or blank");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t", "\n"})
    @DisplayName("Should reject blank connection state string")
    void shouldRejectBlankString(String input) {
        assertThatThrownBy(() -> ConnectionState.fromString(input))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("must not be null or blank");
    }
}
