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

@DisplayName("ProcessingResult model tests")
class ProcessingResultTest {

    private static final Instant SAMPLE_TIME = Instant.parse("2026-11-13T00:00:00Z");

    private NetworkEvent createSampleEvent(long recordOrdinal) {
        try {
            return new NetworkEvent(
                recordOrdinal,
                SAMPLE_TIME,
                "C_UID_" + recordOrdinal,
                InetAddress.getByName("192.168.1.1"),
                12345,
                InetAddress.getByName("192.168.1.2"),
                80,
                TransportProtocol.TCP,
                "http",
                1.5,
                100L,
                200L,
                ConnectionState.SF,
                "ShAD",
                5L,
                5L
            );
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Should construct a valid success ProcessingResult")
    void shouldConstructValidSuccessResult() {
        NetworkEvent event = createSampleEvent(0L);
        ProcessingResult result = new ProcessingResult(9L, 0L, event, null);

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.isFailure()).isFalse();
        assertThat(result.lineNumber()).isEqualTo(9L);
        assertThat(result.recordOrdinal()).isZero();
        assertThat(result.event()).isEqualTo(event);
        assertThat(result.errorMessage()).isNull();
    }

    @Test
    @DisplayName("Should construct a valid failure ProcessingResult")
    void shouldConstructValidFailureResult() {
        ProcessingResult result = new ProcessingResult(10L, 1L, null, "Malformed record: missing required field");

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.isFailure()).isTrue();
        assertThat(result.lineNumber()).isEqualTo(10L);
        assertThat(result.recordOrdinal()).isEqualTo(1L);
        assertThat(result.event()).isNull();
        assertThat(result.errorMessage()).isEqualTo("Malformed record: missing required field");
    }

    @Test
    @DisplayName("Should create success result via factory method")
    void shouldCreateSuccessViaFactoryMethod() {
        NetworkEvent event = createSampleEvent(5L);
        ProcessingResult result = ProcessingResult.success(15L, 5L, event);

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.event()).isEqualTo(event);
        assertThat(result.errorMessage()).isNull();
    }

    @Test
    @DisplayName("Should create failure result via factory method")
    void shouldCreateFailureViaFactoryMethod() {
        ProcessingResult result = ProcessingResult.failure(12L, 2L, "Invalid IP address");

        assertThat(result.isFailure()).isTrue();
        assertThat(result.event()).isNull();
        assertThat(result.errorMessage()).isEqualTo("Invalid IP address");
    }

    @Test
    @DisplayName("Should reject factory method calls with null arguments")
    void shouldRejectFactoryMethodWithNullArguments() {
        assertThatThrownBy(() -> ProcessingResult.success(10L, 0L, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("event must not be null");

        assertThatThrownBy(() -> ProcessingResult.failure(10L, 0L, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("errorMessage must not be null");
    }

    @Test
    @DisplayName("Should reject when both event and errorMessage are null (invariant violation)")
    void shouldRejectWhenBothEventAndErrorMessageAreNull() {
        assertThatThrownBy(() -> new ProcessingResult(1L, 0L, null, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Precisely one of 'event' or 'errorMessage' must be non-null");
    }

    @Test
    @DisplayName("Should reject when both event and errorMessage are non-null (invariant violation)")
    void shouldRejectWhenBothEventAndErrorMessageAreNonNull() {
        NetworkEvent event = createSampleEvent(0L);
        assertThatThrownBy(() -> new ProcessingResult(1L, 0L, event, "Error message"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Precisely one of 'event' or 'errorMessage' must be non-null");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t", "\n"})
    @DisplayName("Should reject failure result with blank errorMessage")
    void shouldRejectBlankErrorMessage(String blankError) {
        assertThatThrownBy(() -> new ProcessingResult(1L, 0L, null, blankError))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("errorMessage must not be blank");
    }

    @ParameterizedTest
    @ValueSource(longs = {0L, -1L, -100L})
    @DisplayName("Should reject lineNumber < 1 (1-based physical lines)")
    void shouldRejectInvalidLineNumber(long invalidLine) {
        NetworkEvent event = createSampleEvent(0L);
        assertThatThrownBy(() -> new ProcessingResult(invalidLine, 0L, event, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("lineNumber must be >= 1");
    }

    @ParameterizedTest
    @ValueSource(longs = {-1L, -5L, -100L})
    @DisplayName("Should reject recordOrdinal < 0 (0-based record ordinals)")
    void shouldRejectInvalidRecordOrdinal(long invalidOrdinal) {
        assertThatThrownBy(() -> new ProcessingResult(1L, invalidOrdinal, null, "Error"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("recordOrdinal must be >= 0");
    }

    @Test
    @DisplayName("Should reject when event.recordOrdinal does not match ProcessingResult.recordOrdinal")
    void shouldRejectMismatchedRecordOrdinal() {
        NetworkEvent eventWithOrdinal5 = createSampleEvent(5L);

        assertThatThrownBy(() -> new ProcessingResult(20L, 10L, eventWithOrdinal5, null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("event.recordOrdinal (5) must match ProcessingResult.recordOrdinal (10)");
    }

    @Test
    @DisplayName("Should satisfy record equality, hashcode, and toString contract")
    void shouldSatisfyRecordEqualityContract() {
        NetworkEvent event = createSampleEvent(0L);
        ProcessingResult res1 = new ProcessingResult(9L, 0L, event, null);
        ProcessingResult res2 = new ProcessingResult(9L, 0L, event, null);
        ProcessingResult diff = new ProcessingResult(10L, 0L, event, null);

        assertThat(res1).isEqualTo(res2);
        assertThat(res1.hashCode()).isEqualTo(res2.hashCode());
        assertThat(res1).isNotEqualTo(diff);
        assertThat(res1.toString()).contains("lineNumber=9", "recordOrdinal=0");
    }
}
