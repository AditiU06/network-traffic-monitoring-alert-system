package com.kletech.networkmonitor.engine.e1.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("ProcessedNetworkEvent unit tests")
class ProcessedNetworkEventTest {

    private NetworkEvent createEvent(long ordinal) {
        try {
            return new NetworkEvent(
                ordinal,
                Instant.ofEpochSecond(1600000000L),
                "C" + ordinal,
                InetAddress.getByAddress(new byte[]{10, 0, 0, 1}),
                1234,
                InetAddress.getByAddress(new byte[]{10, 0, 0, 2}),
                80,
                TransportProtocol.TCP,
                "http",
                1.5,
                100L,
                200L,
                ConnectionState.SF,
                "S",
                5L,
                10L
            );
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Successfully creates ProcessedNetworkEvent with valid fields")
    void testValidConstruction() {
        NetworkEvent event = createEvent(42L);
        ProcessedNetworkEvent processed = new ProcessedNetworkEvent(
            42L,
            event,
            300L,
            15L,
            20.0,
            0.5
        );

        assertThat(processed.recordOrdinal()).isEqualTo(42L);
        assertThat(processed.originalEvent()).isSameAs(event);
        assertThat(processed.totalBytes()).isEqualTo(300L);
        assertThat(processed.totalPackets()).isEqualTo(15L);
        assertThat(processed.bytesPerPacket()).isEqualTo(20.0);
        assertThat(processed.origToRespRatio()).isEqualTo(0.5);
    }

    @Test
    @DisplayName("Rejects negative recordOrdinal")
    void testNegativeRecordOrdinal() {
        NetworkEvent event = createEvent(0L);
        assertThatThrownBy(() -> new ProcessedNetworkEvent(-1L, event, 100L, 10L, 10.0, 1.0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("recordOrdinal must be non-negative");
    }

    @Test
    @DisplayName("Rejects null originalEvent")
    void testNullOriginalEvent() {
        assertThatThrownBy(() -> new ProcessedNetworkEvent(0L, null, 100L, 10L, 10.0, 1.0))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("originalEvent must not be null");
    }

    @Test
    @DisplayName("Rejects mismatch between recordOrdinal and originalEvent.recordOrdinal")
    void testOrdinalMismatch() {
        NetworkEvent event = createEvent(5L);
        assertThatThrownBy(() -> new ProcessedNetworkEvent(10L, event, 100L, 10L, 10.0, 1.0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("does not match originalEvent.recordOrdinal");
    }

    @Test
    @DisplayName("Rejects negative totalBytes or totalPackets")
    void testNegativeTotals() {
        NetworkEvent event = createEvent(0L);
        assertThatThrownBy(() -> new ProcessedNetworkEvent(0L, event, -1L, 10L, 1.0, 1.0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("totalBytes must be non-negative");

        assertThatThrownBy(() -> new ProcessedNetworkEvent(0L, event, 10L, -5L, 1.0, 1.0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("totalPackets must be non-negative");
    }

    @Test
    @DisplayName("Rejects non-finite or negative ratios")
    void testInvalidRatios() {
        NetworkEvent event = createEvent(0L);
        assertThatThrownBy(() -> new ProcessedNetworkEvent(0L, event, 10L, 10L, Double.NaN, 1.0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("bytesPerPacket must be a finite number");

        assertThatThrownBy(() -> new ProcessedNetworkEvent(0L, event, 10L, 10L, -0.5, 1.0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("bytesPerPacket must not be negative");

        assertThatThrownBy(() -> new ProcessedNetworkEvent(0L, event, 10L, 10L, 1.0, Double.POSITIVE_INFINITY))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("origToRespRatio must be a finite number");

        assertThatThrownBy(() -> new ProcessedNetworkEvent(0L, event, 10L, 10L, 1.0, -1.0))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("origToRespRatio must not be negative");
    }

    @Test
    @DisplayName("Allows null values for optional calculated metrics")
    void testNullCalculatedMetrics() {
        NetworkEvent event = createEvent(0L);
        ProcessedNetworkEvent processed = new ProcessedNetworkEvent(0L, event, null, null, null, null);
        assertThat(processed.totalBytes()).isNull();
        assertThat(processed.totalPackets()).isNull();
        assertThat(processed.bytesPerPacket()).isNull();
        assertThat(processed.origToRespRatio()).isNull();
    }
}
