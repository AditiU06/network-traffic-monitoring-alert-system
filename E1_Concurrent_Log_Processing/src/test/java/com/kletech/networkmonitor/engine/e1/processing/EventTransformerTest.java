package com.kletech.networkmonitor.engine.e1.processing;

import com.kletech.networkmonitor.engine.e1.model.ConnectionState;
import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.ProcessedNetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.TransportProtocol;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("EventTransformer unit tests")
class EventTransformerTest {

    private NetworkEvent createEvent(long ordinal, Long origBytes, Long respBytes, Long origPkts, Long respPkts) {
        try {
            return new NetworkEvent(
                ordinal,
                Instant.ofEpochSecond(1600000000L),
                "C" + ordinal,
                InetAddress.getByAddress(new byte[]{(byte) 192, (byte) 168, 1, 10}),
                5000,
                InetAddress.getByAddress(new byte[]{10, 0, 0, 1}),
                80,
                TransportProtocol.TCP,
                "http",
                2.0,
                origBytes,
                respBytes,
                ConnectionState.SF,
                "ShADdfFa",
                origPkts,
                respPkts
            );
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Transforms event with all byte and packet metrics present")
    void testCompleteMetrics() {
        NetworkEvent event = createEvent(100L, 1000L, 4000L, 10L, 40L);
        ProcessedNetworkEvent processed = EventTransformer.transform(event);

        assertThat(processed.recordOrdinal()).isEqualTo(100L);
        assertThat(processed.originalEvent()).isSameAs(event);
        assertThat(processed.totalBytes()).isEqualTo(5000L);
        assertThat(processed.totalPackets()).isEqualTo(50L);
        assertThat(processed.bytesPerPacket()).isEqualTo(100.0); // 5000 / 50
        assertThat(processed.origToRespRatio()).isEqualTo(0.25); // 1000 / 4000
    }

    @Test
    @DisplayName("Handles missing values when both originator and responder are null")
    void testBothNullMetrics() {
        NetworkEvent event = createEvent(1L, null, null, null, null);
        ProcessedNetworkEvent processed = EventTransformer.transform(event);

        assertThat(processed.totalBytes()).isNull();
        assertThat(processed.totalPackets()).isNull();
        assertThat(processed.bytesPerPacket()).isNull();
        assertThat(processed.origToRespRatio()).isNull();
    }

    @Test
    @DisplayName("Treats null as 0 when only one byte or packet counter is present")
    void testPartialMetrics() {
        NetworkEvent event = createEvent(2L, 500L, null, null, 5L);
        ProcessedNetworkEvent processed = EventTransformer.transform(event);

        assertThat(processed.totalBytes()).isEqualTo(500L); // 500 + 0
        assertThat(processed.totalPackets()).isEqualTo(5L);   // 0 + 5
        assertThat(processed.bytesPerPacket()).isEqualTo(100.0); // 500 / 5
        assertThat(processed.origToRespRatio()).isNull();    // respBytes is null
    }

    @Test
    @DisplayName("Yields null bytesPerPacket when totalPackets is zero")
    void testZeroPackets() {
        NetworkEvent event = createEvent(3L, 100L, 200L, 0L, 0L);
        ProcessedNetworkEvent processed = EventTransformer.transform(event);

        assertThat(processed.totalBytes()).isEqualTo(300L);
        assertThat(processed.totalPackets()).isZero();
        assertThat(processed.bytesPerPacket()).isNull();
    }

    @Test
    @DisplayName("Yields null origToRespRatio when respBytes is zero")
    void testZeroRespBytes() {
        NetworkEvent event = createEvent(4L, 500L, 0L, 1L, 1L);
        ProcessedNetworkEvent processed = EventTransformer.transform(event);

        assertThat(processed.totalBytes()).isEqualTo(500L);
        assertThat(processed.origToRespRatio()).isNull();
    }

    @Test
    @DisplayName("Throws ArithmeticException on totalBytes overflow")
    void testTotalBytesOverflow() {
        NetworkEvent event = createEvent(5L, Long.MAX_VALUE, 1L, 1L, 1L);
        assertThatThrownBy(() -> EventTransformer.transform(event))
            .isInstanceOf(ArithmeticException.class);
    }

    @Test
    @DisplayName("Throws ArithmeticException on totalPackets overflow")
    void testTotalPacketsOverflow() {
        NetworkEvent event = createEvent(6L, 10L, 10L, Long.MAX_VALUE, 100L);
        assertThatThrownBy(() -> EventTransformer.transform(event))
            .isInstanceOf(ArithmeticException.class);
    }

    @Test
    @DisplayName("Rejects null NetworkEvent input")
    void testNullEvent() {
        assertThatThrownBy(() -> EventTransformer.transform(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("event must not be null");
    }

    @Test
    @DisplayName("Preserves original non-sequential recordOrdinal")
    void testPreservesArbitraryOrdinal() {
        NetworkEvent event = createEvent(999999L, 10L, 10L, 1L, 1L);
        ProcessedNetworkEvent processed = EventTransformer.transform(event);
        assertThat(processed.recordOrdinal()).isEqualTo(999999L);
    }
}
