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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("SequentialProcessor unit tests")
class SequentialProcessorTest {

    private NetworkEvent createEvent(long ordinal, Long origBytes, Long respBytes) {
        try {
            return new NetworkEvent(
                ordinal,
                Instant.ofEpochSecond(1600000000L + ordinal),
                "Cuid_" + ordinal,
                InetAddress.getByAddress(new byte[]{(byte) 192, (byte) 168, 1, (byte) (ordinal % 250 + 1)}),
                1000 + (int) ordinal,
                InetAddress.getByAddress(new byte[]{10, 0, 0, 1}),
                80,
                TransportProtocol.TCP,
                "http",
                1.0,
                origBytes,
                respBytes,
                ConnectionState.SF,
                "S",
                10L,
                20L
            );
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Returns empty list when input is empty and list is unmodifiable")
    void testEmptyList() {
        SequentialProcessor processor = new SequentialProcessor();
        List<ProcessedNetworkEvent> results = processor.process(Collections.emptyList());
        assertThat(results).isEmpty();
        assertThatThrownBy(() -> results.add(null))
            .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("Returns unmodifiable result list for non-empty input")
    void testResultListIsUnmodifiable() {
        SequentialProcessor processor = new SequentialProcessor();
        List<NetworkEvent> events = List.of(createEvent(1L, 100L, 200L));
        List<ProcessedNetworkEvent> results = processor.process(events);
        assertThat(results).hasSize(1);
        assertThatThrownBy(() -> results.add(null))
            .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> results.remove(0))
            .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("Processes multiple events sequentially and preserves exact order and ordinals")
    void testProcessMultipleEvents() {
        SequentialProcessor processor = new SequentialProcessor();
        List<NetworkEvent> events = List.of(
            createEvent(10L, 100L, 200L),
            createEvent(50L, 300L, 400L),
            createEvent(999L, 500L, 500L)
        );

        List<ProcessedNetworkEvent> results = processor.process(events);

        assertThat(results).hasSize(3);
        assertThat(results.get(0).recordOrdinal()).isEqualTo(10L);
        assertThat(results.get(0).totalBytes()).isEqualTo(300L);

        assertThat(results.get(1).recordOrdinal()).isEqualTo(50L);
        assertThat(results.get(1).totalBytes()).isEqualTo(700L);

        assertThat(results.get(2).recordOrdinal()).isEqualTo(999L);
        assertThat(results.get(2).totalBytes()).isEqualTo(1000L);
    }

    @Test
    @DisplayName("Rejects null list input")
    void testNullList() {
        SequentialProcessor processor = new SequentialProcessor();
        assertThatThrownBy(() -> processor.process(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("events must not be null");
    }

    @Test
    @DisplayName("Rejects list containing null elements")
    void testListWithNullElement() {
        SequentialProcessor processor = new SequentialProcessor();
        List<NetworkEvent> events = new ArrayList<>();
        events.add(createEvent(1L, 10L, 10L));
        events.add(null);

        assertThatThrownBy(() -> processor.process(events))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("event element in list must not be null");
    }
}
