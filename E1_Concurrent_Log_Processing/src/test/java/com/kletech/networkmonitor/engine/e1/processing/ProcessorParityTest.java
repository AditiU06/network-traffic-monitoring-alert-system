package com.kletech.networkmonitor.engine.e1.processing;

import com.kletech.networkmonitor.engine.e1.model.ConnectionState;
import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.ProcessedNetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.TransportProtocol;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Processor parity tests: 100% output equivalence")
class ProcessorParityTest {

    private List<NetworkEvent> generateDiverseDataset(int count) {
        List<NetworkEvent> list = new ArrayList<>(count);
        TransportProtocol[] protos = TransportProtocol.values();
        ConnectionState[] states = ConnectionState.values();

        for (int i = 0; i < count; i++) {
            try {
                // Non-sequential ordinals to verify that ordinal does not assume list index
                long ordinal = i * 7L + 3L;
                Long origBytes = (i % 3 == 0) ? null : (long) (i * 128);
                Long respBytes = (i % 5 == 0) ? null : (long) (i * 256);
                Long origPkts = (i % 4 == 0) ? null : (long) (i * 2 + 1);
                Long respPkts = (i % 6 == 0) ? null : (long) (i * 3);
                Integer srcPort = (protos[i % protos.length] == TransportProtocol.ICMP) ? null : (1024 + (i % 50000));
                Integer dstPort = (protos[i % protos.length] == TransportProtocol.ICMP) ? null : 80;

                list.add(new NetworkEvent(
                    ordinal,
                    Instant.ofEpochSecond(1600000000L + i),
                    "Cuid_" + i,
                    InetAddress.getByAddress(new byte[]{(byte) 192, (byte) 168, 1, (byte) (i % 250 + 1)}),
                    srcPort,
                    InetAddress.getByAddress(new byte[]{10, 0, 0, (byte) (i % 250 + 1)}),
                    dstPort,
                    protos[i % protos.length],
                    "service_" + (i % 5),
                    (i % 2 == 0) ? (double) i * 0.1 : null,
                    origBytes,
                    respBytes,
                    states[i % states.length],
                    "hist_" + i,
                    origPkts,
                    respPkts
                ));
            } catch (UnknownHostException e) {
                throw new RuntimeException(e);
            }
        }
        return list;
    }

    @ParameterizedTest(name = "Parity check with {0} worker thread(s)")
    @ValueSource(ints = {1, 2, 4, 8, 16})
    @DisplayName("Multithreaded output matches sequential output with 100% parity")
    void testParityAcrossWorkerCounts(int workers) {
        List<NetworkEvent> dataset = generateDiverseDataset(500);

        SequentialProcessor sequentialProcessor = new SequentialProcessor();
        List<ProcessedNetworkEvent> seqResults = sequentialProcessor.process(dataset);

        try (MultithreadedProcessor mtProcessor = new MultithreadedProcessor(workers)) {
            List<ProcessedNetworkEvent> mtResults = mtProcessor.process(dataset);

            // 1. Strict equality assertion: bit-for-bit record equality
            assertThat(mtResults).isEqualTo(seqResults);

            // 2. Explicit ordering verification
            assertThat(mtResults).hasSize(seqResults.size());
            for (int i = 0; i < seqResults.size(); i++) {
                ProcessedNetworkEvent seq = seqResults.get(i);
                ProcessedNetworkEvent mt = mtResults.get(i);

                assertThat(mt.recordOrdinal())
                    .as("recordOrdinal parity at index %d", i)
                    .isEqualTo(seq.recordOrdinal())
                    .isEqualTo(dataset.get(i).recordOrdinal());

                assertThat(mt.totalBytes()).isEqualTo(seq.totalBytes());
                assertThat(mt.totalPackets()).isEqualTo(seq.totalPackets());
                assertThat(mt.bytesPerPacket()).isEqualTo(seq.bytesPerPacket());
                assertThat(mt.origToRespRatio()).isEqualTo(seq.origToRespRatio());
                assertThat(mt.originalEvent()).isSameAs(seq.originalEvent());
            }
        }
    }
}
