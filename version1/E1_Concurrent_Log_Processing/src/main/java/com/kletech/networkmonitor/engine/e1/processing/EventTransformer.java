package com.kletech.networkmonitor.engine.e1.processing;

import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.ProcessedNetworkEvent;

import java.util.Objects;

/**
 * Deterministic transformation function converting a single {@link NetworkEvent}
 * into an enriched {@link ProcessedNetworkEvent}.
 *
 * <p>Serves as the single source of truth for both sequential and multithreaded
 * processing engines, ensuring strict 100% output parity.</p>
 */
public final class EventTransformer {

    private EventTransformer() {
        // Prevent instantiation of utility class
    }

    /**
     * Transforms an immutable {@link NetworkEvent} into a {@link ProcessedNetworkEvent}.
     *
     * <p>Missing value semantics:</p>
     * <ul>
     *   <li>{@code totalBytes}: null if both {@code origBytes} and {@code respBytes} are null;
     *       otherwise sums available bytes treating null as 0 with {@link Math#addExact(long, long)} overflow protection.</li>
     *   <li>{@code totalPackets}: null if both {@code origPkts} and {@code respPkts} are null;
     *       otherwise sums available packets treating null as 0 with {@link Math#addExact(long, long)} overflow protection.</li>
     *   <li>{@code bytesPerPacket}: {@code totalBytes / totalPackets} when both are non-null and {@code totalPackets > 0};
     *       otherwise null.</li>
     *   <li>{@code origToRespRatio}: {@code origBytes / respBytes} when both are non-null and {@code respBytes > 0};
     *       otherwise null.</li>
     * </ul>
     *
     * @param event parsed network event
     * @return transformed processed network event
     * @throws NullPointerException if {@code event} is null
     * @throws ArithmeticException  if byte or packet sums exceed {@link Long#MAX_VALUE}
     */
    public static ProcessedNetworkEvent transform(NetworkEvent event) {
        Objects.requireNonNull(event, "event must not be null");

        // 1. Total bytes calculation
        Long totalBytes = null;
        if (event.origBytes() != null || event.respBytes() != null) {
            long orig = event.origBytes() != null ? event.origBytes() : 0L;
            long resp = event.respBytes() != null ? event.respBytes() : 0L;
            totalBytes = Math.addExact(orig, resp);
        }

        // 2. Total packets calculation
        Long totalPackets = null;
        if (event.origPkts() != null || event.respPkts() != null) {
            long orig = event.origPkts() != null ? event.origPkts() : 0L;
            long resp = event.respPkts() != null ? event.respPkts() : 0L;
            totalPackets = Math.addExact(orig, resp);
        }

        // 3. Bytes per packet calculation
        Double bytesPerPacket = null;
        if (totalBytes != null && totalPackets != null && totalPackets > 0L) {
            bytesPerPacket = (double) totalBytes / totalPackets;
        }

        // 4. Originator to responder byte ratio calculation
        Double origToRespRatio = null;
        if (event.origBytes() != null && event.respBytes() != null && event.respBytes() > 0L) {
            origToRespRatio = (double) event.origBytes() / event.respBytes();
        }

        return new ProcessedNetworkEvent(
            event.recordOrdinal(),
            event,
            totalBytes,
            totalPackets,
            bytesPerPacket,
            origToRespRatio
        );
    }
}
