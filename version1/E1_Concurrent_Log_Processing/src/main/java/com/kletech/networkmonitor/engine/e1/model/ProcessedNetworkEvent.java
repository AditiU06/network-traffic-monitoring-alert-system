package com.kletech.networkmonitor.engine.e1.model;

import java.util.Objects;

/**
 * Immutable processed representation of a Zeek network connection event.
 *
 * <p>Enriches the underlying immutable {@link NetworkEvent} with computed transmission
 * metrics, preserving the original record ordinal and deterministic event reference.</p>
 *
 * @param recordOrdinal   0-based ordinal of the data record in the source stream
 * @param originalEvent   underlying immutable network event
 * @param totalBytes      total bytes transferred across originator and responder; nullable if both are absent
 * @param totalPackets    total packets transferred across originator and responder; nullable if both are absent
 * @param bytesPerPacket  average bytes per packet (totalBytes / totalPackets); nullable if totalPackets is null or <= 0
 * @param origToRespRatio ratio of originator bytes to responder bytes (origBytes / respBytes); nullable if respBytes is null or <= 0
 */
public record ProcessedNetworkEvent(
    long recordOrdinal,
    NetworkEvent originalEvent,
    Long totalBytes,
    Long totalPackets,
    Double bytesPerPacket,
    Double origToRespRatio
) {
    /**
     * Compact constructor validating invariants, bounds, and consistency.
     */
    public ProcessedNetworkEvent {
        if (recordOrdinal < 0) {
            throw new IllegalArgumentException("recordOrdinal must be non-negative: " + recordOrdinal);
        }
        Objects.requireNonNull(originalEvent, "originalEvent must not be null");
        if (originalEvent.recordOrdinal() != recordOrdinal) {
            throw new IllegalArgumentException(
                "recordOrdinal (" + recordOrdinal + ") does not match originalEvent.recordOrdinal ("
                + originalEvent.recordOrdinal() + ")"
            );
        }
        if (totalBytes != null && totalBytes < 0) {
            throw new IllegalArgumentException("totalBytes must be non-negative: " + totalBytes);
        }
        if (totalPackets != null && totalPackets < 0) {
            throw new IllegalArgumentException("totalPackets must be non-negative: " + totalPackets);
        }
        if (bytesPerPacket != null) {
            if (!Double.isFinite(bytesPerPacket)) {
                throw new IllegalArgumentException("bytesPerPacket must be a finite number: " + bytesPerPacket);
            }
            if (bytesPerPacket < 0.0) {
                throw new IllegalArgumentException("bytesPerPacket must not be negative: " + bytesPerPacket);
            }
        }
        if (origToRespRatio != null) {
            if (!Double.isFinite(origToRespRatio)) {
                throw new IllegalArgumentException("origToRespRatio must be a finite number: " + origToRespRatio);
            }
            if (origToRespRatio < 0.0) {
                throw new IllegalArgumentException("origToRespRatio must not be negative: " + origToRespRatio);
            }
        }
    }
}
