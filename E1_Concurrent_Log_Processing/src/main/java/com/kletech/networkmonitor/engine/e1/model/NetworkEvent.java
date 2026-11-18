package com.kletech.networkmonitor.engine.e1.model;

import java.net.InetAddress;
import java.time.Instant;
import java.util.Objects;

/**
 * Immutable representation of a normalized Zeek network connection event (from {@code conn.log}).
 *
 * <p>Represents Network (L3) and Transport (L4) layer connection information.
 * All fields are immutable and validated at construction.</p>
 *
 * @param recordOrdinal      0-based ordinal of the data record in the source stream (for deterministic ordering)
 * @param timestamp          Timestamp of the connection start (Zeek {@code ts})
 * @param uid                Unique Zeek connection identifier (Zeek {@code uid})
 * @param sourceAddress      Source/originator IP address (IPv4 or IPv6) (Zeek {@code id.orig_h})
 * @param sourcePort         Source/originator port; nullable for protocols without ports (e.g. ICMP) or missing data (Zeek {@code id.orig_p})
 * @param destinationAddress Destination/responder IP address (IPv4 or IPv6) (Zeek {@code id.resp_h})
 * @param destinationPort    Destination/responder port; nullable for protocols without ports (e.g. ICMP) or missing data (Zeek {@code id.resp_p})
 * @param protocol           Transport-layer protocol: TCP, UDP, or ICMP (Zeek {@code proto})
 * @param service            Application-level service identifier if detected by Zeek; nullable if missing (Zeek {@code service})
 * @param duration           Connection duration in seconds; nullable if missing or connection incomplete (Zeek {@code duration})
 * @param origBytes          Originator payload byte count; nullable if missing or unknown (Zeek {@code orig_bytes})
 * @param respBytes          Responder payload byte count; nullable if missing or unknown (Zeek {@code resp_bytes})
 * @param connectionState    Connection state summary (Zeek {@code conn_state})
 * @param history            Connection state history flags; nullable if missing (Zeek {@code history})
 * @param origPkts           Originator packet count; nullable if missing (Zeek {@code orig_pkts})
 * @param respPkts           Responder packet count; nullable if missing (Zeek {@code resp_pkts})
 */
public record NetworkEvent(
    long recordOrdinal,
    Instant timestamp,
    String uid,
    InetAddress sourceAddress,
    Integer sourcePort,
    InetAddress destinationAddress,
    Integer destinationPort,
    TransportProtocol protocol,
    String service,
    Double duration,
    Long origBytes,
    Long respBytes,
    ConnectionState connectionState,
    String history,
    Long origPkts,
    Long respPkts
) {
    /**
     * Minimum valid port number for transport-layer endpoints.
     */
    public static final int MIN_PORT = 0;

    /**
     * Maximum valid port number for transport-layer endpoints.
     */
    public static final int MAX_PORT = 65535;

    /**
     * Compact constructor validating required fields, ranges, and invariants.
     */
    public NetworkEvent {
        if (recordOrdinal < 0) {
            throw new IllegalArgumentException("recordOrdinal must be non-negative: " + recordOrdinal);
        }
        Objects.requireNonNull(timestamp, "timestamp must not be null");
        Objects.requireNonNull(uid, "uid must not be null");
        if (uid.isBlank()) {
            throw new IllegalArgumentException("uid must not be blank");
        }
        Objects.requireNonNull(sourceAddress, "sourceAddress must not be null");
        Objects.requireNonNull(destinationAddress, "destinationAddress must not be null");
        Objects.requireNonNull(protocol, "protocol must not be null");
        Objects.requireNonNull(connectionState, "connectionState must not be null");

        validatePort("sourcePort", sourcePort);
        validatePort("destinationPort", destinationPort);

        if (duration != null) {
            if (!Double.isFinite(duration)) {
                throw new IllegalArgumentException("duration must be a finite number: " + duration);
            }
            if (duration < 0.0) {
                throw new IllegalArgumentException("duration must not be negative: " + duration);
            }
        }

        validateNonNegative("origBytes", origBytes);
        validateNonNegative("respBytes", respBytes);
        validateNonNegative("origPkts", origPkts);
        validateNonNegative("respPkts", respPkts);
    }

    private static void validatePort(String fieldName, Integer port) {
        if (port != null && (port < MIN_PORT || port > MAX_PORT)) {
            throw new IllegalArgumentException(
                fieldName + " must be between " + MIN_PORT + " and " + MAX_PORT + ": " + port
            );
        }
    }

    private static void validateNonNegative(String fieldName, Long value) {
        if (value != null && value < 0) {
            throw new IllegalArgumentException(fieldName + " must not be negative: " + value);
        }
    }
}
