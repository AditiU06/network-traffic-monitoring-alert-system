package com.kletech.networkmonitor.engine.e1.model;

import java.util.Locale;

/**
 * Supported transport-layer and network-layer protocols for Zeek connection processing.
 *
 * <p>Represents the core transport protocols documented in Zeek {@code conn.log}
 * ({@code proto} field): TCP, UDP, and ICMP.</p>
 */
public enum TransportProtocol {
    /**
     * Transmission Control Protocol.
     */
    TCP,

    /**
     * User Datagram Protocol.
     */
    UDP,

    /**
     * Internet Control Message Protocol.
     */
    ICMP;

    /**
     * Resolves a protocol from a string identifier (e.g. "tcp", "udp", "icmp").
     *
     * <p>Matching is case-insensitive. Unknown or unsupported protocols are
     * rejected with {@link IllegalArgumentException} rather than silently
     * misclassified or defaulted.</p>
     *
     * @param value raw protocol string
     * @return matching {@link TransportProtocol}
     * @throws IllegalArgumentException if {@code value} is null, blank, or unsupported
     */
    public static TransportProtocol fromString(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Transport protocol must not be null or blank");
        }
        try {
            return TransportProtocol.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unsupported or unknown transport protocol: '" + value + "'", e);
        }
    }
}
