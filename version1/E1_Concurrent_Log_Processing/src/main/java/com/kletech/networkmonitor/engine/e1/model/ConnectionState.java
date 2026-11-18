package com.kletech.networkmonitor.engine.e1.model;

import java.util.Locale;

/**
 * Documented Zeek connection states ({@code conn_state}) used in {@code conn.log}.
 *
 * <p>Reference: Official Zeek connection state specifications:</p>
 * <ul>
 *   <li>{@link #S0} - Connection attempt seen, no reply.</li>
 *   <li>{@link #S1} - Connection established, not terminated.</li>
 *   <li>{@link #SF} - Normal establishment and termination.</li>
 *   <li>{@link #REJ} - Connection attempt rejected.</li>
 *   <li>{@link #S2} - Connection established and close attempt by originator seen (no responder reply).</li>
 *   <li>{@link #S3} - Connection established and close attempt by responder seen (no originator reply).</li>
 *   <li>{@link #RSTO} - Connection established, originator aborted (sent a RST).</li>
 *   <li>{@link #RSTR} - Established, responder aborted (sent a RST).</li>
 *   <li>{@link #RSTOS0} - Originator sent a SYN followed by a RST; no SYN-ACK seen from responder.</li>
 *   <li>{@link #RSTRH} - Responder sent a SYN-ACK followed by a RST; no SYN seen from originator.</li>
 *   <li>{@link #SH} - Originator sent a SYN followed by a FIN; no SYN-ACK seen from responder.</li>
 *   <li>{@link #SHR} - Responder sent a SYN-ACK followed by a FIN; no SYN seen from originator.</li>
 *   <li>{@link #OTH} - No SYN seen, just midstream traffic (partial connection).</li>
 * </ul>
 */
public enum ConnectionState {
    /**
     * Connection attempt seen, no reply.
     */
    S0,

    /**
     * Connection established, not terminated.
     */
    S1,

    /**
     * Normal establishment and termination.
     */
    SF,

    /**
     * Connection attempt rejected.
     */
    REJ,

    /**
     * Connection established and close attempt by originator seen (no reply from responder).
     */
    S2,

    /**
     * Connection established and close attempt by responder seen (no reply from originator).
     */
    S3,

    /**
     * Connection established, originator aborted (sent a RST).
     */
    RSTO,

    /**
     * Established, responder aborted (sent a RST).
     */
    RSTR,

    /**
     * Originator sent a SYN followed by a RST; no SYN-ACK seen from responder.
     */
    RSTOS0,

    /**
     * Responder sent a SYN-ACK followed by a RST; no SYN seen from originator.
     */
    RSTRH,

    /**
     * Originator sent a SYN followed by a FIN; no SYN-ACK seen from responder.
     */
    SH,

    /**
     * Responder sent a SYN-ACK followed by a FIN; no SYN seen from originator.
     */
    SHR,

    /**
     * No SYN seen, just midstream traffic (partial connection).
     */
    OTH;

    /**
     * Resolves a connection state from its Zeek symbol string (e.g. "S0", "SF", "REJ").
     *
     * <p>Unknown or unsupported states are rejected with {@link IllegalArgumentException}
     * rather than silently misclassified or defaulted.</p>
     *
     * @param value raw connection state string
     * @return matching {@link ConnectionState}
     * @throws IllegalArgumentException if {@code value} is null, blank, or unsupported
     */
    public static ConnectionState fromString(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Connection state must not be null or blank");
        }
        try {
            return ConnectionState.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unsupported or unknown connection state: '" + value + "'", e);
        }
    }
}
