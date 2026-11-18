package com.kletech.networkmonitor.engine.e1.parser;

import com.kletech.networkmonitor.engine.e1.exception.RecordParseException;
import com.kletech.networkmonitor.engine.e1.model.ConnectionState;
import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.TransportProtocol;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Parses individual Zeek {@code conn.log} data rows into immutable {@link NetworkEvent} instances.
 *
 * <p><strong>Key Design Principles:</strong></p>
 * <ul>
 *   <li><strong>Dynamic Schema Awareness:</strong> Uses {@link ZeekHeader#getFieldIndex(String)}
 *       for every field lookup; never hardcodes column positions.</li>
 *   <li><strong>Precision Timekeeping:</strong> Parses decimal epoch timestamps without floating-point
 *       precision loss by splitting whole seconds and fractional nanoseconds directly.</li>
 *   <li><strong>Zero DNS Lookups:</strong> Parses IPv4 and IPv6 literals into raw byte arrays and
 *       constructs {@link InetAddress} without issuing network DNS queries.</li>
 *   <li><strong>Defensive Parsing:</strong> Preserves trailing columns via limit {@code -1} splits,
 *       handles absent optional columns gracefully, and throws descriptive {@link RecordParseException}
 *       without exposing raw input line contents in error messages.</li>
 * </ul>
 */
public class ZeekRecordParser {

    private static final ZeekRecordParser INSTANCE = new ZeekRecordParser();

    /**
     * Constructs a default ZeekRecordParser.
     */
    public ZeekRecordParser() {
    }

    /**
     * Static convenience method delegating to the singleton parser instance.
     *
     * @param header        parsed Zeek log header containing schema metadata
     * @param rawLine       raw connection data row string
     * @param recordOrdinal 0-based data-record index
     * @return validated immutable {@link NetworkEvent}
     * @throws RecordParseException     if the row is malformed, field count mismatches, or values are invalid
     * @throws IllegalArgumentException if recordOrdinal is negative
     */
    public static NetworkEvent parseRecord(ZeekHeader header, String rawLine, long recordOrdinal) {
        return INSTANCE.parse(header, rawLine, recordOrdinal);
    }

    /**
     * Parses a single Zeek connection data line into an immutable {@link NetworkEvent}.
     *
     * @param header        parsed Zeek log header containing schema metadata
     * @param rawLine       raw connection data row string
     * @param recordOrdinal 0-based data-record index
     * @return validated immutable {@link NetworkEvent}
     * @throws RecordParseException     if the row is malformed, field count mismatches, or values are invalid
     * @throws IllegalArgumentException if recordOrdinal is negative
     */
    public NetworkEvent parse(ZeekHeader header, String rawLine, long recordOrdinal) {
        if (recordOrdinal < 0) {
            throw new IllegalArgumentException("recordOrdinal must be non-negative: " + recordOrdinal);
        }
        Objects.requireNonNull(header, "header must not be null");

        if (rawLine == null) {
            throw new RecordParseException("Raw data row must not be null", recordOrdinal);
        }
        if (rawLine.isBlank()) {
            throw new RecordParseException("Raw data row must not be blank", recordOrdinal);
        }
        if (rawLine.startsWith("#")) {
            throw new RecordParseException("Comment line cannot be parsed as a data record", recordOrdinal);
        }

        // Preserve trailing empty or unset columns with -1 limit
        String separator = header.separator();
        String[] tokens = rawLine.split(Pattern.quote(separator), -1);

        if (tokens.length != header.fieldCount()) {
            throw new RecordParseException(
                "Data row token count (" + tokens.length + ") does not match header field count ("
                + header.fieldCount() + ")",
                recordOrdinal
            );
        }

        // 1. Mandatory timestamp (ts)
        Instant timestamp = parseTimestampField(header, tokens, recordOrdinal);

        // 2. Mandatory connection UID (uid)
        String uid = parseStringMandatoryField(header, tokens, "uid", recordOrdinal);

        // 3. Mandatory source IP (id.orig_h)
        InetAddress sourceAddress = parseIpField(header, tokens, "id.orig_h", recordOrdinal);

        // 4. Source port (id.orig_p) - nullable for ICMP or unset data
        Integer sourcePort = parsePortField(header, tokens, "id.orig_p", recordOrdinal);

        // 5. Mandatory destination IP (id.resp_h)
        InetAddress destinationAddress = parseIpField(header, tokens, "id.resp_h", recordOrdinal);

        // 6. Destination port (id.resp_p) - nullable for ICMP or unset data
        Integer destinationPort = parsePortField(header, tokens, "id.resp_p", recordOrdinal);

        // 7. Mandatory protocol (proto)
        TransportProtocol protocol = parseProtocolField(header, tokens, recordOrdinal);

        // 8. Optional service (service)
        String service = parseOptionalStringField(header, tokens, "service");

        // 9. Optional duration (duration)
        Double duration = parseDurationField(header, tokens, recordOrdinal);

        // 10. Optional originator bytes (orig_bytes)
        Long origBytes = parseCountField(header, tokens, "orig_bytes", recordOrdinal);

        // 11. Optional responder bytes (resp_bytes)
        Long respBytes = parseCountField(header, tokens, "resp_bytes", recordOrdinal);

        // 12. Mandatory connection state (conn_state)
        ConnectionState connectionState = parseConnectionStateField(header, tokens, recordOrdinal);

        // 13. Optional connection history (history)
        String history = parseOptionalStringField(header, tokens, "history");

        // 14. Optional originator packet count (orig_pkts)
        Long origPkts = parseCountField(header, tokens, "orig_pkts", recordOrdinal);

        // 15. Optional responder packet count (resp_pkts)
        Long respPkts = parseCountField(header, tokens, "resp_pkts", recordOrdinal);

        try {
            return new NetworkEvent(
                recordOrdinal,
                timestamp,
                uid,
                sourceAddress,
                sourcePort,
                destinationAddress,
                destinationPort,
                protocol,
                service,
                duration,
                origBytes,
                respBytes,
                connectionState,
                history,
                origPkts,
                respPkts
            );
        } catch (IllegalArgumentException e) {
            throw new RecordParseException("NetworkEvent constraint validation failed: " + e.getMessage(), recordOrdinal, e);
        }
    }

    private Instant parseTimestampField(ZeekHeader header, String[] tokens, long recordOrdinal) {
        int idx = header.getFieldIndex("ts");
        if (idx == -1) {
            throw new RecordParseException("Required field 'ts' is missing from header schema", recordOrdinal);
        }
        String token = tokens[idx];
        if (header.isUnset(token) || token.isBlank()) {
            throw new RecordParseException("Required field 'ts' cannot be unset or blank", recordOrdinal);
        }
        try {
            return parseEpochTimestamp(token);
        } catch (IllegalArgumentException e) {
            throw new RecordParseException("Invalid or malformed epoch timestamp in field 'ts'", recordOrdinal, e);
        }
    }

    private String parseStringMandatoryField(ZeekHeader header, String[] tokens, String fieldName, long recordOrdinal) {
        int idx = header.getFieldIndex(fieldName);
        if (idx == -1) {
            throw new RecordParseException("Required field '" + fieldName + "' is missing from header schema", recordOrdinal);
        }
        String token = tokens[idx];
        if (header.isUnset(token) || token.isBlank()) {
            throw new RecordParseException("Required field '" + fieldName + "' cannot be unset or blank", recordOrdinal);
        }
        return token.trim();
    }

    private InetAddress parseIpField(ZeekHeader header, String[] tokens, String fieldName, long recordOrdinal) {
        int idx = header.getFieldIndex(fieldName);
        if (idx == -1) {
            throw new RecordParseException("Required field '" + fieldName + "' is missing from header schema", recordOrdinal);
        }
        String token = tokens[idx];
        if (header.isUnset(token) || token.isBlank()) {
            throw new RecordParseException("Required field '" + fieldName + "' cannot be unset or blank", recordOrdinal);
        }
        return parseIpLiteral(token, fieldName, recordOrdinal);
    }

    private Integer parsePortField(ZeekHeader header, String[] tokens, String fieldName, long recordOrdinal) {
        int idx = header.getFieldIndex(fieldName);
        if (idx == -1) {
            return null;
        }
        String token = tokens[idx];
        if (header.isUnset(token) || header.isEmpty(token) || token.isBlank()) {
            return null;
        }
        int port;
        try {
            port = Integer.parseInt(token.trim());
        } catch (NumberFormatException e) {
            throw new RecordParseException("Invalid port number in field '" + fieldName + "': not a valid integer", recordOrdinal, e);
        }
        if (port < NetworkEvent.MIN_PORT || port > NetworkEvent.MAX_PORT) {
            throw new RecordParseException("Port number in field '" + fieldName + "' out of range [0, 65535]", recordOrdinal);
        }
        return port;
    }

    private TransportProtocol parseProtocolField(ZeekHeader header, String[] tokens, long recordOrdinal) {
        int idx = header.getFieldIndex("proto");
        if (idx == -1) {
            throw new RecordParseException("Required field 'proto' is missing from header schema", recordOrdinal);
        }
        String token = tokens[idx];
        if (header.isUnset(token) || token.isBlank()) {
            throw new RecordParseException("Required field 'proto' cannot be unset or blank", recordOrdinal);
        }
        try {
            return TransportProtocol.fromString(token);
        } catch (IllegalArgumentException e) {
            throw new RecordParseException("Unsupported or unknown transport protocol in field 'proto'", recordOrdinal, e);
        }
    }

    private ConnectionState parseConnectionStateField(ZeekHeader header, String[] tokens, long recordOrdinal) {
        int idx = header.getFieldIndex("conn_state");
        if (idx == -1) {
            throw new RecordParseException("Required field 'conn_state' is missing from header schema", recordOrdinal);
        }
        String token = tokens[idx];
        if (header.isUnset(token) || token.isBlank()) {
            throw new RecordParseException("Required field 'conn_state' cannot be unset or blank", recordOrdinal);
        }
        try {
            return ConnectionState.fromString(token);
        } catch (IllegalArgumentException e) {
            throw new RecordParseException("Unsupported or unknown connection state in field 'conn_state'", recordOrdinal, e);
        }
    }

    private String parseOptionalStringField(ZeekHeader header, String[] tokens, String fieldName) {
        int idx = header.getFieldIndex(fieldName);
        if (idx == -1) {
            return null;
        }
        String token = tokens[idx];
        if (header.isUnset(token) || header.isEmpty(token) || token.isBlank()) {
            return null;
        }
        return token.trim();
    }

    private Double parseDurationField(ZeekHeader header, String[] tokens, long recordOrdinal) {
        int idx = header.getFieldIndex("duration");
        if (idx == -1) {
            return null;
        }
        String token = tokens[idx];
        if (header.isUnset(token) || header.isEmpty(token) || token.isBlank()) {
            return null;
        }
        try {
            double d = Double.parseDouble(token.trim());
            if (!Double.isFinite(d) || d < 0.0) {
                throw new RecordParseException("Duration in field 'duration' must be a finite, non-negative number", recordOrdinal);
            }
            return d;
        } catch (NumberFormatException e) {
            throw new RecordParseException("Invalid duration format in field 'duration'", recordOrdinal, e);
        }
    }

    private Long parseCountField(ZeekHeader header, String[] tokens, String fieldName, long recordOrdinal) {
        int idx = header.getFieldIndex(fieldName);
        if (idx == -1) {
            return null;
        }
        String token = tokens[idx];
        if (header.isUnset(token) || header.isEmpty(token) || token.isBlank()) {
            return null;
        }
        try {
            long count = Long.parseLong(token.trim());
            if (count < 0) {
                throw new RecordParseException("Count value in field '" + fieldName + "' must not be negative", recordOrdinal);
            }
            return count;
        } catch (NumberFormatException e) {
            throw new RecordParseException("Invalid count format in field '" + fieldName + "'", recordOrdinal, e);
        }
    }

    /**
     * Parses a decimal Zeek epoch timestamp (e.g. {@code "1537522822.965530"}) accurately
     * without floating-point precision loss.
     *
     * @param rawTs timestamp string
     * @return equivalent {@link Instant}
     * @throws IllegalArgumentException if format is invalid or seconds are negative
     */
    public static Instant parseEpochTimestamp(String rawTs) {
        if (rawTs == null || rawTs.isBlank()) {
            throw new IllegalArgumentException("Timestamp string must not be null or blank");
        }
        String trimmed = rawTs.trim();
        int dotIndex = trimmed.indexOf('.');

        long seconds;
        long nanos = 0;

        if (dotIndex == -1) {
            try {
                seconds = Long.parseLong(trimmed);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid epoch seconds: " + trimmed, e);
            }
        } else {
            String secPart = trimmed.substring(0, dotIndex);
            String fracPart = trimmed.substring(dotIndex + 1);

            if (secPart.isEmpty() || fracPart.isEmpty()) {
                throw new IllegalArgumentException("Invalid decimal timestamp format");
            }
            try {
                seconds = Long.parseLong(secPart);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid epoch seconds: " + secPart, e);
            }

            // Pad or truncate to exactly 9 digits (nanoseconds)
            if (fracPart.length() > 9) {
                fracPart = fracPart.substring(0, 9);
            }
            StringBuilder sb = new StringBuilder(fracPart);
            while (sb.length() < 9) {
                sb.append('0');
            }
            try {
                nanos = Long.parseLong(sb.toString());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid fractional seconds: " + fracPart, e);
            }
        }

        if (seconds < 0 || nanos < 0) {
            throw new IllegalArgumentException("Timestamp values must not be negative");
        }

        return Instant.ofEpochSecond(seconds, nanos);
    }

    /**
     * Parses an IPv4 or IPv6 string literal into an {@link InetAddress} without performing DNS queries.
     *
     * @param ipStr         raw IP literal string
     * @param fieldName     field name for error reporting
     * @param recordOrdinal record ordinal for error reporting
     * @return parsed {@link InetAddress}
     * @throws RecordParseException if IP literal format is malformed or invalid
     */
    public static InetAddress parseIpLiteral(String ipStr, String fieldName, long recordOrdinal) {
        if (ipStr == null || ipStr.isBlank()) {
            throw new RecordParseException("IP address in field '" + fieldName + "' must not be null or blank", recordOrdinal);
        }
        String trimmed = ipStr.trim();
        byte[] bytes = parseIpv4Literal(trimmed);
        if (bytes == null) {
            bytes = parseIpv6Literal(trimmed);
        }
        if (bytes == null) {
            throw new RecordParseException("Invalid or malformed IP address in field '" + fieldName + "'", recordOrdinal);
        }
        try {
            return InetAddress.getByAddress(bytes);
        } catch (UnknownHostException e) {
            throw new RecordParseException("Failed to instantiate IP address in field '" + fieldName + "'", recordOrdinal, e);
        }
    }

    private static byte[] parseIpv4Literal(String src) {
        if (src == null || src.isEmpty()) {
            return null;
        }
        int dotCount = 0;
        for (int i = 0; i < src.length(); i++) {
            char c = src.charAt(i);
            if (c == '.') {
                dotCount++;
            } else if (c < '0' || c > '9') {
                return null;
            }
        }
        if (dotCount != 3) {
            return null;
        }

        String[] parts = src.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }

        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (p.isEmpty() || p.length() > 3) {
                return null;
            }
            if (p.length() > 1 && p.charAt(0) == '0') {
                return null; // Reject leading zeros
            }
            int val = 0;
            for (int j = 0; j < p.length(); j++) {
                val = val * 10 + (p.charAt(j) - '0');
            }
            if (val > 255) {
                return null;
            }
            bytes[i] = (byte) val;
        }
        return bytes;
    }

    private static byte[] parseIpv6Literal(String src) {
        if (src == null || src.isEmpty()) {
            return null;
        }

        if (src.contains(":::")) {
            return null;
        }

        int firstDbl = src.indexOf("::");
        boolean hasDoubleColon = (firstDbl != -1);
        if (hasDoubleColon && src.indexOf("::", firstDbl + 2) != -1) {
            return null; // More than one "::" is invalid
        }

        int colonCount = 0;
        for (int i = 0; i < src.length(); i++) {
            char c = src.charAt(i);
            if (c == ':') {
                colonCount++;
            } else if (!isHexDigit(c) && c != '.') {
                return null;
            }
        }

        if (colonCount < 2) {
            return null;
        }

        // Handle embedded IPv4 at the end (e.g. ::ffff:192.168.1.1)
        int lastColon = src.lastIndexOf(':');
        String ipv4Part = null;
        if (src.indexOf('.', lastColon) != -1) {
            ipv4Part = src.substring(lastColon + 1);
            src = src.substring(0, lastColon + 1);
        }

        byte[] ipv4Bytes = null;
        if (ipv4Part != null) {
            ipv4Bytes = parseIpv4Literal(ipv4Part);
            if (ipv4Bytes == null) {
                return null;
            }
        }

        int targetGroups = ipv4Bytes != null ? 6 : 8;
        String[] parts;

        if (hasDoubleColon) {
            int dblIdx = src.indexOf("::");
            String left = src.substring(0, dblIdx);
            String right = src.substring(dblIdx + 2);

            String[] leftTokens = left.isEmpty() ? new String[0] : left.split(":", -1);
            String[] rightTokens = right.isEmpty() ? new String[0] : right.split(":", -1);

            int totalExplicit = leftTokens.length + rightTokens.length;
            if (totalExplicit >= targetGroups) {
                return null;
            }

            int zeroGroupsToInsert = targetGroups - totalExplicit;
            parts = new String[targetGroups];
            int p = 0;
            for (String t : leftTokens) {
                if (t.isEmpty()) {
                    return null;
                }
                parts[p++] = t;
            }
            for (int i = 0; i < zeroGroupsToInsert; i++) {
                parts[p++] = "0";
            }
            for (String t : rightTokens) {
                if (t.isEmpty()) {
                    return null;
                }
                parts[p++] = t;
            }
        } else {
            parts = src.split(":", -1);
            if (parts.length != targetGroups) {
                return null;
            }
        }

        byte[] bytes = new byte[16];
        for (int i = 0; i < targetGroups; i++) {
            String token = parts[i];
            if (token == null || token.isEmpty() || token.length() > 4) {
                return null;
            }
            int val;
            try {
                val = Integer.parseInt(token, 16);
            } catch (NumberFormatException e) {
                return null;
            }
            if (val < 0 || val > 0xFFFF) {
                return null;
            }
            bytes[i * 2] = (byte) ((val >> 8) & 0xFF);
            bytes[i * 2 + 1] = (byte) (val & 0xFF);
        }

        if (ipv4Bytes != null) {
            System.arraycopy(ipv4Bytes, 0, bytes, 12, 4);
        }

        return bytes;
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') ||
               (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    }
}
