package com.kletech.networkmonitor.engine.e1.parser;

import com.kletech.networkmonitor.engine.e1.exception.HeaderParseException;
import com.kletech.networkmonitor.engine.e1.validation.InputValidator;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Parses Zeek TSV log header directives dynamically.
 *
 * <p>Validates the input file path using {@link InputValidator} before opening.
 * Reads using UTF-8 and buffered I/O, reading only the header section without
 * loading data records into memory.</p>
 *
 * <p>Enforces Zeek header requirements, decodes escape sequences (e.g. {@code \x09}),
 * validates presence and type counts of {@code #fields} and {@code #types}, and
 * verifies the presence of mandatory connection log fields required by the
 * {@link com.kletech.networkmonitor.engine.e1.model.NetworkEvent} model.</p>
 *
 * <p><strong>Reader positioning and data preservation:</strong> Header parsing stops
 * immediately before consuming the first non-comment data row, leaving the underlying
 * {@link BufferedReader} positioned at index 0 of the first data row.
 * This is accomplished with a 1-character lookahead ({@code mark(1)} / {@code reset()})
 * without buffering data lines into memory or imposing an arbitrary maximum line length.</p>
 *
 * <p><strong>#close directive handling:</strong> In standard Zeek logs, {@code #close} is
 * written as the final line after all data records. Scanning data records to extract
 * a trailing {@code #close} directive would violate the zero-data-I/O contract of header
 * parsing. Thus, {@code closeTime()} is populated only if {@code #close} appears in the
 * initial header block preceding data rows; otherwise, {@code closeTime()} is {@code null}.</p>
 *
 * <p><strong>Unknown metadata directives:</strong> Unrecognized metadata directives
 * (e.g. {@code #zeek_version}) are safely ignored without failing the file or interfering
 * with recognized directives, while mandatory directives and schema rules remain strictly enforced.</p>
 */
public class ZeekHeaderParser {

    /**
     * Mandatory connection log fields required by the NetworkEvent model.
     * All 8 fields must be present in #fields regardless of column order.
     */
    public static final Set<String> REQUIRED_CONN_FIELDS = Set.of(
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "conn_state"
    );

    /**
     * Mandatory header directives that must be present in a valid Zeek log file.
     */
    public static final Set<String> MANDATORY_DIRECTIVES = Set.of(
        "separator", "set_separator", "empty_field", "unset_field", "path", "open", "fields", "types"
    );

    /**
     * All recognized Zeek header directive names.
     */
    public static final Set<String> KNOWN_DIRECTIVES = Set.of(
        "separator", "set_separator", "empty_field", "unset_field", "path", "open", "close", "fields", "types"
    );

    private final InputValidator validator;

    /**
     * Constructs a ZeekHeaderParser with the specified {@link InputValidator}.
     *
     * @param validator pre-ingestion path validator
     */
    public ZeekHeaderParser(InputValidator validator) {
        this.validator = Objects.requireNonNull(validator, "validator must not be null");
    }

    /**
     * Constructs a ZeekHeaderParser with a default validator for the specified permitted root.
     *
     * @param permittedRoot root directory under which input files must reside
     */
    public ZeekHeaderParser(Path permittedRoot) {
        this(new InputValidator(permittedRoot));
    }

    /**
     * Returns the configured input validator.
     *
     * @return input validator
     */
    public InputValidator getValidator() {
        return validator;
    }

    /**
     * Validates and parses a Zeek log header from a file path string.
     *
     * @param rawPath path to the Zeek log file
     * @return parsed immutable {@link ZeekHeader}
     * @throws HeaderParseException if header parsing or schema validation fails
     */
    public ZeekHeader parse(String rawPath) {
        Path validatedPath = validator.validate(rawPath);
        return parseValidatedPath(validatedPath);
    }

    /**
     * Validates and parses a Zeek log header from a {@link Path}.
     *
     * @param path candidate file path
     * @return parsed immutable {@link ZeekHeader}
     * @throws HeaderParseException if header parsing or schema validation fails
     */
    public ZeekHeader parse(Path path) {
        Path validatedPath = validator.validate(path);
        return parseValidatedPath(validatedPath);
    }

    /**
     * Parses a Zeek log header directly from an open {@link BufferedReader}.
     *
     * <p>Useful for streaming sources or in-memory unit tests. Does not perform
     * filesystem path validation.</p>
     *
     * @param reader buffered character reader positioned at the start of the log
     * @return parsed immutable {@link ZeekHeader}
     * @throws HeaderParseException if header directives are malformed, missing, or invalid
     */
    public ZeekHeader parse(BufferedReader reader) {
        Objects.requireNonNull(reader, "reader must not be null");
        return parseReader(reader);
    }

    private ZeekHeader parseValidatedPath(Path path) {
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            return parseReader(reader);
        } catch (HeaderParseException e) {
            throw e;
        } catch (IOException e) {
            throw new HeaderParseException("Failed to read header from input file", e);
        }
    }

    private ZeekHeader parseReader(BufferedReader reader) {
        long lineNumber = 0;
        String separator = null;
        String setSeparator = null;
        String emptyField = null;
        String unsetField = null;
        String logPath = null;
        Instant openTime = null;
        Instant closeTime = null;
        List<String> fields = null;
        List<String> types = null;
        long fieldsLine = -1;
        long typesLine = -1;

        Set<String> seenDirectives = new HashSet<>();

        try {
            while (true) {
                // Peek next character without consuming lines
                reader.mark(1);
                int ch = reader.read();
                if (ch == -1) {
                    break;
                }

                // Consume blank/empty lines between header directives
                if (ch == '\r' || ch == '\n') {
                    reader.reset();
                    reader.readLine();
                    lineNumber++;
                    continue;
                }

                // First non-comment character indicates data rows have begun;
                // leave reader positioned at start of this first data row.
                if (ch != '#') {
                    reader.reset();
                    break;
                }

                // Line starts with '#'. Consume full directive line.
                reader.reset();
                String line = reader.readLine();
                lineNumber++;

                // Skip blank lines
                if (line.isBlank()) {
                    continue;
                }

                // Check for malformed bare '#' or '# '
                if (line.length() <= 1 || Character.isWhitespace(line.charAt(1))) {
                    throw new HeaderParseException("Malformed header directive: missing directive name", lineNumber);
                }

                // Locate delimiter between '#<directive>' and '<value>'
                int delimIdx = -1;
                if (separator != null) {
                    delimIdx = line.indexOf(separator, 1);
                }
                if (delimIdx == -1) {
                    // Fall back to first whitespace character
                    for (int i = 1; i < line.length(); i++) {
                        if (Character.isWhitespace(line.charAt(i))) {
                            delimIdx = i;
                            break;
                        }
                    }
                }

                if (delimIdx == -1) {
                    String candidateDirective = line.substring(1).trim();
                    if (!KNOWN_DIRECTIVES.contains(candidateDirective)) {
                        // Safely ignore unrecognized metadata directive without a value
                        continue;
                    }
                    throw new HeaderParseException("Malformed header directive: missing value for directive", lineNumber);
                }

                String directive = line.substring(1, delimIdx).trim();
                String rawValue = line.substring(delimIdx + (separator != null && line.startsWith(separator, delimIdx) ? separator.length() : 1));

                // Safely ignore unrecognized metadata directives without failing the file
                if (!KNOWN_DIRECTIVES.contains(directive)) {
                    continue;
                }

                if (seenDirectives.contains(directive)) {
                    throw new HeaderParseException("Duplicate header directive: #" + directive, lineNumber);
                }
                seenDirectives.add(directive);

                switch (directive) {
                    case "separator" -> {
                        String trimmed = rawValue.trim();
                        if (trimmed.isEmpty()) {
                            throw new HeaderParseException("Missing value for #separator", lineNumber);
                        }
                        separator = decodeSeparator(trimmed, lineNumber);
                    }
                    case "set_separator" -> {
                        String trimmed = rawValue.trim();
                        if (trimmed.isEmpty()) {
                            throw new HeaderParseException("Missing value for #set_separator", lineNumber);
                        }
                        setSeparator = trimmed;
                    }
                    case "empty_field" -> {
                        String trimmed = rawValue.trim();
                        if (trimmed.isEmpty()) {
                            throw new HeaderParseException("Missing value for #empty_field", lineNumber);
                        }
                        emptyField = trimmed;
                    }
                    case "unset_field" -> {
                        String trimmed = rawValue.trim();
                        if (trimmed.isEmpty()) {
                            throw new HeaderParseException("Missing value for #unset_field", lineNumber);
                        }
                        unsetField = trimmed;
                    }
                    case "path" -> {
                        String trimmed = rawValue.trim();
                        if (trimmed.isEmpty()) {
                            throw new HeaderParseException("Missing value for #path", lineNumber);
                        }
                        logPath = trimmed;
                    }
                    case "open" -> {
                        String trimmed = rawValue.trim();
                        if (trimmed.isEmpty()) {
                            throw new HeaderParseException("Missing value for #open", lineNumber);
                        }
                        try {
                            openTime = parseZeekTimestamp(trimmed);
                        } catch (IllegalArgumentException e) {
                            throw new HeaderParseException("Invalid timestamp format for #open: " + e.getMessage(), lineNumber, e);
                        }
                    }
                    case "close" -> {
                        String trimmed = rawValue.trim();
                        if (trimmed.isEmpty()) {
                            throw new HeaderParseException("Missing value for #close", lineNumber);
                        }
                        try {
                            closeTime = parseZeekTimestamp(trimmed);
                        } catch (IllegalArgumentException e) {
                            throw new HeaderParseException("Invalid timestamp format for #close: " + e.getMessage(), lineNumber, e);
                        }
                    }
                    case "fields" -> {
                        if (separator == null) {
                            throw new HeaderParseException("Directive #fields encountered before #separator declaration", lineNumber);
                        }
                        fieldsLine = lineNumber;
                        fields = parseFieldsList(rawValue, separator, lineNumber);
                    }
                    case "types" -> {
                        if (separator == null) {
                            throw new HeaderParseException("Directive #types encountered before #separator declaration", lineNumber);
                        }
                        typesLine = lineNumber;
                        types = parseTypesList(rawValue, separator, lineNumber);
                    }
                    default -> throw new HeaderParseException("Unhandled directive: #" + directive, lineNumber);
                }
            }
        } catch (IOException e) {
            throw new HeaderParseException("Failed to read header from input stream", lineNumber, e);
        }

        // Validate overall header completeness
        if (seenDirectives.isEmpty()) {
            throw new HeaderParseException("Input file is empty or does not contain a Zeek header");
        }

        for (String mandatory : MANDATORY_DIRECTIVES) {
            if (!seenDirectives.contains(mandatory)) {
                throw new HeaderParseException("Missing mandatory Zeek header directive: #" + mandatory);
            }
        }

        if (fields == null) {
            throw new HeaderParseException("Missing mandatory header directive: #fields");
        }
        if (types == null) {
            throw new HeaderParseException("Missing mandatory header directive: #types");
        }

        if (fields.size() != types.size()) {
            throw new HeaderParseException(
                "Header field count (" + fields.size() + ") does not match type count (" + types.size() + ")",
                typesLine
            );
        }

        // Verify required connection log fields for NetworkEvent
        Set<String> fieldSet = new HashSet<>(fields);
        List<String> missingFields = new ArrayList<>();
        for (String req : REQUIRED_CONN_FIELDS) {
            if (!fieldSet.contains(req)) {
                missingFields.add(req);
            }
        }
        if (!missingFields.isEmpty()) {
            throw new HeaderParseException(
                "Missing required connection log field(s): " + String.join(", ", missingFields),
                fieldsLine
            );
        }

        // Build dynamic O(1) index and type maps
        Map<String, Integer> fieldIndexMap = new LinkedHashMap<>();
        Map<String, String> fieldTypeMap = new LinkedHashMap<>();
        for (int i = 0; i < fields.size(); i++) {
            fieldIndexMap.put(fields.get(i), i);
            fieldTypeMap.put(fields.get(i), types.get(i));
        }

        return new ZeekHeader(
            separator,
            setSeparator,
            emptyField,
            unsetField,
            logPath,
            openTime,
            closeTime,
            fields,
            types,
            fieldIndexMap,
            fieldTypeMap,
            lineNumber
        );
    }

    private List<String> parseFieldsList(String rawValue, String separator, long lineNumber) {
        String[] tokens = rawValue.split(Pattern.quote(separator), -1);
        if (tokens.length == 0 || (tokens.length == 1 && tokens[0].isBlank())) {
            throw new HeaderParseException("Empty #fields directive", lineNumber);
        }

        List<String> list = new ArrayList<>(tokens.length);
        Set<String> seen = new HashSet<>();

        for (String token : tokens) {
            if (token.isBlank()) {
                throw new HeaderParseException("Blank field name in #fields", lineNumber);
            }
            String name = token.trim();
            if (!seen.add(name)) {
                throw new HeaderParseException("Duplicate field name in #fields: '" + name + "'", lineNumber);
            }
            list.add(name);
        }
        return list;
    }

    private List<String> parseTypesList(String rawValue, String separator, long lineNumber) {
        String[] tokens = rawValue.split(Pattern.quote(separator), -1);
        if (tokens.length == 0 || (tokens.length == 1 && tokens[0].isBlank())) {
            throw new HeaderParseException("Empty #types directive", lineNumber);
        }

        List<String> list = new ArrayList<>(tokens.length);
        for (String token : tokens) {
            if (token.isBlank()) {
                throw new HeaderParseException("Blank type name in #types", lineNumber);
            }
            list.add(token.trim());
        }
        return list;
    }

    /**
     * Decodes a Zeek separator declaration, handling hex escapes (e.g. {@code \x09}),
     * unicode escapes (e.g. {@code \u0009}), and character escapes.
     *
     * @param rawValue raw separator string
     * @param lineNumber line number for error reporting
     * @return decoded separator character string
     */
    public static String decodeSeparator(String rawValue, long lineNumber) {
        if (rawValue == null || rawValue.isEmpty()) {
            throw new HeaderParseException("Zeek separator value cannot be empty", lineNumber);
        }

        // Handle \xHH hex escape (e.g. \x09 -> tab)
        if (rawValue.startsWith("\\x") && rawValue.length() >= 4) {
            try {
                int code = Integer.parseInt(rawValue.substring(2, 4), 16);
                return String.valueOf((char) code);
            } catch (NumberFormatException e) {
                throw new HeaderParseException("Invalid hex escape in #separator: " + rawValue, lineNumber, e);
            }
        }

        // Handle \\uXXXX unicode escape
        if (rawValue.startsWith("\\u") && rawValue.length() >= 6) {
            try {
                int code = Integer.parseInt(rawValue.substring(2, 6), 16);
                return String.valueOf((char) code);
            } catch (NumberFormatException e) {
                throw new HeaderParseException("Invalid unicode escape in #separator: " + rawValue, lineNumber, e);
            }
        }

        // Common literal escapes
        if (rawValue.equals("\\t")) return "\t";
        if (rawValue.equals("\\n")) return "\n";
        if (rawValue.equals("\\r")) return "\r";
        if (rawValue.equals("\\s")) return " ";

        return rawValue;
    }

    /**
     * Parses a Zeek header timestamp string (such as {@code 2022-11-28-09-08-17}) into an {@link Instant}.
     *
     * @param rawTimestamp raw timestamp string
     * @return corresponding {@link Instant} in UTC
     * @throws IllegalArgumentException if format is invalid
     */
    public static Instant parseZeekTimestamp(String rawTimestamp) {
        if (rawTimestamp == null || rawTimestamp.isBlank()) {
            throw new IllegalArgumentException("Timestamp string must not be null or blank");
        }

        String trimmed = rawTimestamp.trim();

        // 1. Standard Zeek format: yyyy-MM-dd-HH-mm-ss
        try {
            DateTimeFormatter zeekFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd-HH-mm-ss", Locale.ROOT);
            return LocalDateTime.parse(trimmed, zeekFormatter).toInstant(ZoneOffset.UTC);
        } catch (DateTimeParseException ignored) {
        }

        // 2. ISO-8601 format
        try {
            return Instant.parse(trimmed);
        } catch (DateTimeParseException ignored) {
        }

        // 3. Alternative standard format: yyyy-MM-dd HH:mm:ss
        try {
            DateTimeFormatter altFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.ROOT);
            return LocalDateTime.parse(trimmed, altFormatter).toInstant(ZoneOffset.UTC);
        } catch (DateTimeParseException ignored) {
        }

        throw new IllegalArgumentException("Unsupported timestamp format: '" + trimmed + "'");
    }
}
