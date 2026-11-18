package com.kletech.networkmonitor.engine.e1.parser;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable metadata and schema representation extracted from Zeek log header directives.
 *
 * <p>Preserves all parsed field names and types in their original order while providing
 * O(1) indexed lookups by field name. Supports dynamic column schemas and additional
 * non-standard columns.</p>
 *
 * @param separator        Decoded field separator string (e.g. {@code "\t"})
 * @param setSeparator     Separator string used inside set fields (e.g. {@code ","})
 * @param emptyField       Placeholder string representing an empty container (e.g. {@code "(empty)"})
 * @param unsetField       Placeholder string representing an unset/missing value (e.g. {@code "-"})
 * @param path             Zeek log path identifier (e.g. {@code "conn"})
 * @param openTime         Log opening timestamp as an {@link Instant}
 * @param closeTime        Log closing timestamp as an {@link Instant} if present in the initial
 *                         header section; null for standard Zeek logs where {@code #close} is
 *                         written at the end of the file (header parsing stops before data rows
 *                         and does not scan data records for trailing directives)
 * @param fields           Unmodifiable list of field names in their original order
 * @param types            Unmodifiable list of field types in their original order
 * @param fieldIndexMap    Unmodifiable map from field name to 0-based column index
 * @param fieldTypeMap     Unmodifiable map from field name to its declared Zeek type
 * @param headerLinesCount Physical line count consumed during header parsing (excludes data rows)
 */
public record ZeekHeader(
    String separator,
    String setSeparator,
    String emptyField,
    String unsetField,
    String path,
    Instant openTime,
    Instant closeTime,
    List<String> fields,
    List<String> types,
    Map<String, Integer> fieldIndexMap,
    Map<String, String> fieldTypeMap,
    long headerLinesCount
) {
    public ZeekHeader {
        Objects.requireNonNull(separator, "separator must not be null");
        Objects.requireNonNull(setSeparator, "setSeparator must not be null");
        Objects.requireNonNull(emptyField, "emptyField must not be null");
        Objects.requireNonNull(unsetField, "unsetField must not be null");
        Objects.requireNonNull(path, "path must not be null");
        Objects.requireNonNull(openTime, "openTime must not be null");
        Objects.requireNonNull(fields, "fields must not be null");
        Objects.requireNonNull(types, "types must not be null");
        Objects.requireNonNull(fieldIndexMap, "fieldIndexMap must not be null");
        Objects.requireNonNull(fieldTypeMap, "fieldTypeMap must not be null");

        if (fields.size() != types.size()) {
            throw new IllegalArgumentException(
                "Field count (" + fields.size() + ") must match type count (" + types.size() + ")"
            );
        }

        fields = List.copyOf(fields);
        types = List.copyOf(types);
        fieldIndexMap = Map.copyOf(fieldIndexMap);
        fieldTypeMap = Map.copyOf(fieldTypeMap);
    }

    /**
     * Returns the 0-based column index of the specified field, or -1 if the field is absent.
     *
     * @param fieldName name of the field to look up
     * @return 0-based column index, or -1 if not found
     */
    public int getFieldIndex(String fieldName) {
        return fieldIndexMap.getOrDefault(fieldName, -1);
    }

    /**
     * Returns the declared Zeek type string for the specified field, or null if absent.
     *
     * @param fieldName name of the field to look up
     * @return type string (e.g. {@code "time"}, {@code "string"}, {@code "addr"}), or null
     */
    public String getFieldType(String fieldName) {
        return fieldTypeMap.get(fieldName);
    }

    /**
     * Checks whether the header contains the specified field name.
     *
     * @param fieldName name of the field to check
     * @return true if the field is present in the schema, false otherwise
     */
    public boolean hasField(String fieldName) {
        return fieldIndexMap.containsKey(fieldName);
    }

    /**
     * Returns the total number of fields declared in the header.
     *
     * @return total field count
     */
    public int fieldCount() {
        return fields.size();
    }

    /**
     * Checks whether the given raw token matches the declared unset field placeholder.
     *
     * @param token token to check
     * @return true if token equals unsetField (typically {@code "-"}), false otherwise
     */
    public boolean isUnset(String token) {
        return unsetField.equals(token);
    }

    /**
     * Checks whether the given raw token matches the declared empty field placeholder.
     *
     * @param token token to check
     * @return true if token equals emptyField (typically {@code "(empty)"}), false otherwise
     */
    public boolean isEmpty(String token) {
        return emptyField.equals(token);
    }
}
