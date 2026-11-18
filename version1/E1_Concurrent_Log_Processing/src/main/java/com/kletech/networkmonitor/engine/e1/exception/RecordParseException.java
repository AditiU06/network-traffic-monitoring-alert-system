package com.kletech.networkmonitor.engine.e1.exception;

/**
 * Thrown when an individual Zeek connection data record fails parsing due to
 * column count mismatch, invalid IP syntax, unparseable timestamp, illegal port numbers,
 * unknown protocol, or constraint violations.
 */
public class RecordParseException extends ValidationException {

    private final Long recordOrdinal;

    public RecordParseException(String message) {
        super(message);
        this.recordOrdinal = null;
    }

    public RecordParseException(String message, long recordOrdinal) {
        super(message + " (record ordinal " + recordOrdinal + ")");
        this.recordOrdinal = recordOrdinal;
    }

    public RecordParseException(String message, Throwable cause) {
        super(message, cause);
        this.recordOrdinal = null;
    }

    public RecordParseException(String message, long recordOrdinal, Throwable cause) {
        super(message + " (record ordinal " + recordOrdinal + ")", cause);
        this.recordOrdinal = recordOrdinal;
    }

    /**
     * Returns the 0-based record ordinal where the parse error occurred,
     * or null if the error is not associated with a specific ordinal.
     *
     * @return 0-based record ordinal or null
     */
    public Long getRecordOrdinal() {
        return recordOrdinal;
    }
}
