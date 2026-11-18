package com.kletech.networkmonitor.engine.e1.exception;

/**
 * Thrown when Zeek log header parsing fails due to missing directives,
 * malformed headers, invalid timestamps, or missing required fields.
 */
public class HeaderParseException extends ValidationException {

    private final Long lineNumber;

    public HeaderParseException(String message) {
        super(message);
        this.lineNumber = null;
    }

    public HeaderParseException(String message, long lineNumber) {
        super(message + " (line " + lineNumber + ")");
        this.lineNumber = lineNumber;
    }

    public HeaderParseException(String message, Throwable cause) {
        super(message, cause);
        this.lineNumber = null;
    }

    public HeaderParseException(String message, long lineNumber, Throwable cause) {
        super(message + " (line " + lineNumber + ")", cause);
        this.lineNumber = lineNumber;
    }

    /**
     * Returns the 1-based physical line number where the header parse error occurred,
     * or null if the error is not associated with a specific line (e.g. empty file).
     *
     * @return 1-based physical line number or null
     */
    public Long getLineNumber() {
        return lineNumber;
    }
}
