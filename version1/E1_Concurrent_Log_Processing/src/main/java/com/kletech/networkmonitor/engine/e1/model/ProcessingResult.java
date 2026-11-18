package com.kletech.networkmonitor.engine.e1.model;

import java.util.Objects;

/**
 * Immutable result of ingesting, parsing, or processing a single Zeek log line.
 *
 * <p>Enforces the invariant that precisely one of {@code event} or {@code errorMessage}
 * is non-null:</p>
 * <ul>
 *   <li>On success: {@code event} is non-null, and {@code errorMessage} is null.</li>
 *   <li>On failure: {@code errorMessage} is non-null, and {@code event} is null.</li>
 * </ul>
 *
 * @param lineNumber    Physical 1-based line number in the source file
 * @param recordOrdinal 0-based data-record ordinal (excluding headers and comments)
 * @param event         Successfully parsed network event; null on failure
 * @param errorMessage  Error message describing failure; null on success
 */
public record ProcessingResult(
    long lineNumber,
    long recordOrdinal,
    NetworkEvent event,
    String errorMessage
) {
    /**
     * Compact constructor enforcing invariants on line numbers, ordinals, and outcomes.
     */
    public ProcessingResult {
        if (lineNumber < 1) {
            throw new IllegalArgumentException(
                "lineNumber must be >= 1 (1-based physical line): " + lineNumber
            );
        }
        if (recordOrdinal < 0) {
            throw new IllegalArgumentException(
                "recordOrdinal must be >= 0 (0-based record ordinal): " + recordOrdinal
            );
        }
        if ((event == null) == (errorMessage == null)) {
            throw new IllegalArgumentException(
                "Precisely one of 'event' or 'errorMessage' must be non-null"
            );
        }
        if (errorMessage != null && errorMessage.isBlank()) {
            throw new IllegalArgumentException("errorMessage must not be blank");
        }
        if (event != null && event.recordOrdinal() != recordOrdinal) {
            throw new IllegalArgumentException(
                "event.recordOrdinal (" + event.recordOrdinal()
                + ") must match ProcessingResult.recordOrdinal (" + recordOrdinal + ")"
            );
        }
    }

    /**
     * Checks if this result represents a successfully parsed event.
     *
     * @return true if an event is present, false otherwise
     */
    public boolean isSuccess() {
        return event != null;
    }

    /**
     * Checks if this result represents a processing failure.
     *
     * @return true if an error message is present, false otherwise
     */
    public boolean isFailure() {
        return errorMessage != null;
    }

    /**
     * Factory method creating a successful processing result.
     *
     * @param lineNumber    1-based physical line number
     * @param recordOrdinal 0-based data-record ordinal
     * @param event         non-null parsed network event
     * @return a successful {@link ProcessingResult}
     */
    public static ProcessingResult success(long lineNumber, long recordOrdinal, NetworkEvent event) {
        Objects.requireNonNull(event, "event must not be null for success result");
        return new ProcessingResult(lineNumber, recordOrdinal, event, null);
    }

    /**
     * Factory method creating a failed processing result.
     *
     * @param lineNumber    1-based physical line number
     * @param recordOrdinal 0-based data-record ordinal
     * @param errorMessage  non-null, non-blank error message
     * @return a failure {@link ProcessingResult}
     */
    public static ProcessingResult failure(long lineNumber, long recordOrdinal, String errorMessage) {
        Objects.requireNonNull(errorMessage, "errorMessage must not be null for failure result");
        return new ProcessingResult(lineNumber, recordOrdinal, null, errorMessage);
    }
}
