package com.kletech.networkmonitor.engine.e1.exception;

/**
 * Thrown when an input path or file fails pre-ingestion validation checks
 * (e.g. path traversal, nonexistent file, unreadable file, size limit exceeded).
 */
public class ValidationException extends RuntimeException {

    public ValidationException(String message) {
        super(message);
    }

    public ValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
