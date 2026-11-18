package com.kletech.networkmonitor.engine.e1.validation;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Structured, immutable result of an input path validation check.
 *
 * <p>Enforces the invariant that precisely one of {@code validatedPath} or
 * {@code errorMessage} is present based on {@code isValid}:</p>
 * <ul>
 *   <li>When {@code isValid} is true: {@code validatedPath} is non-null, and {@code errorMessage} is null.</li>
 *   <li>When {@code isValid} is false: {@code errorMessage} is non-null and non-blank, and {@code validatedPath} is null.</li>
 * </ul>
 *
 * @param isValid       true if the input path is valid and safe for ingestion
 * @param validatedPath the normalized, verified absolute path on success; null on failure
 * @param errorMessage  sanitized error description on failure; null on success
 */
public record ValidationResult(
    boolean isValid,
    Path validatedPath,
    String errorMessage
) {
    public ValidationResult {
        if (isValid) {
            Objects.requireNonNull(validatedPath, "validatedPath must not be null when isValid is true");
            if (errorMessage != null) {
                throw new IllegalArgumentException("errorMessage must be null when isValid is true");
            }
        } else {
            Objects.requireNonNull(errorMessage, "errorMessage must not be null when isValid is false");
            if (errorMessage.isBlank()) {
                throw new IllegalArgumentException("errorMessage must not be blank when isValid is false");
            }
            if (validatedPath != null) {
                throw new IllegalArgumentException("validatedPath must be null when isValid is false");
            }
        }
    }

    /**
     * Creates a successful validation result with the verified path.
     *
     * @param validatedPath non-null verified canonical path
     * @return successful {@link ValidationResult}
     */
    public static ValidationResult success(Path validatedPath) {
        return new ValidationResult(true, validatedPath, null);
    }

    /**
     * Creates a failed validation result with a sanitized error message.
     *
     * @param errorMessage non-null, non-blank error message
     * @return failure {@link ValidationResult}
     */
    public static ValidationResult failure(String errorMessage) {
        return new ValidationResult(false, null, errorMessage);
    }
}
