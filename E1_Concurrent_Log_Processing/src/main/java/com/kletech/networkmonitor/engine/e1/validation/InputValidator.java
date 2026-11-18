package com.kletech.networkmonitor.engine.e1.validation;

import com.kletech.networkmonitor.engine.e1.exception.ValidationException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;

/**
 * Validates user-supplied Zeek log file paths prior to ingestion.
 *
 * <p>Enforces filesystem security constraints, path traversal prevention, file-type
 * verification, readability checks, and configurable file-size limits.</p>
 *
 * <p>This component is completely independent of Spring and performs pre-ingestion
 * filesystem security checks without reading file contents into memory.</p>
 */
public class InputValidator {

    /**
     * Default maximum permitted input file size: 1 GB (1,073,741,824 bytes).
     *
     * <p>Generously supports multi-million record Zeek logs (Gate 1 500k-record logs
     * are ~60 MB) while guarding against resource exhaustion or disk-filling attacks.</p>
     */
    public static final long DEFAULT_MAX_FILE_SIZE_BYTES = 1024L * 1024L * 1024L;

    /**
     * Generic safe error message used when an unexpected exception occurs during safe validation.
     */
    public static final String UNEXPECTED_ERROR_MESSAGE = "An unexpected error occurred during path validation";

    private final Path canonicalRoot;
    private final long maxFileSizeBytes;

    /**
     * Constructs an InputValidator with the specified permitted directory root
     * and default maximum file size limit (1 GB).
     *
     * @param permittedRoot root directory under which input files must reside
     * @throws IllegalArgumentException if permittedRoot is null, does not exist,
     *                                  is not a directory, or fails canonical resolution
     */
    public InputValidator(Path permittedRoot) {
        this(permittedRoot, DEFAULT_MAX_FILE_SIZE_BYTES);
    }

    /**
     * Constructs an InputValidator with full configuration.
     *
     * @param permittedRoot    root directory under which input files must reside
     * @param maxFileSizeBytes maximum permitted file size in bytes (must be positive)
     * @throws IllegalArgumentException if permittedRoot is null, does not exist,
     *                                  is not a directory, fails canonical resolution,
     *                                  or if maxFileSizeBytes is not positive
     */
    public InputValidator(Path permittedRoot, long maxFileSizeBytes) {
        if (permittedRoot == null) {
            throw new IllegalArgumentException("permittedRoot must not be null");
        }
        if (!Files.exists(permittedRoot)) {
            throw new IllegalArgumentException("Permitted root directory does not exist: " + permittedRoot);
        }
        if (!Files.isDirectory(permittedRoot)) {
            throw new IllegalArgumentException("Permitted root must be a directory: " + permittedRoot);
        }
        try {
            this.canonicalRoot = permittedRoot.toRealPath();
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to resolve canonical path for permitted root: " + permittedRoot, e);
        }

        if (maxFileSizeBytes <= 0) {
            throw new IllegalArgumentException("maxFileSizeBytes must be positive: " + maxFileSizeBytes);
        }
        this.maxFileSizeBytes = maxFileSizeBytes;
    }

    /**
     * Returns the verified canonical permitted root directory.
     *
     * @return canonical permitted root directory
     */
    public Path getPermittedRoot() {
        return canonicalRoot;
    }

    /**
     * Returns the configured maximum file size in bytes.
     *
     * @return maximum file size in bytes
     */
    public long getMaxFileSizeBytes() {
        return maxFileSizeBytes;
    }

    /**
     * Validates a user-supplied raw path string.
     *
     * @param rawPath string path provided by user or caller
     * @return verified, canonical {@link Path}
     * @throws ValidationException if the path is invalid, unsafe, or fails any check
     */
    public Path validate(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            throw new ValidationException("Input path must not be null or blank");
        }
        try {
            return validate(Path.of(rawPath));
        } catch (InvalidPathException e) {
            throw new ValidationException("Input path is malformed: invalid path syntax", e);
        }
    }

    /**
     * Validates a candidate {@link Path}.
     *
     * @param candidatePath path to validate
     * @return verified, canonical {@link Path}
     * @throws ValidationException if the path is invalid, unsafe, or fails any check
     */
    public Path validate(Path candidatePath) {
        if (candidatePath == null || candidatePath.toString().isBlank()) {
            throw new ValidationException("Input path must not be null or blank");
        }

        Path resolved;
        try {
            if (candidatePath.isAbsolute()) {
                resolved = candidatePath.normalize();
            } else {
                resolved = canonicalRoot.resolve(candidatePath).normalize();
            }
        } catch (InvalidPathException e) {
            throw new ValidationException("Input path is malformed: invalid path syntax", e);
        }

        // 1. Syntactic containment check against canonicalRoot before calling Files.exists().
        //    On Windows, absolute paths may contain short-name aliases (e.g., ADITIU~1)
        //    that differ textually from the long-form canonical root. When the normalized
        //    path does not match syntactically but exists on disk, resolve through
        //    toRealPath() to obtain the canonical long-name form before rejecting.
        if (!resolved.startsWith(canonicalRoot)) {
            if (candidatePath.isAbsolute() && Files.exists(resolved)) {
                // Attempt canonical resolution to handle Windows short-name aliases.
                try {
                    resolved = resolved.toRealPath();
                } catch (IOException e) {
                    throw new ValidationException("Failed to access path: " + sanitize(candidatePath), e);
                }
                // Re-check containment with the canonicalized path.
                if (!resolved.startsWith(canonicalRoot)) {
                    throw new ValidationException("Access denied: path is outside permitted input directory");
                }
            } else {
                throw new ValidationException("Access denied: path is outside permitted input directory");
            }
        }

        // 2. Existence verification
        if (!Files.exists(resolved)) {
            throw new ValidationException("Input file does not exist: " + sanitize(resolved));
        }

        // 3. Canonical real path resolution (resolves symlinks)
        Path realPath;
        try {
            realPath = resolved.toRealPath();
        } catch (IOException e) {
            throw new ValidationException("Failed to access path: " + sanitize(resolved), e);
        }

        // 4. Canonical containment check for symbolic-link escape prevention
        if (!realPath.startsWith(canonicalRoot)) {
            throw new ValidationException("Access denied: symbolic link points outside permitted directory");
        }

        // 5. Regular file verification (rejects directories, devices, sockets, pipes)
        if (Files.isDirectory(realPath)) {
            throw new ValidationException("Input path is a directory, not a regular file: " + sanitize(resolved));
        }
        if (!Files.isRegularFile(realPath)) {
            throw new ValidationException("Input path is not a regular file: " + sanitize(resolved));
        }

        // 6. Readability verification
        if (!Files.isReadable(realPath)) {
            throw new ValidationException("Input file is not readable (permission denied): " + sanitize(resolved));
        }

        // 7. Size check (uses filesystem metadata without reading file content into memory)
        long size;
        try {
            size = Files.size(realPath);
        } catch (IOException e) {
            throw new ValidationException("Failed to read file size for: " + sanitize(resolved), e);
        }

        if (size > maxFileSizeBytes) {
            throw new ValidationException(
                "Input file size (" + size + " bytes) exceeds maximum limit (" + maxFileSizeBytes + " bytes): "
                + sanitize(resolved)
            );
        }

        return realPath;
    }

    /**
     * Validates a raw path string, returning a structured {@link ValidationResult}
     * instead of throwing an exception on failure.
     *
     * <p>Preserves sanitized {@link ValidationException} messages, but returns
     * a generic safe error message for unexpected exceptions without catching
     * fatal JVM errors.</p>
     *
     * @param rawPath string path provided by user
     * @return {@link ValidationResult} indicating outcome and sanitized message
     */
    public ValidationResult validateSafe(String rawPath) {
        try {
            Path valid = validate(rawPath);
            return ValidationResult.success(valid);
        } catch (ValidationException e) {
            return ValidationResult.failure(e.getMessage());
        } catch (Exception e) {
            return ValidationResult.failure(UNEXPECTED_ERROR_MESSAGE);
        }
    }

    /**
     * Validates a candidate {@link Path}, returning a structured {@link ValidationResult}
     * instead of throwing an exception on failure.
     *
     * <p>Preserves sanitized {@link ValidationException} messages, but returns
     * a generic safe error message for unexpected exceptions without catching
     * fatal JVM errors.</p>
     *
     * @param candidatePath path to validate
     * @return {@link ValidationResult} indicating outcome and sanitized message
     */
    public ValidationResult validateSafe(Path candidatePath) {
        try {
            Path valid = validate(candidatePath);
            return ValidationResult.success(valid);
        } catch (ValidationException e) {
            return ValidationResult.failure(e.getMessage());
        } catch (Exception e) {
            return ValidationResult.failure(UNEXPECTED_ERROR_MESSAGE);
        }
    }

    /**
     * Sanitizes a path for error reporting so that absolute internal directory trees,
     * hostnames, or usernames are never leaked.
     *
     * @param path target path
     * @return sanitized relative path or filename
     */
    private String sanitize(Path path) {
        if (path == null) {
            return "<unknown>";
        }
        try {
            Path abs = path.toAbsolutePath().normalize();
            if (abs.startsWith(canonicalRoot)) {
                return canonicalRoot.relativize(abs).toString().replace('\\', '/');
            }
            if (path.getFileName() != null) {
                return path.getFileName().toString();
            }
        } catch (Exception ignored) {
        }
        return "<redacted>";
    }
}
