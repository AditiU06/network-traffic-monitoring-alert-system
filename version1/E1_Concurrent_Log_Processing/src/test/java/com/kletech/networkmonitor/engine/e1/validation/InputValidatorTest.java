package com.kletech.networkmonitor.engine.e1.validation;

import com.kletech.networkmonitor.engine.e1.exception.ValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("InputValidator unit tests")
class InputValidatorTest {

    @TempDir
    Path tempDir;

    private Path permittedRoot;
    private InputValidator validator;

    @BeforeEach
    void setUp() throws IOException {
        permittedRoot = tempDir.toRealPath().resolve("permitted-data");
        Files.createDirectories(permittedRoot);
        permittedRoot = permittedRoot.toRealPath();
        validator = new InputValidator(permittedRoot);
    }

    @Test
    @DisplayName("Should accept a valid readable regular file inside permitted root")
    void shouldAcceptValidReadableRegularFile() throws IOException {
        Path validFile = permittedRoot.resolve("conn.log");
        Files.writeString(validFile, "sample log content");

        Path validated = validator.validate(validFile);
        assertThat(validated).isNotNull();
        assertThat(Files.isSameFile(validated, validFile)).isTrue();

        // Also test validate(String)
        Path validatedFromStr = validator.validate("conn.log");
        assertThat(validatedFromStr).isNotNull();
        assertThat(Files.isSameFile(validatedFromStr, validFile)).isTrue();

        // Also test structured safe validation
        ValidationResult result = validator.validateSafe("conn.log");
        assertThat(result.isValid()).isTrue();
        assertThat(result.validatedPath()).isEqualTo(validatedFromStr);
        assertThat(result.errorMessage()).isNull();
    }

    @Test
    @DisplayName("Should accept valid file located in nested subdirectories under permitted root")
    void shouldAcceptNestedFile() throws IOException {
        Path nestedDir = permittedRoot.resolve("real").resolve("benign");
        Files.createDirectories(nestedDir);
        Path nestedFile = nestedDir.resolve("conn.log");
        Files.writeString(nestedFile, "nested content");

        Path validated = validator.validate("real/benign/conn.log");
        assertThat(Files.isSameFile(validated, nestedFile)).isTrue();
    }

    @Test
    @DisplayName("Should accept valid Zeek dataset with .txt extension (no extension restriction)")
    void shouldAcceptValidDatasetWithTxtExtension() throws IOException {
        Path txtDataset = permittedRoot.resolve("conn.txt");
        Files.writeString(txtDataset, "#fields ts uid proto\n");

        Path validated = validator.validate(txtDataset);
        assertThat(Files.isSameFile(validated, txtDataset)).isTrue();
    }

    @Test
    @DisplayName("Should reject null path string and null Path object using ValidationException")
    void shouldRejectNullPathsWithValidationException() {
        assertThatThrownBy(() -> validator.validate((String) null))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("must not be null or blank");

        assertThatThrownBy(() -> validator.validate((Path) null))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("must not be null or blank");

        ValidationResult resultStr = validator.validateSafe((String) null);
        assertThat(resultStr.isValid()).isFalse();
        assertThat(resultStr.errorMessage()).contains("must not be null or blank");

        ValidationResult resultPath = validator.validateSafe((Path) null);
        assertThat(resultPath.isValid()).isFalse();
        assertThat(resultPath.errorMessage()).contains("must not be null or blank");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t", "\n"})
    @DisplayName("Should reject blank path strings using ValidationException")
    void shouldRejectBlankPaths(String blankPath) {
        assertThatThrownBy(() -> validator.validate(blankPath))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("must not be null or blank");

        ValidationResult result = validator.validateSafe(blankPath);
        assertThat(result.isValid()).isFalse();
        assertThat(result.errorMessage()).contains("must not be null or blank");
    }

    @Test
    @DisplayName("Should reject empty Path object using ValidationException")
    void shouldRejectEmptyPathObject() {
        assertThatThrownBy(() -> validator.validate(Path.of("")))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("must not be null or blank");

        ValidationResult result = validator.validateSafe(Path.of(""));
        assertThat(result.isValid()).isFalse();
        assertThat(result.errorMessage()).contains("must not be null or blank");
    }

    @Test
    @DisplayName("Should reject malformed path string containing illegal NUL characters")
    void shouldRejectMalformedPath() {
        String malformedPath = "conn\0.log";
        assertThatThrownBy(() -> validator.validate(malformedPath))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("malformed");
    }

    @Test
    @DisplayName("Should reject nonexistent file")
    void shouldRejectNonexistentFile() {
        assertThatThrownBy(() -> validator.validate("nonexistent.log"))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("does not exist")
            .hasMessageContaining("nonexistent.log");

        ValidationResult result = validator.validateSafe("nonexistent.log");
        assertThat(result.isValid()).isFalse();
        assertThat(result.errorMessage()).contains("does not exist");
    }

    @Test
    @DisplayName("Should reject directory path instead of regular file")
    void shouldRejectDirectoryTarget() throws IOException {
        Path subDir = permittedRoot.resolve("sub-directory");
        Files.createDirectories(subDir);

        assertThatThrownBy(() -> validator.validate("sub-directory"))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("is a directory, not a regular file");

        ValidationResult result = validator.validateSafe("sub-directory");
        assertThat(result.isValid()).isFalse();
        assertThat(result.errorMessage()).contains("is a directory");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "../outside.log",
        "../../outside.log",
        "sub/../../outside.log",
        "real/benign/../../../secret.txt"
    })
    @DisplayName("Should reject path traversal attempts escaping permitted root")
    void shouldRejectPathTraversal(String traversalPath) {
        assertThatThrownBy(() -> validator.validate(traversalPath))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("Access denied: path is outside permitted input directory");

        ValidationResult result = validator.validateSafe(traversalPath);
        assertThat(result.isValid()).isFalse();
        assertThat(result.errorMessage()).contains("Access denied");
    }

    @Test
    @DisplayName("Should immediately reject absolute path outside permitted root before existence check")
    void shouldRejectExternalAbsolutePathImmediately() throws IOException {
        Path outsideFile = tempDir.resolve("external-secret.log");
        Files.writeString(outsideFile, "secret");

        // Existing external file
        assertThatThrownBy(() -> validator.validate(outsideFile))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("Access denied: path is outside permitted input directory");

        // Nonexistent external file (must still be rejected with Access Denied, not File Not Found)
        Path nonexistentOutside = tempDir.resolve("nonexistent-external.log");
        assertThatThrownBy(() -> validator.validate(nonexistentOutside))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("Access denied: path is outside permitted input directory");

        // Error message must not leak the absolute path of the external file
        ValidationResult result = validator.validateSafe(outsideFile);
        assertThat(result.isValid()).isFalse();
        assertThat(result.errorMessage()).doesNotContain(outsideFile.toString());
    }

    @Test
    @DisplayName("Should reject symbolic link pointing outside permitted root (symlink escape)")
    void shouldRejectSymbolicLinkEscapeWhenSupported() throws IOException {
        Path outsideTarget = tempDir.resolve("sensitive.log");
        Files.writeString(outsideTarget, "top secret external data");

        Path linkInside = permittedRoot.resolve("symlink-escape.log");

        boolean symlinkCreated = false;
        try {
            Files.createSymbolicLink(linkInside, outsideTarget);
            symlinkCreated = true;
        } catch (UnsupportedOperationException | FileSystemException e) {
            // Windows without Developer Mode or unprivileged accounts can disallow symlinks
            System.out.println("Symbolic links not permitted in this OS environment: " + e.getMessage());
        }

        if (symlinkCreated) {
            assertThatThrownBy(() -> validator.validate("symlink-escape.log"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("symbolic link points outside permitted directory");

            ValidationResult result = validator.validateSafe("symlink-escape.log");
            assertThat(result.isValid()).isFalse();
            assertThat(result.errorMessage()).contains("symbolic link points outside permitted directory");
        }
    }

    @Test
    @DisplayName("Should accept 0-byte regular file (content validation deferred to Phase 4)")
    void shouldAcceptZeroByteRegularFile() throws IOException {
        Path emptyFile = permittedRoot.resolve("empty.log");
        Files.createFile(emptyFile);

        Path validated = validator.validate(emptyFile);
        assertThat(validated).isNotNull();
        assertThat(Files.isSameFile(validated, emptyFile)).isTrue();

        ValidationResult result = validator.validateSafe(emptyFile);
        assertThat(result.isValid()).isTrue();
        assertThat(result.validatedPath()).isNotNull();
    }

    @Test
    @DisplayName("Should accept file at exact maximum file size limit boundary")
    void shouldAcceptFileAtExactSizeBoundary() throws IOException {
        long exactLimit = 50L;
        InputValidator limitedValidator = new InputValidator(permittedRoot, exactLimit);

        Path boundaryFile = permittedRoot.resolve("boundary.log");
        byte[] content = new byte[(int) exactLimit];
        Files.write(boundaryFile, content);

        Path validated = limitedValidator.validate(boundaryFile);
        assertThat(validated).isNotNull();
    }

    @Test
    @DisplayName("Should reject file exceeding maximum file size limit by even one byte")
    void shouldRejectFileExceedingSizeLimit() throws IOException {
        long exactLimit = 50L;
        InputValidator limitedValidator = new InputValidator(permittedRoot, exactLimit);

        Path oversizedFile = permittedRoot.resolve("oversized.log");
        byte[] content = new byte[(int) exactLimit + 1];
        Files.write(oversizedFile, content);

        assertThatThrownBy(() -> limitedValidator.validate(oversizedFile))
            .isInstanceOf(ValidationException.class)
            .hasMessageContaining("exceeds maximum limit");

        ValidationResult result = limitedValidator.validateSafe(oversizedFile);
        assertThat(result.isValid()).isFalse();
        assertThat(result.errorMessage()).contains("exceeds maximum limit");
    }

    @Test
    @DisplayName("Should reject unreadable file where filesystem supports permission restrictions")
    void shouldRejectUnreadableFileWhereTestable() throws IOException {
        Path unreadableFile = permittedRoot.resolve("unreadable.log");
        Files.writeString(unreadableFile, "data");

        if (unreadableFile.toFile().setReadable(false)) {
            try {
                if (!Files.isReadable(unreadableFile)) {
                    assertThatThrownBy(() -> validator.validate(unreadableFile))
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining("not readable");
                }
            } finally {
                unreadableFile.toFile().setReadable(true);
            }
        }
    }

    @Test
    @DisplayName("Should not expose absolute system paths in error messages")
    void shouldSanitizeErrorMessagesWithoutExposingAbsolutePaths() throws IOException {
        Path nested = permittedRoot.resolve("a").resolve("b");
        Files.createDirectories(nested);
        Path missing = nested.resolve("missing.log");

        try {
            validator.validate("a/b/missing.log");
        } catch (ValidationException e) {
            // Must contain relative path representation, not absolute C:\ or /tmp path
            assertThat(e.getMessage()).contains("a/b/missing.log");
            assertThat(e.getMessage()).doesNotContain(tempDir.toString());
        }
    }

    @Test
    @DisplayName("Should reject non-positive maxFileSizeBytes in constructor")
    void shouldRejectNonPositiveMaxFileSize() {
        assertThatThrownBy(() -> new InputValidator(permittedRoot, 0L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("maxFileSizeBytes must be positive");

        assertThatThrownBy(() -> new InputValidator(permittedRoot, -100L))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("maxFileSizeBytes must be positive");
    }

    @Test
    @DisplayName("Should reject null permittedRoot in constructor")
    void shouldRejectNullPermittedRoot() {
        assertThatThrownBy(() -> new InputValidator(null))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("permittedRoot must not be null");
    }

    @Test
    @DisplayName("Should reject nonexistent permittedRoot in constructor")
    void shouldRejectNonexistentPermittedRoot() {
        Path nonExistent = tempDir.resolve("nonexistent-root");
        assertThatThrownBy(() -> new InputValidator(nonExistent))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("does not exist");
    }

    @Test
    @DisplayName("Should reject permittedRoot that is a regular file instead of directory")
    void shouldRejectFileAsPermittedRoot() throws IOException {
        Path fileAsRoot = tempDir.resolve("file-root.txt");
        Files.writeString(fileAsRoot, "not a directory");

        assertThatThrownBy(() -> new InputValidator(fileAsRoot))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("must be a directory");
    }

    @Test
    @DisplayName("Should accept absolute path with Windows short-name alias when it resolves inside permitted root")
    void shouldAcceptWindowsShortNameAlias() throws IOException {
        // On Windows, Files.createTempFile() may return a path with 8.3 short-name
        // components (e.g. ADITIU~1) that differ textually from the long-name form
        // stored in canonicalRoot via toRealPath(). This test verifies that
        // InputValidator resolves such aliases correctly.
        Path validFile = permittedRoot.resolve("shortname-test.log");
        Files.writeString(validFile, "test content");

        // Obtain the real (long-name) path and the raw normalized path.
        Path realPath = validFile.toRealPath();
        Path normalizedPath = validFile.toAbsolutePath().normalize();

        // If they differ (Windows short-name alias), both must be accepted.
        Path validated = validator.validate(normalizedPath);
        assertThat(validated).isNotNull();
        assertThat(Files.isSameFile(validated, realPath)).isTrue();

        // The real path must also be accepted directly.
        Path validatedReal = validator.validate(realPath);
        assertThat(validatedReal).isNotNull();
        assertThat(Files.isSameFile(validatedReal, realPath)).isTrue();

        // Safe variant must succeed for both forms.
        ValidationResult resultNorm = validator.validateSafe(normalizedPath);
        assertThat(resultNorm.isValid()).isTrue();

        ValidationResult resultReal = validator.validateSafe(realPath);
        assertThat(resultReal.isValid()).isTrue();
    }
}
