package com.kletech.networkmonitor.engine.e1.parser;

import com.kletech.networkmonitor.engine.e1.exception.RecordParseException;
import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.ProcessingResult;
import com.kletech.networkmonitor.engine.e1.validation.InputValidator;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import java.util.Objects;

/**
 * Streams Zeek {@code conn.log} files line‑by‑line, emitting a {@link ProcessingResult}
 * for each data record. The implementation uses {@link InputValidator} for path
 * validation, {@link ZeekHeaderParser} for header parsing (which leaves the
 * {@link BufferedReader} positioned at the first data row), and {@link ZeekRecordParser}
 * for per‑record parsing.
 *
 * <p>Consumers receive a {@code ProcessingResult} for every data row – successful
 * parses contain a {@link NetworkEvent}, failures contain a sanitized error
 * message. Blank lines are ignored, comment lines (starting with {@code #}) are
 * skipped, and a trailing {@code #close} directive is not treated as a record.
 * The method does not load the entire file or all results into memory; it
 * processes each line as it is read.</p>
 */
public class ZeekLogStreamer {

    private final InputValidator validator;

    /** Constructs a streamer with a custom {@link InputValidator}. */
    public ZeekLogStreamer(InputValidator validator) {
        this.validator = Objects.requireNonNull(validator, "validator must not be null");
    }

    /** Constructs a streamer that validates paths against the given permitted root. */
    public ZeekLogStreamer(Path permittedRoot) {
        this(new InputValidator(permittedRoot));
    }

    /**
     * Streams the given Zeek log file, invoking {@code consumer} for each
     * {@link ProcessingResult}. The caller supplies a {@link Consumer} to handle
     * results as they are produced. Resources are closed automatically.
     *
     * @param rawPath  path to the Zeek log file (may be {@link String} or {@link Path})
     * @param consumer consumer that receives each {@link ProcessingResult}
     */
    public void stream(String rawPath, Consumer<ProcessingResult> consumer) {
        Path path = validator.validate(rawPath);
        streamPath(path, consumer);
    }

    /** Same as {@link #stream(String,Consumer)} but takes a {@link Path}. */
    public void stream(Path path, Consumer<ProcessingResult> consumer) {
        Objects.requireNonNull(path, "path must not be null");
        Path validatedPath = validator.validate(path);
        streamPath(validatedPath, consumer);
    }

    /**
     * Parses the given Zeek log file and returns all successfully parsed {@link NetworkEvent}s.
     * Malformed records are safely skipped.
     *
     * @param path path to the Zeek log file
     * @return unmodifiable list of successfully parsed events, in original stream order
     */
    public List<NetworkEvent> parseValidEvents(Path path) {
        Objects.requireNonNull(path, "path must not be null");
        List<NetworkEvent> events = new ArrayList<>();
        stream(path, result -> {
            if (result.isSuccess()) {
                events.add(result.event());
            }
        });
        return Collections.unmodifiableList(events);
    }

    /**
     * Same as {@link #parseValidEvents(Path)} but takes a raw path string.
     *
     * @param rawPath user-supplied path string
     * @return unmodifiable list of successfully parsed events, in original stream order
     */
    public List<NetworkEvent> parseValidEvents(String rawPath) {
        Objects.requireNonNull(rawPath, "rawPath must not be null");
        Path validatedPath = validator.validate(rawPath);
        return parseValidEvents(validatedPath);
    }

    /**
     * Returns the {@link InputValidator} used by this streamer.
     *
     * @return configured input validator
     */
    public InputValidator getValidator() {
        return validator;
    }

    private void streamPath(Path path, Consumer<ProcessingResult> consumer) {
        Objects.requireNonNull(consumer, "consumer must not be null");
        ZeekHeaderParser headerParser = new ZeekHeaderParser(validator);
        try (BufferedReader reader = java.nio.file.Files.newBufferedReader(path)) {
            // Parse header – leaves reader positioned at first data row.
            ZeekHeader header = headerParser.parse(reader);
            long lineNumber = header.headerLinesCount(); // header lines already consumed
            long recordOrdinal = 0L;
            String line;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                // Skip blank lines.
                if (line.isBlank()) {
                    continue;
                }
                // Skip comment lines; #close at end of file is also a comment.
                if (line.startsWith("#")) {
                    continue;
                }
                try {
                    NetworkEvent event = ZeekRecordParser.parseRecord(header, line, recordOrdinal);
                    consumer.accept(ProcessingResult.success(lineNumber, recordOrdinal, event));
                } catch (RecordParseException e) {
                    // Preserve sanitized error message; include line number and ordinal via ProcessingResult.
                    consumer.accept(ProcessingResult.failure(lineNumber, recordOrdinal, e.getMessage()));
                }
                recordOrdinal++;
            }
        } catch (IOException e) {
            throw new UncheckedIOException("I/O error while reading Zeek log", e);
        }
    }
}
