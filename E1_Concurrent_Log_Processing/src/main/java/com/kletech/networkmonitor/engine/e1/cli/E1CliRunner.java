package com.kletech.networkmonitor.engine.e1.cli;

import com.kletech.networkmonitor.engine.e1.LogProcessingEngine;
import com.kletech.networkmonitor.engine.e1.benchmark.BenchmarkMetrics;
import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.ProcessedNetworkEvent;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

/**
 * Production CLI entry point for Engine 1 (Concurrent Log Processing Engine).
 *
 * <p>Invoked by the Python Orchestration layer to process Zeek network logs,
 * execute multithreaded/sequential processing or benchmarking, and stream structured
 * NDJSON event records and JSON benchmark metrics.</p>
 */
public class E1CliRunner {

    public static void main(String[] args) {
        String inputPathStr = null;
        String mode = "MULTITHREADED";
        int threads = 4;
        String outputEventsPathStr = null;
        String outputMetricsPathStr = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--input":
                    if (i + 1 < args.length) inputPathStr = args[++i];
                    break;
                case "--mode":
                    if (i + 1 < args.length) mode = args[++i].toUpperCase(Locale.ROOT);
                    break;
                case "--threads":
                    if (i + 1 < args.length) threads = Integer.parseInt(args[++i]);
                    break;
                case "--output-events":
                    if (i + 1 < args.length) outputEventsPathStr = args[++i];
                    break;
                case "--output-metrics":
                    if (i + 1 < args.length) outputMetricsPathStr = args[++i];
                    break;
                default:
                    System.err.println("Unknown argument: " + args[i]);
            }
        }

        if (inputPathStr == null || inputPathStr.isBlank()) {
            System.err.println("Error: Missing required argument --input <file_path>");
            System.exit(1);
        }

        try {
            Path inputPath = Path.of(inputPathStr).toAbsolutePath().normalize();
            Path rootPath = inputPath.getParent() != null ? inputPath.getParent() : Path.of(".");
            // Configure LogProcessingEngine permitting access to the file's parent or root
            LogProcessingEngine engine = new LogProcessingEngine(rootPath);

            // 1. Single-pass log ingestion and parsing
            List<NetworkEvent> parsedEvents = engine.parseLog(inputPath);

            // 2. Execution based on mode
            List<ProcessedNetworkEvent> processedEvents;
            BenchmarkMetrics metrics = null;

            if ("BENCHMARK".equals(mode)) {
                metrics = engine.benchmarkEvents(parsedEvents, threads);
                processedEvents = engine.processMultithreaded(parsedEvents, threads);
            } else if ("SEQUENTIAL".equals(mode)) {
                processedEvents = engine.processSequentially(parsedEvents);
            } else { // MULTITHREADED (default)
                processedEvents = engine.processMultithreaded(parsedEvents, threads);
            }

            // 3. Write processed events to NDJSON if requested
            if (outputEventsPathStr != null && !outputEventsPathStr.isBlank()) {
                Path outEventsPath = Path.of(outputEventsPathStr);
                if (outEventsPath.getParent() != null) {
                    Files.createDirectories(outEventsPath.getParent());
                }
                try (BufferedWriter writer = Files.newBufferedWriter(outEventsPath, StandardCharsets.UTF_8)) {
                    for (ProcessedNetworkEvent pe : processedEvents) {
                        writer.write(eventToNdjsonLine(pe));
                        writer.newLine();
                    }
                }
            }

            // 4. Write benchmark metrics to JSON if requested
            if (metrics != null && outputMetricsPathStr != null && !outputMetricsPathStr.isBlank()) {
                Path outMetricsPath = Path.of(outputMetricsPathStr);
                if (outMetricsPath.getParent() != null) {
                    Files.createDirectories(outMetricsPath.getParent());
                }
                Files.writeString(outMetricsPath, metricsToJson(metrics), StandardCharsets.UTF_8);
            }

            // 5. Output summary JSON to stdout for orchestrator
            System.out.println(String.format(Locale.ROOT,
                    "{\"status\":\"SUCCESS\",\"mode\":\"%s\",\"threads\":%d,\"records_parsed\":%d,\"records_processed\":%d}",
                    mode, threads, parsedEvents.size(), processedEvents.size()));

        } catch (Exception ex) {
            System.err.println("E1 Processing Error: " + ex.getMessage());
            ex.printStackTrace(System.err);
            System.out.println(String.format(Locale.ROOT,
                    "{\"status\":\"FAILED\",\"error\":\"%s\",\"message\":\"%s\"}",
                    ex.getClass().getSimpleName(), escapeJson(ex.getMessage())));
            System.exit(2);
        }
    }

    private static String eventToNdjsonLine(ProcessedNetworkEvent pe) {
        NetworkEvent ne = pe.originalEvent();
        StringBuilder sb = new StringBuilder(256);
        sb.append("{");
        sb.append("\"record_ordinal\":").append(pe.recordOrdinal()).append(",");
        sb.append("\"timestamp\":\"").append(ne.timestamp().toString()).append("\",");
        sb.append("\"uid\":\"").append(escapeJson(ne.uid())).append("\",");
        sb.append("\"source_ip\":\"").append(ne.sourceAddress().getHostAddress()).append("\",");
        sb.append("\"source_port\":").append(ne.sourcePort() != null ? ne.sourcePort() : "null").append(",");
        sb.append("\"destination_ip\":\"").append(ne.destinationAddress().getHostAddress()).append("\",");
        sb.append("\"destination_port\":").append(ne.destinationPort() != null ? ne.destinationPort() : "null").append(",");
        sb.append("\"protocol\":\"").append(ne.protocol().name().toLowerCase(Locale.ROOT)).append("\",");
        sb.append("\"service\":").append(ne.service() != null ? "\"" + escapeJson(ne.service()) + "\"" : "null").append(",");
        sb.append("\"duration\":").append(ne.duration() != null ? ne.duration() : "null").append(",");
        sb.append("\"orig_bytes\":").append(ne.origBytes() != null ? ne.origBytes() : "null").append(",");
        sb.append("\"resp_bytes\":").append(ne.respBytes() != null ? ne.respBytes() : "null").append(",");
        sb.append("\"conn_state\":\"").append(ne.connectionState().name()).append("\",");
        sb.append("\"history\":").append(ne.history() != null ? "\"" + escapeJson(ne.history()) + "\"" : "null").append(",");
        sb.append("\"orig_pkts\":").append(ne.origPkts() != null ? ne.origPkts() : "null").append(",");
        sb.append("\"resp_pkts\":").append(ne.respPkts() != null ? ne.respPkts() : "null").append(",");

        // Calculated enrichment fields
        sb.append("\"total_bytes\":").append(pe.totalBytes() != null ? pe.totalBytes() : "null").append(",");
        sb.append("\"total_packets\":").append(pe.totalPackets() != null ? pe.totalPackets() : "null").append(",");
        sb.append("\"bytes_per_packet\":").append(pe.bytesPerPacket() != null ? String.format(Locale.ROOT, "%.4f", pe.bytesPerPacket()) : "null").append(",");
        sb.append("\"orig_to_resp_ratio\":").append(pe.origToRespRatio() != null ? String.format(Locale.ROOT, "%.4f", pe.origToRespRatio()) : "null");
        sb.append("}");
        return sb.toString();
    }

    private static String metricsToJson(BenchmarkMetrics m) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("{");
        sb.append("\"record_count\":").append(m.recordCount()).append(",");
        sb.append("\"worker_count\":").append(m.workerCount()).append(",");
        sb.append("\"sequential_duration_ms\":").append(String.format(Locale.ROOT, "%.3f", m.medianSequentialDuration().toNanos() / 1_000_000.0)).append(",");
        sb.append("\"multithreaded_duration_ms\":").append(String.format(Locale.ROOT, "%.3f", m.medianMultithreadedDuration().toNanos() / 1_000_000.0)).append(",");
        sb.append("\"sequential_throughput\":").append(String.format(Locale.ROOT, "%.2f", m.sequentialThroughput())).append(",");
        sb.append("\"multithreaded_throughput\":").append(String.format(Locale.ROOT, "%.2f", m.multithreadedThroughput())).append(",");
        sb.append("\"speedup\":").append(m.speedup() != null ? String.format(Locale.ROOT, "%.4f", m.speedup()) : "null").append(",");
        sb.append("\"sequential_cpu_load\":").append(m.sequentialCpuLoad() != null ? String.format(Locale.ROOT, "%.2f", m.sequentialCpuLoad()) : "null").append(",");
        sb.append("\"multithreaded_cpu_load\":").append(m.multithreadedCpuLoad() != null ? String.format(Locale.ROOT, "%.2f", m.multithreadedCpuLoad()) : "null").append(",");
        sb.append("\"sequential_observed_heap_bytes\":").append(m.sequentialObservedHeapBytes()).append(",");
        sb.append("\"multithreaded_observed_heap_bytes\":").append(m.multithreadedObservedHeapBytes()).append(",");
        sb.append("\"output_parity\":").append(m.outputParity());
        sb.append("}");
        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
