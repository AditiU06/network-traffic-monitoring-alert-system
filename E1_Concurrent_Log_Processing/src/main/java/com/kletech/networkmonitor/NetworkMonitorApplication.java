package com.kletech.networkmonitor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Network Traffic Monitoring Alert System.
 *
 * <p>This application processes Zeek network traffic logs, detects
 * anomalies, and provides monitoring and alerting capabilities.</p>
 *
 * <p>The system is organized into four engines:</p>
 * <ul>
 *   <li>E1 — Network Log Ingestion and Processing</li>
 *   <li>E2 — Anomaly Detection (future)</li>
 *   <li>E3 — Data Persistence (future)</li>
 *   <li>E4 — Dashboard and Alerting (future)</li>
 * </ul>
 */
@SpringBootApplication
public class NetworkMonitorApplication {

    public static void main(String[] args) {
        SpringApplication.run(NetworkMonitorApplication.class, args);
    }
}
