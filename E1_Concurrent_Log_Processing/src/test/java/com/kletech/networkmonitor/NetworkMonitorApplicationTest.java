package com.kletech.networkmonitor;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Build verification test.
 *
 * <p>Confirms that the Spring application context loads successfully
 * with the current configuration and dependency set.</p>
 */
@SpringBootTest
class NetworkMonitorApplicationTest {

    @Test
    void contextLoads() {
        // Verifies that the Spring application context starts without errors.
        // A failure here indicates a misconfiguration in dependencies,
        // component scanning, or application properties.
    }
}
