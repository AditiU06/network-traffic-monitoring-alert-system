package com.kletech.networkmonitor.engine.e1.processing;

import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.ProcessedNetworkEvent;

import java.util.List;

/**
 * Common processing engine contract for transforming parsed network events into
 * enriched processed events.
 *
 * <p>Both sequential and multithreaded implementations fulfill this interface,
 * guaranteeing identical transformation logic, preserved input ordering, and
 * 100% output parity.</p>
 */
public interface NetworkEventProcessor {

    /**
     * Processes a list of pre-parsed network events.
     *
     * @param events non-null list of parsed network events
     * @return unmodifiable list of processed events matching the input size and ordering
     * @throws NullPointerException if {@code events} is null or contains null elements
     */
    List<ProcessedNetworkEvent> process(List<NetworkEvent> events);
}
