package com.kletech.networkmonitor.engine.e1.processing;

import com.kletech.networkmonitor.engine.e1.model.NetworkEvent;
import com.kletech.networkmonitor.engine.e1.model.ProcessedNetworkEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Baseline single-threaded implementation of {@link NetworkEventProcessor}.
 *
 * <p>Processes a list of pre-parsed {@link NetworkEvent} records sequentially in their
 * original input order using {@link EventTransformer#transform(NetworkEvent)}.
 * Preserves each event's original {@code recordOrdinal} without assuming it equals
 * the list index.</p>
 */
public class SequentialProcessor implements NetworkEventProcessor {

    /**
     * Constructs a default SequentialProcessor.
     */
    public SequentialProcessor() {
    }

    @Override
    public List<ProcessedNetworkEvent> process(List<NetworkEvent> events) {
        Objects.requireNonNull(events, "events must not be null");

        List<ProcessedNetworkEvent> results = new ArrayList<>(events.size());
        for (NetworkEvent event : events) {
            Objects.requireNonNull(event, "event element in list must not be null");
            results.add(EventTransformer.transform(event));
        }
        return Collections.unmodifiableList(results);
    }
}
