#pragma once
#include "intriqo/metrics/metrics.hpp"
#include <ostream>

namespace intriqo::tools {
inline void detailed_counters(std::ostream& out, const metrics::EngineMetrics& m) {
    out << " packets_seen=";
    if (m.capture_statistics_available) out << m.packets_seen; else out << "N/A";
    out << " packets_captured=" << m.packets_captured
        << " capture_statistics_available=" << (m.capture_statistics_available ? "true" : "false")
        << " capture_drops=";
    if (m.capture_statistics_available) out << m.capture_drops; else out << "N/A";
    out << " interface_drops=";
    if (m.capture_statistics_available) out << m.interface_drops; else out << "N/A";
    out << " capture_errors=" << m.capture_errors
        << " packets_processed=" << m.packets_processed
        << " packets_unsupported=" << m.packets_unsupported
        << " packets_truncated=" << m.packets_truncated
        << " flows_evicted=" << m.flows_evicted << " peak_active_flows=" << m.peak_active_flows
        << " detector_observations=" << m.detector_observations
        << " detector_state_sources=" << m.detector_state_sources
        << " detector_state_observations=" << m.detector_state_observations
        << " detector_peak_sources=" << m.detector_peak_sources
        << " detector_peak_observations=" << m.detector_peak_observations
        << " detector_expired_sources=" << m.detector_expired_sources
        << " detector_state_rejections=" << m.detector_state_rejections
        << " detector_errors=" << m.detector_errors
        << " events_generated=" << m.detections_fired
        << " detections_generated=" << m.detections_fired
        << " event_sink_failures=" << m.sink_failures
        << " queue_depth=" << m.queue_depth
        << " queue_peak_depth=" << m.queue_peak_depth
        << " queue_overflows=" << m.queue_overflows
        << " processing_seconds=" << m.processing_seconds
        << " event_sink_seconds=" << m.event_sink_seconds
        << " processing_packets_per_second=" << m.processing_packets_per_second;
}
} // namespace intriqo::tools
