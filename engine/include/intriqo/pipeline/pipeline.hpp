#pragma once

#include "intriqo/packet/packet.hpp"
#include "intriqo/flow/flow.hpp"
#include "intriqo/events/security_event.hpp"
#include "intriqo/detection/detector.hpp"
#include "intriqo/transport/flow_feature_sink.hpp"
#include <functional>
#include <vector>

namespace intriqo::pipeline {

struct PipelineStatistics {
    std::uint64_t flows_created{0};
    std::uint64_t flows_expired{0};
    std::uint64_t flows_flushed{0};
    std::uint64_t flows_active{0};
    std::uint64_t flows_evicted{0};
    std::uint64_t peak_active_flows{0};
    detection::DetectorStatistics detection;
    std::uint64_t feature_records_generated{0};
    std::uint64_t feature_generation_failures{0};
    std::uint64_t feature_setup_failures{0};
    double feature_generation_seconds{0.0};
    transport::FlowFeatureSinkStatistics feature_stream;
};

/// Callback invoked for every SecurityEvent the pipeline produces.
using EventCallback = std::function<void(events::SecurityEvent)>;

/// The IDS processing pipeline.
///
/// Packet → Flow construction → Feature extraction → Detection → Event emission
///
/// This interface is the single entry point for raw packets.
/// Implementations are free to parallelise internally.
class Pipeline {
public:
    virtual ~Pipeline() = default;

    /// Submit a parsed packet for flow tracking and detection.
    virtual void ingest(const packet::ParsedPacket& pkt) = 0;

    /// Register a callback to receive SecurityEvents.
    virtual void on_event(EventCallback cb) = 0;

    /// Flush all active flows and emit any pending events.
    virtual void flush() = 0;

    /// Expire idle state without requiring a packet; optional for implementations.
    virtual void maintain(TimePoint) {}

    /// Return currently active flow count (for metrics).
    [[nodiscard]] virtual std::size_t active_flow_count() const noexcept = 0;

    /// Lifecycle counters; the default preserves existing pipeline implementations.
    [[nodiscard]] virtual PipelineStatistics statistics() const noexcept {
        PipelineStatistics result;
        result.flows_active = active_flow_count();
        result.peak_active_flows = result.flows_active;
        return result;
    }
};

} // namespace intriqo::pipeline
