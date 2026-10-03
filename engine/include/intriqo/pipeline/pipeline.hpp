#pragma once

#include "intriqo/packet/packet.hpp"
#include "intriqo/flow/flow.hpp"
#include "intriqo/events/security_event.hpp"
#include <functional>
#include <vector>

namespace intriqo::pipeline {

struct PipelineStatistics {
    std::uint64_t flows_created{0};
    std::uint64_t flows_expired{0};
    std::uint64_t flows_flushed{0};
    std::uint64_t flows_active{0};
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

    /// Return currently active flow count (for metrics).
    [[nodiscard]] virtual std::size_t active_flow_count() const noexcept = 0;

    /// Lifecycle counters; the default preserves existing pipeline implementations.
    [[nodiscard]] virtual PipelineStatistics statistics() const noexcept {
        PipelineStatistics result;
        result.flows_active = active_flow_count();
        return result;
    }
};

} // namespace intriqo::pipeline
