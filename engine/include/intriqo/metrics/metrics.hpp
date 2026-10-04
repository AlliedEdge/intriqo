#pragma once

#include <cstdint>
#include <chrono>

namespace intriqo::metrics {

/// Point-in-time snapshot of engine performance counters.
///
/// Exposed by Engine::metrics(); no HTTP metrics endpoint is implemented.
/// Cumulative counters increase since engine start; flows_active is a gauge.
struct EngineMetrics {
    std::uint64_t packets_received{0};
    std::uint64_t packets_dropped{0};   ///< Compatibility total: capture_drops + interface_drops
    std::uint64_t packets_parsed{0};
    std::uint64_t flows_created{0};
    std::uint64_t flows_expired{0};
    std::uint64_t flows_active{0};
    std::uint64_t events_emitted{0};
    std::uint64_t detections_fired{0};

    std::chrono::time_point<std::chrono::system_clock> snapshot_time;

    /// Packets per second (derived; not a raw counter).
    double pps{0.0};

    std::uint64_t packets_malformed{0}; ///< Subset of packets_rejected
    std::uint64_t packets_rejected{0};  ///< received == parsed + rejected
    std::uint64_t sink_failures{0};
    std::uint64_t queue_depth{0};        ///< Pending delivery events, excluding the worker's event
    std::uint64_t queue_peak_depth{0};
    std::uint64_t queue_overflows{0};
    double runtime_seconds{0.0};
    std::uint64_t flows_flushed{0};

    std::uint64_t packets_seen{0};     ///< Live ps_recv, or finite input count; check availability
    std::uint64_t packets_captured{0}; ///< Actual callbacks, independent of kernel/filter semantics
    std::uint64_t capture_drops{0};    ///< Live ps_drop
    std::uint64_t interface_drops{0};  ///< Live ps_ifdrop; zero does not establish hardware support
    std::uint64_t capture_errors{0};
    bool capture_statistics_available{false};
    std::uint64_t packets_unsupported{0}; ///< Subset of packets_rejected
    std::uint64_t packets_truncated{0};   ///< Subset of packets_malformed
    std::uint64_t packets_processed{0};   ///< Successfully completed pipeline ingests
    std::uint64_t flows_evicted{0};
    std::uint64_t peak_active_flows{0};
    std::uint64_t detector_observations{0};
    std::uint64_t detector_state_sources{0};
    std::uint64_t detector_state_observations{0};
    std::uint64_t detector_peak_sources{0};
    std::uint64_t detector_peak_observations{0};
    std::uint64_t detector_expired_sources{0};
    std::uint64_t detector_state_rejections{0};
    std::uint64_t detector_errors{0};
    double processing_seconds{0.0};       ///< Packet callback time, including synchronous event delivery
    double event_sink_seconds{0.0};       ///< Actual sink submit/flush time; excludes queue-drain waiting
    double processing_packets_per_second{0.0};

    /// Legacy delivered-plus-dropped fraction, retained for source compatibility.
    /// Not a capture/wire loss estimate: ps_recv, callbacks and interface counters
    /// have different platform/filter semantics. Prefer the separate raw counters.
    [[nodiscard]] double drop_rate() const noexcept {
        if (packets_received == 0 && packets_dropped == 0) return 0.0;
        return static_cast<double>(packets_dropped) /
               (static_cast<double>(packets_received) + static_cast<double>(packets_dropped));
    }
};

} // namespace intriqo::metrics
