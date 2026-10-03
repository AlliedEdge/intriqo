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
    std::uint64_t packets_dropped{0};   ///< Kernel / capture buffer drops
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
    double runtime_seconds{0.0};
    std::uint64_t flows_flushed{0};

    /// Estimated fraction dropped among delivered plus dropped packets.
    /// Kernel counters vary by link type/filter; this is not a wire loss metric.
    [[nodiscard]] double drop_rate() const noexcept {
        if (packets_received == 0 && packets_dropped == 0) return 0.0;
        return static_cast<double>(packets_dropped) /
               (static_cast<double>(packets_received) + static_cast<double>(packets_dropped));
    }
};

} // namespace intriqo::metrics
