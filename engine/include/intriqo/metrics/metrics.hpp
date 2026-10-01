#pragma once

#include <cstdint>
#include <chrono>

namespace intriqo::metrics {

/// Point-in-time snapshot of engine performance counters.
///
/// Exposed by the runtime to the control plane via a metrics endpoint.
/// All counters are monotonically increasing since engine start.
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

    /// Ratio of dropped to received packets (0.0–1.0).
    [[nodiscard]] double drop_rate() const noexcept {
        if (packets_received == 0) return 0.0;
        return static_cast<double>(packets_dropped) /
               static_cast<double>(packets_received);
    }
};

} // namespace intriqo::metrics
