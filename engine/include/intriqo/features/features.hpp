#pragma once

#include "intriqo/flow/flow.hpp"
#include <cstdint>

namespace intriqo::features {

/// Derived statistical features extracted from a NetworkFlow.
///
/// These features serve as the input vector for both rule-based detectors
/// and (eventually) ML inference models.
struct FlowFeatures {
    // ── Raw flow counters ──────────────────────────────────────────────────
    std::uint64_t packet_count{0};
    ByteCount     byte_count{0};
    double        duration_seconds{0.0};

    // ── Derived metrics ───────────────────────────────────────────────────
    double bytes_per_packet{0.0};      ///< Mean packet size
    double packets_per_second{0.0};    ///< Throughput in pps
    double bytes_per_second{0.0};      ///< Throughput in Bps

    // ── TCP-specific ──────────────────────────────────────────────────────
    std::uint32_t syn_count{0};
    std::uint32_t fin_count{0};
    std::uint32_t rst_count{0};

    /// Extract features from an aggregated NetworkFlow.
    [[nodiscard]] static FlowFeatures from_flow(const flow::NetworkFlow& f) noexcept;
};

} // namespace intriqo::features
