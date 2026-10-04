#pragma once

#include "intriqo/flow/flow.hpp"
#include "intriqo/features/features.hpp"
#include "intriqo/events/security_event.hpp"
#include <cstdint>
#include <vector>
#include <string_view>

namespace intriqo::detection {

/// Cumulative work counters and current/peak detector state sizes.
/// reset() clears live state but implementations should retain cumulative counters.
struct DetectorStatistics {
    std::uint64_t observations{0};
    std::uint64_t detections{0};
    std::uint64_t state_sources{0};
    std::uint64_t state_observations{0};
    std::uint64_t peak_sources{0};
    std::uint64_t peak_observations{0};
    std::uint64_t expired_sources{0};
    std::uint64_t state_rejections{0};
    std::uint64_t errors{0};
};

/// Abstract base for all IDS detectors.
///
/// Each concrete detector owns its own state (counters, windows, models).
/// The detection pipeline calls evaluate() for each flow observation.
///
/// THREAD-SAFETY: Implementations must be thread-safe — the pipeline
/// may call evaluation, lifecycle maintenance and snapshots concurrently.
class Detector {
public:
    virtual ~Detector() = default;

    /// Human-readable name identifying this detector (used in logging/metrics).
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;

    /// Evaluate an observed flow and return zero or more SecurityEvents.
    ///
    /// Returns an empty vector if no detection fires.
    /// Must not throw — failures are signalled through the returned vector
    /// being empty (or via a dedicated error event in the future).
    [[nodiscard]] virtual std::vector<events::SecurityEvent>
    evaluate(const flow::NetworkFlow& flow,
             const features::FlowFeatures& features) noexcept = 0;

    [[nodiscard]] virtual DetectorStatistics statistics() const noexcept { return {}; }

    /// Advance event-time maintenance without requiring another eligible flow.
    virtual void expire(TimePoint) noexcept {}

    /// Release a flow's deduplication identity after its final evaluation.
    virtual void retire_flow(FlowId) noexcept {}

    /// Reset all stateful tracking (e.g. time-window counters).
    /// Called on engine restart or explicit flush.
    virtual void reset() noexcept = 0;
};

} // namespace intriqo::detection
