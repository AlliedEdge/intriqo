#pragma once

#include "intriqo/flow/flow.hpp"
#include "intriqo/features/features.hpp"
#include "intriqo/events/security_event.hpp"
#include <vector>
#include <string_view>

namespace intriqo::detection {

/// Abstract base for all IDS detectors.
///
/// Each concrete detector owns its own state (counters, windows, models).
/// The detection pipeline calls evaluate() for every completed flow.
///
/// THREAD-SAFETY: Implementations must be thread-safe — the pipeline
/// may call evaluate() concurrently from multiple worker threads.
class Detector {
public:
    virtual ~Detector() = default;

    /// Human-readable name identifying this detector (used in logging/metrics).
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;

    /// Evaluate a completed flow and return zero or more SecurityEvents.
    ///
    /// Returns an empty vector if no detection fires.
    /// Must not throw — failures are signalled through the returned vector
    /// being empty (or via a dedicated error event in the future).
    [[nodiscard]] virtual std::vector<events::SecurityEvent>
    evaluate(const flow::NetworkFlow& flow,
             const features::FlowFeatures& features) noexcept = 0;

    /// Reset all stateful tracking (e.g. time-window counters).
    /// Called on engine restart or explicit flush.
    virtual void reset() noexcept = 0;
};

} // namespace intriqo::detection
