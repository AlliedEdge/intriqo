#pragma once

#include "intriqo/features/features.hpp"
#include "intriqo/events/security_event.hpp"
#include <optional>
#include <string>

namespace intriqo::anomaly {

/// Abstract statistical anomaly detector.
///
/// Anomaly detectors differ from rule-based detectors in that they maintain
/// a statistical baseline and fire when a deviation threshold is exceeded.
/// The detection pipeline treats them uniformly via this interface.
class AnomalyDetector {
public:
    virtual ~AnomalyDetector() = default;

    [[nodiscard]] virtual std::string name() const = 0;

    /// Update the statistical model with new features.
    virtual void update(const features::FlowFeatures& f) noexcept = 0;

    /// Compute anomaly score and optionally emit an event.
    [[nodiscard]] virtual std::optional<events::SecurityEvent>
    score(const features::FlowFeatures& f) const noexcept = 0;

    /// Reset the baseline model.
    virtual void reset() noexcept = 0;
};

} // namespace intriqo::anomaly
