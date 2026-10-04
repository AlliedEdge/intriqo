#pragma once

#include "intriqo/detection/detector.hpp"
#include <memory>
#include <mutex>
#include <string>

namespace intriqo::detection {

/// Composite detector. Registration closes permanently on the first evaluation.
/// Statistics sum child counters/gauges/peaks; peaks are sums of child high-water
/// marks, not a simultaneous registry high-water mark. Aggregation errors add to
/// the child error total and survive reset().
class DetectorRegistry final : public Detector {
public:
    void add(std::unique_ptr<Detector> detector);
    [[nodiscard]] std::vector<std::string> names() const;
    [[nodiscard]] std::string_view name() const noexcept override;
    [[nodiscard]] std::vector<events::SecurityEvent>
    evaluate(const flow::NetworkFlow&, const features::FlowFeatures&) noexcept override;
    [[nodiscard]] DetectorStatistics statistics() const noexcept override;
    void expire(TimePoint) noexcept override;
    void retire_flow(FlowId) noexcept override;
    void reset() noexcept override;

private:
    using DetectorList = std::vector<std::shared_ptr<Detector>>;

    // Copy-on-write registration makes snapshots allocation-free. No registry
    // mutex is held while invoking a child detector, including its statistics.
    mutable std::mutex mutex_;
    std::shared_ptr<const DetectorList> detectors_{std::make_shared<DetectorList>()};
    std::vector<std::string> names_;
    bool frozen_{false};
    std::uint64_t errors_{0};
};

} // namespace intriqo::detection
