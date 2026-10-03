#pragma once

#include "intriqo/detection/detector.hpp"
#include <memory>
#include <mutex>
#include <string>

namespace intriqo::detection {

/// Composite detector. Registration closes permanently on the first evaluation.
class DetectorRegistry final : public Detector {
public:
    void add(std::unique_ptr<Detector> detector);
    [[nodiscard]] std::vector<std::string> names() const;
    [[nodiscard]] std::string_view name() const noexcept override;
    [[nodiscard]] std::vector<events::SecurityEvent>
    evaluate(const flow::NetworkFlow&, const features::FlowFeatures&) noexcept override;
    void reset() noexcept override;

private:
    mutable std::mutex mutex_;
    std::vector<std::unique_ptr<Detector>> detectors_;
    std::vector<std::string> names_;
    bool frozen_{false};
};

} // namespace intriqo::detection
