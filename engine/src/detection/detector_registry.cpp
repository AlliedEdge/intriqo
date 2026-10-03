#include "intriqo/detection/detector_registry.hpp"
#include <algorithm>
#include <iterator>
#include <stdexcept>

namespace intriqo::detection {

void DetectorRegistry::add(std::unique_ptr<Detector> detector) {
    if (!detector) throw std::invalid_argument("cannot register a null detector");
    std::lock_guard lock(mutex_);
    if (frozen_) throw std::logic_error("detector registration is closed after evaluation starts");
    std::string detector_name(detector->name());
    if (std::find(names_.begin(), names_.end(), detector_name) != names_.end()) {
        throw std::invalid_argument("duplicate detector name: " + detector_name);
    }
    names_.push_back(std::move(detector_name));
    try {
        detectors_.push_back(std::move(detector));
    } catch (...) {
        names_.pop_back();
        throw;
    }
}

std::vector<std::string> DetectorRegistry::names() const {
    std::lock_guard lock(mutex_);
    return names_;
}

std::string_view DetectorRegistry::name() const noexcept { return "detector_registry"; }

std::vector<events::SecurityEvent> DetectorRegistry::evaluate(
    const flow::NetworkFlow& flow, const features::FlowFeatures& features) noexcept {
    std::lock_guard lock(mutex_);
    frozen_ = true;
    std::vector<events::SecurityEvent> result;
    try {
        for (const auto& detector : detectors_) {
            auto events = detector->evaluate(flow, features);
            result.insert(result.end(), std::make_move_iterator(events.begin()),
                          std::make_move_iterator(events.end()));
        }
    } catch (...) {
        // Detector's noexcept contract also covers aggregation allocation failures.
        return {};
    }
    return result;
}

void DetectorRegistry::reset() noexcept {
    std::lock_guard lock(mutex_);
    for (const auto& detector : detectors_) detector->reset();
}

} // namespace intriqo::detection
