#include "intriqo/detection/detector_registry.hpp"
#include <algorithm>
#include <iterator>
#include <stdexcept>

namespace intriqo::detection {

void DetectorRegistry::add(std::unique_ptr<Detector> detector) {
    if (!detector) throw std::invalid_argument("cannot register a null detector");
    std::string detector_name(detector->name());
    std::lock_guard lock(mutex_);
    if (frozen_) throw std::logic_error("detector registration is closed after evaluation starts");
    if (std::find(names_.begin(), names_.end(), detector_name) != names_.end()) {
        throw std::invalid_argument("duplicate detector name: " + detector_name);
    }
    auto updated = std::make_shared<DetectorList>(*detectors_);
    updated->push_back(std::move(detector));
    names_.push_back(std::move(detector_name));
    detectors_ = std::move(updated);
}

std::vector<std::string> DetectorRegistry::names() const {
    std::lock_guard lock(mutex_);
    return names_;
}

std::string_view DetectorRegistry::name() const noexcept { return "detector_registry"; }

std::vector<events::SecurityEvent> DetectorRegistry::evaluate(
    const flow::NetworkFlow& flow, const features::FlowFeatures& features) noexcept {
    std::shared_ptr<const DetectorList> detectors;
    {
        std::lock_guard lock(mutex_);
        frozen_ = true;
        detectors = detectors_;
    }
    std::vector<events::SecurityEvent> result;
    for (const auto& detector : *detectors) {
        auto events = detector->evaluate(flow, features);
        try {
            if (result.empty()) {
                result = std::move(events);
            } else {
                result.insert(result.end(), std::make_move_iterator(events.begin()),
                              std::make_move_iterator(events.end()));
            }
        } catch (...) {
            // Preserve earlier results, expose failed aggregation and still
            // dispatch the observation to the remaining detectors.
            std::lock_guard lock(mutex_);
            ++errors_;
        }
    }
    return result;
}

DetectorStatistics DetectorRegistry::statistics() const noexcept {
    std::shared_ptr<const DetectorList> detectors;
    DetectorStatistics result;
    {
        std::lock_guard lock(mutex_);
        detectors = detectors_;
        result.errors = errors_;
    }
    for (const auto& detector : *detectors) {
        const auto stats = detector->statistics();
        result.observations += stats.observations;
        result.detections += stats.detections;
        result.state_sources += stats.state_sources;
        result.state_observations += stats.state_observations;
        result.peak_sources += stats.peak_sources;
        result.peak_observations += stats.peak_observations;
        result.expired_sources += stats.expired_sources;
        result.state_rejections += stats.state_rejections;
        result.errors += stats.errors;
    }
    return result;
}

void DetectorRegistry::expire(TimePoint now) noexcept {
    std::shared_ptr<const DetectorList> detectors;
    {
        std::lock_guard lock(mutex_);
        detectors = detectors_;
    }
    for (const auto& detector : *detectors) detector->expire(now);
}

void DetectorRegistry::retire_flow(FlowId id) noexcept {
    std::shared_ptr<const DetectorList> detectors;
    {
        std::lock_guard lock(mutex_);
        detectors = detectors_;
    }
    for (const auto& detector : *detectors) detector->retire_flow(id);
}

void DetectorRegistry::reset() noexcept {
    std::shared_ptr<const DetectorList> detectors;
    {
        std::lock_guard lock(mutex_);
        detectors = detectors_;
    }
    for (const auto& detector : *detectors) detector->reset();
}

} // namespace intriqo::detection
