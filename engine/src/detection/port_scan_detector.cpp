#include "intriqo/detection/port_scan_detector.hpp"
#include "intriqo/events/security_event.hpp"
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <type_traits>

namespace intriqo::detection {
namespace {

// Unsigned subtraction preserves the full interval even at extreme time
// points, without overflowing a signed clock duration or adding a deadline.
long double elapsed_seconds(TimePoint end, TimePoint start) noexcept {
    using UnsignedCount = std::make_unsigned_t<Clock::duration::rep>;
    const auto end_count = static_cast<UnsignedCount>(end.time_since_epoch().count());
    const auto start_count = static_cast<UnsignedCount>(start.time_since_epoch().count());
    const bool positive = end >= start;
    const auto ticks = positive ? end_count - start_count : start_count - end_count;
    const auto seconds = std::chrono::duration<long double>(
        std::chrono::duration<UnsignedCount, Clock::duration::period>{ticks}).count();
    return positive ? seconds : -seconds;
}

} // namespace

PortScanDetector::PortScanDetector(PortScanConfig config) : config_(config) {
    if (!std::isfinite(config_.window_seconds) || config_.window_seconds <= 0.0) {
        throw std::invalid_argument("port scan window_seconds must be finite and positive");
    }
    if (config_.unique_port_threshold == 0 || config_.minimum_attempts == 0) {
        throw std::invalid_argument("port scan thresholds must be positive");
    }
    if (config_.max_tracked_sources == 0 || config_.max_tracked_observations == 0) {
        throw std::invalid_argument("port scan state capacities must be positive");
    }
}

void PortScanDetector::expire_locked(TimePoint now) noexcept {
    if (!has_watermark_ || now > watermark_) {
        watermark_ = now;
        has_watermark_ = true;
    }
    while (!expiry_index_.empty()) {
        const auto oldest = expiry_index_.begin();
        if (elapsed_seconds(watermark_, oldest->first) <= config_.window_seconds) break;
        windows_.erase(oldest->second);
        expiry_index_.erase(oldest);
        ++statistics_.expired_sources;
    }
    // counted_flows_ is lifecycle state, not window state. Expiring a source
    // must never allow a still-active flow to count again in another window.
}

std::vector<events::SecurityEvent> PortScanDetector::evaluate(
    const flow::NetworkFlow& flow, const features::FlowFeatures&) noexcept {
    std::lock_guard lock(mutex_);
    expire_locked(flow.last_seen);
    if (flow.key.protocol != Protocol::TCP || flow.key.src_ip == flow.key.dst_ip
        || flow.key.dst_port == 0 || counted_flows_.contains(flow.flow_id)) {
        return {};
    }

    auto window = windows_.find(flow.key.src_ip);
    const bool new_source = window == windows_.end();
    // A late unseen source could otherwise resurrect an expired window and
    // emit again. Existing windows can safely accept late, in-window attempts.
    if ((new_source && elapsed_seconds(watermark_, flow.last_seen) > config_.window_seconds)
        || (!new_source && flow.last_seen < window->second.started)
        || (new_source && windows_.size() >= config_.max_tracked_sources)
        || counted_flows_.size() >= config_.max_tracked_observations) {
        ++statistics_.state_rejections;
        return {};
    }

    const auto attempts = new_source ? std::uint64_t{1} : window->second.attempts + 1;
    const auto ports = new_source ? std::size_t{1}
        : window->second.ports.size() + !window->second.ports.contains(flow.key.dst_port);
    const auto started = new_source ? flow.last_seen : window->second.started;
    const auto latest = new_source ? flow.last_seen
        : std::max(window->second.latest_seen, flow.last_seen);
    const bool detect = (new_source || !window->second.emitted)
        && ports >= config_.unique_port_threshold && attempts >= config_.minimum_attempts;

    try {
        // Construct the complete output before committing any observation.
        // If an allocation fails, the attempt can be retried without silent
        // partial identity/port insertion or a suppressed detection.
        std::vector<events::SecurityEvent> result;
        if (detect) {
            auto event = events::make_port_scan_event(
                flow.key.src_ip, flow.key.dst_ip, config_.severity, ports, attempts,
                static_cast<double>(elapsed_seconds(latest, started)),
                static_cast<std::uint16_t>(config_.unique_port_threshold), latest);
            // UUID formatting uses streams, which can absorb bad_alloc into
            // failbit. Treat a truncated result as an error before admission.
            if (event.event_id.size() != 36) {
                ++statistics_.errors;
                return {};
            }
            result.push_back(std::move(event));
        }

        const auto counted = counted_flows_.insert(flow.flow_id).first;
        try {
            if (new_source) {
                Window pending;
                pending.started = started;
                pending.latest_seen = latest;
                pending.ports.insert(flow.key.dst_port);
                pending.attempts = attempts;
                pending.emitted = detect;
                const auto expiry = expiry_index_.emplace(started, flow.key.src_ip);
                try {
                    windows_.emplace(flow.key.src_ip, std::move(pending));
                } catch (...) {
                    expiry_index_.erase(expiry);
                    throw;
                }
            } else {
                // The only throwing mutation is first. Subsequent scalar
                // updates commit the port and identity together.
                auto& current = window->second;
                current.ports.insert(flow.key.dst_port);
                current.attempts = attempts;
                current.latest_seen = latest;
                current.emitted = current.emitted || detect;
            }
        } catch (...) {
            counted_flows_.erase(counted);
            throw;
        }

        ++statistics_.observations;
        if (detect) ++statistics_.detections;
        statistics_.peak_sources = std::max(statistics_.peak_sources,
                                           static_cast<std::uint64_t>(windows_.size()));
        statistics_.peak_observations = std::max(statistics_.peak_observations,
                                                static_cast<std::uint64_t>(counted_flows_.size()));
        return result;
    } catch (...) {
        ++statistics_.errors;
        return {};
    }
}

DetectorStatistics PortScanDetector::statistics() const noexcept {
    std::lock_guard lock(mutex_);
    auto result = statistics_;
    result.state_sources = windows_.size();
    result.state_observations = counted_flows_.size();
    return result;
}

void PortScanDetector::expire(TimePoint now) noexcept {
    std::lock_guard lock(mutex_);
    expire_locked(now);
}

void PortScanDetector::retire_flow(FlowId id) noexcept {
    std::lock_guard lock(mutex_);
    counted_flows_.erase(id);
}

void PortScanDetector::reset() noexcept {
    std::lock_guard lock(mutex_);
    windows_.clear();
    expiry_index_.clear();
    counted_flows_.clear();
    has_watermark_ = false;
    watermark_ = {};
}

} // namespace intriqo::detection
