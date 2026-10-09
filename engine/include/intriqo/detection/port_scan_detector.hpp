#pragma once

#include "intriqo/detection/detector.hpp"
#include <chrono>
#include <map>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace intriqo::detection {

struct PortScanConfig {
    double window_seconds{10.0};
    std::size_t unique_port_threshold{10};
    std::size_t minimum_attempts{10};
    events::Severity severity{events::Severity::HIGH};
    std::size_t max_tracked_sources{4096};
    std::size_t max_tracked_observations{100000};
    Protocol protocol{Protocol::TCP};
};

/// Fixed windows count distinct TCP or UDP destination ports and flow IDs.
/// Windows expire strictly after window_seconds from their first observation.
/// The event-time watermark never moves backwards. Late observations may join
/// an existing window if they do not precede its start; they cannot open a new
/// window behind the watermark. Those admissions and capacity misses increment
/// state_rejections. Retained IDs survive window expiry until retire_flow().
/// statistics().observations counts accepted distinct flow IDs; live source and
/// observation gauges count windows and retained IDs. Rejections count admission
/// calls, including retries of untracked flows; reset() retains all counters/peaks.
class PortScanDetector final : public Detector {
public:
    explicit PortScanDetector(PortScanConfig config = {});
    [[nodiscard]] std::string_view name() const noexcept override {
        return config_.protocol == Protocol::UDP ? "udp_port_scan" : "port_scan";
    }
    [[nodiscard]] std::vector<events::SecurityEvent>
    evaluate(const flow::NetworkFlow&, const features::FlowFeatures&) noexcept override;
    [[nodiscard]] DetectorStatistics statistics() const noexcept override;
    void expire(TimePoint) noexcept override;
    void retire_flow(FlowId) noexcept override;
    void reset() noexcept override;

private:
    struct AddressHash {
        std::size_t operator()(const IPv4Address& address) const noexcept {
            std::size_t hash = 0;
            for (auto byte : address.octets) hash = hash * 131 + byte;
            return hash;
        }
    };
    struct Window {
        TimePoint started{};
        TimePoint latest_seen{};
        std::unordered_set<Port> ports;
        std::uint64_t attempts{0};
        bool emitted{false};
    };
    PortScanConfig config_;
    std::unordered_map<IPv4Address, Window, AddressHash> windows_;
    // Exactly one entry per live window; no stale/lazy heap nodes accumulate.
    std::multimap<TimePoint, IPv4Address> expiry_index_;
    std::unordered_set<FlowId> counted_flows_;
    TimePoint watermark_{};
    bool has_watermark_{false};
    DetectorStatistics statistics_;
    mutable std::mutex mutex_;

    void expire_locked(TimePoint) noexcept;
};

} // namespace intriqo::detection
