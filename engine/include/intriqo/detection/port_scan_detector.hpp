#pragma once

#include "intriqo/detection/detector.hpp"
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

namespace intriqo::detection {

struct PortScanConfig {
    double window_seconds{10.0};
    std::size_t unique_port_threshold{10};
    std::size_t minimum_attempts{10};
    events::Severity severity{events::Severity::HIGH};
};

class PortScanDetector final : public Detector {
public:
    explicit PortScanDetector(PortScanConfig config = {});
    [[nodiscard]] std::string_view name() const noexcept override { return "port_scan"; }
    [[nodiscard]] std::vector<events::SecurityEvent>
    evaluate(const flow::NetworkFlow&, const features::FlowFeatures&) noexcept override;
    void reset() noexcept override;

private:
    struct AddressHash { std::size_t operator()(const IPv4Address& a) const noexcept { std::size_t h=0; for(auto b:a.octets) h=h*131+b; return h; } };
    struct Window {
        TimePoint started{};
        std::unordered_set<Port> ports;
        std::size_t attempts{0};
        bool emitted{false};
    };
    PortScanConfig config_;
    std::unordered_map<IPv4Address, Window, AddressHash> windows_;
    std::unordered_set<FlowId> counted_flows_;
    mutable std::mutex mutex_;
};

} // namespace intriqo::detection
