#include "intriqo/detection/port_scan_detector.hpp"
#include "intriqo/events/security_event.hpp"

namespace intriqo::detection {
PortScanDetector::PortScanDetector(PortScanConfig c):config_(c){}
std::vector<events::SecurityEvent> PortScanDetector::evaluate(const flow::NetworkFlow& f,const features::FlowFeatures&) noexcept {
    std::lock_guard lock(mutex_); if (f.key.protocol != Protocol::TCP || f.key.src_ip == f.key.dst_ip || f.key.dst_port == 0 || counted_flows_.contains(f.flow_id)) return {};
    counted_flows_.insert(f.flow_id); auto& w=windows_[f.key.src_ip]; if(w.attempts==0 || std::chrono::duration<double>(f.last_seen-w.started).count() > config_.window_seconds) { w=Window{}; w.started=f.last_seen; }
    w.ports.insert(f.key.dst_port); ++w.attempts; if(!w.emitted && w.ports.size()>=config_.unique_port_threshold && w.attempts>=config_.minimum_attempts) { w.emitted=true; return {events::make_port_scan_event(f.key.src_ip,f.key.dst_ip,config_.severity,w.ports.size(),w.attempts,std::chrono::duration<double>(f.last_seen-w.started).count(),static_cast<std::uint16_t>(config_.unique_port_threshold),f.last_seen)}; } return {};
}
void PortScanDetector::reset() noexcept { std::lock_guard lock(mutex_); windows_.clear(); counted_flows_.clear(); }
}
