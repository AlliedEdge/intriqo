#include "intriqo/features/features.hpp"
namespace intriqo::features {
FlowFeatures FlowFeatures::from_flow(const flow::NetworkFlow& f) noexcept {
    FlowFeatures x; x.packet_count=f.packet_count; x.byte_count=f.byte_count; x.duration_seconds=f.duration_seconds(); x.bytes_per_packet=f.bytes_per_packet(); x.packets_per_second=f.packets_per_second(); x.bytes_per_second=x.duration_seconds>0?f.byte_count/x.duration_seconds:0.0; x.syn_count=f.syn_count; x.fin_count=f.fin_count; x.rst_count=f.rst_count; x.connection_attempts=static_cast<std::uint32_t>(f.packet_count); return x;
}
}
