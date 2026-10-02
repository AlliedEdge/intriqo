#include "intriqo/flow/flow.hpp"
#include <algorithm>

namespace intriqo::flow {
namespace { FlowKey reverse(const FlowKey& k) { return {k.dst_ip,k.src_ip,k.dst_port,k.src_port,k.protocol}; } }
std::size_t FlowTable::KeyHash::operator()(const FlowKey& k) const noexcept {
    std::size_t h=0; for (auto b:k.src_ip.octets) h=h*131+b; for(auto b:k.dst_ip.octets) h=h*131+b; h=h*131+k.src_port; h=h*131+k.dst_port; return h*131+static_cast<unsigned>(k.protocol);
}
FlowTable::FlowTable(Duration timeout): idle_timeout_(timeout) {}
FlowUpdate FlowTable::update(const packet::ParsedPacket& p) {
    FlowKey direct{p.src_ip,p.dst_ip,p.src_port,p.dst_port,p.protocol};
    FlowKey reverse_key=reverse(direct); auto it=flows_.find(direct); bool forward=true;
    if (it==flows_.end()) { it=flows_.find(reverse_key); forward=false; }
    if (it==flows_.end()) { NetworkFlow f; f.flow_id=next_id_++; f.key=direct; f.first_seen=f.last_seen=p.timestamp; it=flows_.emplace(direct,f).first; }
    auto& f=it->second; f.last_seen=p.timestamp; ++f.packet_count; f.byte_count += p.total_length;
    if (p.is_tcp()) { if (p.tcp_flags & 0x02) ++f.syn_count; if (p.tcp_flags & 0x01) ++f.fin_count; if (p.tcp_flags & 0x04) ++f.rst_count; }
    if (forward) { ++f.fwd_packet_count; f.fwd_byte_count += p.total_length; } else { ++f.rev_packet_count; f.rev_byte_count += p.total_length; }
    return {f, f.packet_count == 1};
}
std::vector<NetworkFlow> FlowTable::expire(TimePoint now) { std::vector<NetworkFlow> out; for(auto it=flows_.begin();it!=flows_.end();) { if(now-it->second.last_seen >= idle_timeout_) {out.push_back(it->second); it=flows_.erase(it);} else ++it;} return out; }
std::vector<NetworkFlow> FlowTable::flush() { std::vector<NetworkFlow> out; for(auto& [k,v]:flows_) out.push_back(v); flows_.clear(); return out; }
double NetworkFlow::duration_seconds() const noexcept { return std::chrono::duration<double>(last_seen-first_seen).count(); }
double NetworkFlow::bytes_per_packet() const noexcept { return packet_count ? static_cast<double>(byte_count)/packet_count : 0.0; }
double NetworkFlow::packets_per_second() const noexcept { auto d=duration_seconds(); return d>0 ? packet_count/d : 0.0; }
}
