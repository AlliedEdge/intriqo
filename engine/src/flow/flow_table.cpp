#include "intriqo/flow/flow.hpp"
#include <cmath>
#include <stdexcept>

namespace intriqo::flow {
namespace {
FlowKey reverse(const FlowKey& key) {
    return {key.dst_ip, key.src_ip, key.dst_port, key.src_port, key.protocol};
}

long double elapsed_seconds(TimePoint end, TimePoint start) noexcept {
    // Widen ticks before subtracting to avoid overflow; scale after subtraction
    // so short durations retain precision even far from the clock's epoch.
    const auto ticks = static_cast<long double>(end.time_since_epoch().count())
                     - static_cast<long double>(start.time_since_epoch().count());
    return std::chrono::duration<long double>(
        std::chrono::duration<long double, Clock::duration::period>{ticks}).count();
}
}

std::size_t FlowTable::KeyHash::operator()(const FlowKey& key) const noexcept {
    std::size_t hash = 0;
    for (auto byte : key.src_ip.octets) hash = hash * 131 + byte;
    for (auto byte : key.dst_ip.octets) hash = hash * 131 + byte;
    hash = hash * 131 + key.src_port;
    hash = hash * 131 + key.dst_port;
    return hash * 131 + static_cast<unsigned>(key.protocol);
}

FlowTable::FlowTable(Duration timeout, std::size_t max_flows, bool measure_iat)
    : idle_timeout_(timeout), max_flows_(max_flows), measure_iat_(measure_iat) {
    if (!std::isfinite(timeout.count()) || timeout.count() <= 0.0)
        throw std::invalid_argument("flow idle timeout must be finite and positive");
    if (max_flows == 0)
        throw std::invalid_argument("maximum active flows must be positive");
}

FlowUpdate FlowTable::update(const packet::ParsedPacket& packet) {
    FlowUpdate result;
    // Finish allocating retirement output before changing either index.
    result.expired = collect_expired(packet.timestamp);

    FlowKey direct{packet.src_ip, packet.dst_ip, packet.src_port,
                   packet.dst_port, packet.protocol};
    auto it = flows_.find(direct);
    bool forward = true;
    if (it == flows_.end()) {
        it = flows_.find(reverse(direct));
        forward = false;
    }
    if (!result.expired.empty() && it != flows_.end()
        && elapsed_seconds(packet.timestamp, it->second.last_seen) >= idle_timeout_.count())
        it = flows_.end();
    if (it == flows_.end()) {
        NetworkFlow flow;
        flow.flow_id = next_id_;
        flow.key = direct;
        flow.first_seen = flow.last_seen = packet.timestamp;
        flow.iat.enabled = measure_iat_;
        constexpr std::uint8_t syn = 0x02;
        constexpr std::uint8_t ack = 0x10;
        constexpr std::uint8_t fin = 0x01;
        constexpr std::uint8_t rst = 0x04;
        flow.tcp_handshake_started = packet.is_tcp()
            && (packet.tcp_flags & syn) != 0
            && (packet.tcp_flags & (ack | fin | rst)) == 0;
        if (!result.expired.empty() || flows_.size() == max_flows_) {
            auto oldest = idle_index_.begin();
            auto victim = flows_.find(oldest->second);
            if (result.expired.empty()) result.evicted = victim->second;

            // Reuse both retired nodes. At an equal or smaller hash-table size
            // this needs no rehash; neither index ever exceeds the cap.
            auto flow_node = flows_.extract(victim);
            auto idle_node = idle_index_.extract(oldest);
            if (!result.expired.empty()) erase_oldest(result.expired.size() - 1);
            flow_node.key() = direct;
            flow_node.mapped() = flow;
            idle_node.key() = IdleKey{flow.last_seen, flow.flow_id};
            idle_node.mapped() = direct;
            it = flows_.insert(std::move(flow_node)).position;
            idle_index_.insert(std::move(idle_node));
        } else {
            it = flows_.emplace(direct, flow).first;
            try {
                idle_index_.emplace(IdleKey{flow.last_seen, flow.flow_id}, direct);
            } catch (...) {
                // Keep both indexes consistent if allocating a node fails.
                flows_.erase(it);
                throw;
            }
        }
        ++next_id_;
        result.created = true;
        forward = true;
    } else {
        erase_oldest(result.expired.size());
    }

    auto& flow = it->second;
    if (packet.timestamp > flow.last_seen) {
        // Reuse the existing node rather than accumulating stale heap entries.
        auto idle = idle_index_.extract(IdleKey{flow.last_seen, flow.flow_id});
        idle.key().first = packet.timestamp;
        idle_index_.insert(std::move(idle));
        flow.last_seen = packet.timestamp;
    }
    // Late packets contribute counters without rewinding last_seen/idle order.
    // first_seen remains the timestamp of the packet that created the flow.
    flow.iat.observe(packet.timestamp, flow.packet_count == 0);
    ++flow.packet_count;
    flow.byte_count += packet.total_length;
    if (packet.is_tcp()) {
        constexpr std::uint8_t syn = 0x02;
        constexpr std::uint8_t ack = 0x10;
        constexpr std::uint8_t fin = 0x01;
        constexpr std::uint8_t rst = 0x04;
        if (packet.tcp_flags & 0x02) ++flow.syn_count;
        if ((packet.tcp_flags & (syn | ack | fin | rst)) == syn)
            ++flow.initial_syn_count;
        if ((packet.tcp_flags & (syn | ack | fin | rst)) == (syn | ack))
            ++flow.syn_ack_count;
        if ((packet.tcp_flags & (ack | syn | fin | rst)) == ack)
            ++flow.ack_count;
        if (packet.tcp_flags & 0x01) ++flow.fin_count;
        if (packet.tcp_flags & 0x04) ++flow.rst_count;
        if (!forward && flow.tcp_handshake_started
            && (packet.tcp_flags & (syn | ack)) == (syn | ack)
            && (packet.tcp_flags & (fin | rst)) == 0) {
            flow.tcp_syn_ack_seen = true;
        }
        if (forward && flow.tcp_syn_ack_seen
            && (packet.tcp_flags & ack) != 0
            && (packet.tcp_flags & (syn | fin | rst)) == 0) {
            flow.tcp_handshake_completed = true;
        }
    }
    if (forward) {
        ++flow.fwd_packet_count;
        flow.fwd_byte_count += packet.total_length;
    } else {
        ++flow.rev_packet_count;
        flow.rev_byte_count += packet.total_length;
    }
    result.flow = flow;
    return result;
}

std::vector<NetworkFlow> FlowTable::collect_expired(TimePoint now) const {
    std::vector<NetworkFlow> expired;
    for (auto it = idle_index_.begin(); it != idle_index_.end(); ++it) {
        if (elapsed_seconds(now, it->first.first) < idle_timeout_.count())
            break;
        auto flow = flows_.find(it->second);
        expired.push_back(flow->second);
    }
    return expired;
}

void FlowTable::erase_oldest(std::size_t count) noexcept {
    for (std::size_t i = 0; i < count; ++i) {
        auto oldest = idle_index_.begin();
        flows_.erase(oldest->second);
        idle_index_.erase(oldest);
    }
}

std::vector<NetworkFlow> FlowTable::expire(TimePoint now) {
    auto expired = collect_expired(now);
    erase_oldest(expired.size());
    return expired;
}

std::vector<NetworkFlow> FlowTable::flush() {
    std::vector<NetworkFlow> flushed;
    flushed.reserve(flows_.size());
    for (const auto& [idle, key] : idle_index_)
        flushed.push_back(flows_.find(key)->second);
    flows_.clear();
    idle_index_.clear();
    return flushed;
}

double NetworkFlow::duration_seconds() const noexcept {
    return static_cast<double>(elapsed_seconds(last_seen, first_seen));
}

double NetworkFlow::bytes_per_packet() const noexcept {
    return packet_count ? static_cast<double>(byte_count) / packet_count : 0.0;
}

double NetworkFlow::packets_per_second() const noexcept {
    auto duration = duration_seconds();
    return duration > 0 ? packet_count / duration : 0.0;
}
}
