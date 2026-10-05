#pragma once

#include "intriqo/common/types.hpp"
#include "intriqo/packet/packet.hpp"
#include "intriqo/flow/iat.hpp"
#include <map>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace intriqo::flow {

/// Five-tuple uniquely identifying a network flow.
struct FlowKey {
    IPv4Address src_ip;
    IPv4Address dst_ip;
    Port        src_port{0};
    Port        dst_port{0};
    Protocol    protocol{Protocol::OTHER};

    [[nodiscard]] bool operator==(const FlowKey&) const noexcept = default;
};

/// Aggregated statistics for a single bidirectional network flow.
struct NetworkFlow {
    FlowId    flow_id{0};
    FlowKey   key;
    TimePoint first_seen;
    TimePoint last_seen;

    std::uint64_t packet_count{0};
    ByteCount     byte_count{0};
    std::uint64_t fwd_packet_count{0};
    std::uint64_t rev_packet_count{0};
    ByteCount     fwd_byte_count{0};
    ByteCount     rev_byte_count{0};
    std::uint32_t syn_count{0};
    std::uint32_t fin_count{0};
    std::uint32_t rst_count{0};
    // Additive TCP handshake counters and metadata follow the original
    // aggregate fields above so existing aggregate initialization remains
    // source-compatible.
    std::uint32_t initial_syn_count{0}; ///< SYN without ACK (connection attempts).
    std::uint32_t syn_ack_count{0};
    std::uint32_t ack_count{0}; ///< TCP ACKs without SYN.
    bool tcp_handshake_started{false};
    bool tcp_syn_ack_seen{false};
    bool tcp_handshake_completed{false};

    // Separately gated v2 observation state; v1 extraction never reads it.
    FlowIAT iat{};

    /// Duration of the flow in seconds.
    [[nodiscard]] double duration_seconds() const noexcept;

    /// Average bytes per packet.
    [[nodiscard]] double bytes_per_packet() const noexcept;

    /// Packets per second (0 if duration is zero).
    [[nodiscard]] double packets_per_second() const noexcept;
};

/// Flow lifecycle state.
enum class FlowState {
    ACTIVE,
    EXPIRED,   ///< Idle timeout exceeded
    FINISHED,  ///< FIN/RST observed (TCP)
};

struct FlowUpdate {
    NetworkFlow flow;
    bool created{false};
    std::vector<NetworkFlow> expired;
    std::optional<NetworkFlow> evicted;
};

class FlowTable {
public:
    explicit FlowTable(Duration idle_timeout = Duration{60.0},
                       std::size_t max_flows = 100000,
                       bool measure_iat = false);

    /// Expire idle flows before updating; evict the oldest idle flow if full.
    [[nodiscard]] FlowUpdate update(const packet::ParsedPacket& packet);
    [[nodiscard]] std::vector<NetworkFlow> expire(TimePoint now);
    [[nodiscard]] std::vector<NetworkFlow> flush();
    [[nodiscard]] std::size_t size() const noexcept { return flows_.size(); }

private:
    struct KeyHash {
        std::size_t operator()(const FlowKey& key) const noexcept;
    };
    [[nodiscard]] std::vector<NetworkFlow> collect_expired(TimePoint now) const;
    void erase_oldest(std::size_t count) noexcept;
    using IdleKey = std::pair<TimePoint, FlowId>;
    std::unordered_map<FlowKey, NetworkFlow, KeyHash> flows_;
    // Exactly one index entry per active flow; FlowId breaks timestamp ties.
    std::map<IdleKey, FlowKey> idle_index_;
    Duration idle_timeout_;
    std::size_t max_flows_;
    bool measure_iat_;
    FlowId next_id_{1};
};

} // namespace intriqo::flow
