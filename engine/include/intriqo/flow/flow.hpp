#pragma once

#include "intriqo/common/types.hpp"
#include <optional>

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

} // namespace intriqo::flow
