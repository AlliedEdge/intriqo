#pragma once

#include "intriqo/common/types.hpp"
#include <span>
#include <vector>

namespace intriqo::packet {

/// Immutable view of a captured network packet.
///
/// Ownership of the underlying bytes stays with the capture layer.
/// Parsers and detectors receive a PacketView and must not outlive it.
struct PacketView {
    TimePoint              timestamp;
    std::span<const std::byte> raw_bytes;   ///< Full packet payload
    std::size_t            link_layer_type; ///< e.g. DLT_EN10MB = 1
};

/// Parsed L3/L4 packet header — produced by the packet parser.
struct ParsedPacket {
    TimePoint   timestamp;
    IPv4Address src_ip;
    IPv4Address dst_ip;
    Port        src_port{0};
    Port        dst_port{0};
    Protocol    protocol{Protocol::OTHER};
    PacketSize  total_length{0};
    PacketSize  payload_length{0};
    std::uint8_t tcp_flags{0};  ///< TCP control bits (SYN=0x02, ACK=0x10, etc.)

    [[nodiscard]] bool is_tcp()  const noexcept { return protocol == Protocol::TCP;  }
    [[nodiscard]] bool is_udp()  const noexcept { return protocol == Protocol::UDP;  }
    [[nodiscard]] bool is_icmp() const noexcept { return protocol == Protocol::ICMP; }
    [[nodiscard]] bool is_syn()  const noexcept { return is_tcp() && (tcp_flags & 0x02); }
};

} // namespace intriqo::packet
