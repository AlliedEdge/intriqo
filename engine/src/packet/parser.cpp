#include "intriqo/protocol/protocol_parser.hpp"
#include <cstring>

namespace intriqo::protocol {
namespace {
std::uint16_t u16(const std::byte* p) noexcept { return (std::uint16_t(std::to_integer<unsigned char>(p[0])) << 8) | std::to_integer<unsigned char>(p[1]); }
bool has(std::span<const std::byte> b, std::size_t offset, std::size_t n) noexcept { return offset <= b.size() && n <= b.size() - offset; }
}
std::optional<packet::ParsedPacket> IPv4Parser::parse(packet::PacketView raw) const noexcept {
    auto b = raw.raw_bytes;
    std::size_t ip = 0;
    if (raw.link_layer_type == 1) { if (!has(b, 0, 14)) return std::nullopt; if (u16(b.data()+12) != 0x0800) return std::nullopt; ip = 14; }
    if (!has(b, ip, 20)) return std::nullopt;
    const auto vihl = std::to_integer<unsigned char>(b[ip]);
    if ((vihl >> 4) != 4 || (vihl & 0x0f) < 5) return std::nullopt;
    const std::size_t ihl = (vihl & 0x0f) * 4;
    if (!has(b, ip, ihl)) return std::nullopt;
    const auto total = u16(b.data()+ip+2);
    if (total < ihl || !has(b, ip, total)) return std::nullopt;
    packet::ParsedPacket out{}; out.timestamp = raw.timestamp; out.total_length = total;
    out.payload_length = total - ihl;
    out.src_ip.octets = {std::to_integer<unsigned char>(b[ip+12]), std::to_integer<unsigned char>(b[ip+13]), std::to_integer<unsigned char>(b[ip+14]), std::to_integer<unsigned char>(b[ip+15])};
    out.dst_ip.octets = {std::to_integer<unsigned char>(b[ip+16]), std::to_integer<unsigned char>(b[ip+17]), std::to_integer<unsigned char>(b[ip+18]), std::to_integer<unsigned char>(b[ip+19])};
    const auto proto = std::to_integer<unsigned char>(b[ip+9]);
    out.protocol = proto == 6 ? Protocol::TCP : proto == 17 ? Protocol::UDP : proto == 1 ? Protocol::ICMP : Protocol::OTHER;
    const auto l4 = ip + ihl;
    if (out.protocol == Protocol::TCP) { if (out.payload_length < 20) return std::nullopt; out.src_port=u16(b.data()+l4); out.dst_port=u16(b.data()+l4+2); const auto off=std::to_integer<unsigned char>(b[l4+12])>>4; if (off < 5 || off*4 > out.payload_length) return std::nullopt; out.tcp_flags=std::to_integer<unsigned char>(b[l4+13]); }
    else if (out.protocol == Protocol::UDP) { if (out.payload_length < 8) return std::nullopt; out.src_port=u16(b.data()+l4); out.dst_port=u16(b.data()+l4+2); if (u16(b.data()+l4+4) < 8 || u16(b.data()+l4+4) > out.payload_length) return std::nullopt; }
    else if (out.protocol == Protocol::ICMP) { if (out.payload_length < 4) return std::nullopt; }
    return out;
}
}
