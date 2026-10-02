#include "intriqo/common/types.hpp"
#include <sstream>

namespace intriqo {
std::string IPv4Address::to_string() const {
    return std::to_string(octets[0]) + "." + std::to_string(octets[1]) + "." +
           std::to_string(octets[2]) + "." + std::to_string(octets[3]);
}
std::string_view protocol_name(Protocol p) noexcept {
    switch (p) { case Protocol::TCP: return "TCP"; case Protocol::UDP: return "UDP";
    case Protocol::ICMP: return "ICMP"; default: return "OTHER"; }
}
bool operator<(const IPv4Address& a, const IPv4Address& b) noexcept { return a.octets < b.octets; }
}
