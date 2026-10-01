#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <chrono>
#include <array>

namespace intriqo {

// ── Timestamp ─────────────────────────────────────────────────────────────────
using Clock     = std::chrono::system_clock;
using TimePoint = std::chrono::time_point<Clock>;
using Duration  = std::chrono::duration<double>;  // seconds (fractional)

// ── Network primitives ────────────────────────────────────────────────────────
using Port       = std::uint16_t;
using PacketSize = std::uint32_t;
using ByteCount  = std::uint64_t;
using FlowId     = std::uint64_t;

/// IPv4 address stored as a 4-byte array (network byte order).
struct IPv4Address {
    std::array<std::uint8_t, 4> octets{};

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] bool        operator==(const IPv4Address&) const noexcept = default;
};

/// Layer-4 transport protocol.
enum class Protocol : std::uint8_t {
    TCP   = 6,
    UDP   = 17,
    ICMP  = 1,
    OTHER = 255,
};

[[nodiscard]] std::string_view protocol_name(Protocol p) noexcept;

} // namespace intriqo
