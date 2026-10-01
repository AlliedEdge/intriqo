#pragma once

#include "intriqo/packet/packet.hpp"
#include <optional>
#include <span>

namespace intriqo::protocol {

/// Layer-4 protocol parser interface.
///
/// Parsers are stateless — they receive raw bytes and return a parsed packet.
/// Protocol-specific state (e.g. TCP reassembly) belongs in the flow layer.
class ProtocolParser {
public:
    virtual ~ProtocolParser() = default;

    /// Parse a raw packet payload into a ParsedPacket.
    ///
    /// Returns std::nullopt if the payload is malformed, too short,
    /// or does not match the expected protocol.
    [[nodiscard]] virtual std::optional<packet::ParsedPacket>
    parse(packet::PacketView raw) const noexcept = 0;
};

} // namespace intriqo::protocol
