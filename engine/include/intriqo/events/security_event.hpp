#pragma once

#include "intriqo/common/types.hpp"
#include <string>
#include <unordered_map>
#include <variant>

namespace intriqo::events {

/// Severity levels for a SecurityEvent.
enum class Severity : std::uint8_t {
    LOW      = 0,
    MEDIUM   = 1,
    HIGH     = 2,
    CRITICAL = 3,
};

[[nodiscard]] std::string_view severity_name(Severity s) noexcept;

/// The type of detection that produced this event.
enum class EventType : std::uint16_t {
    PORT_SCAN        = 1,
    SYN_FLOOD        = 2,
    BRUTE_FORCE      = 3,
    DNS_ANOMALY      = 4,
    STATISTICAL_ANOMALY = 100,
    UNKNOWN          = 0xFFFF,
};

[[nodiscard]] std::string_view event_type_name(EventType t) noexcept;

/// Metadata value — a JSON-serialisable scalar.
using MetadataValue = std::variant<std::string, std::int64_t, double, bool>;

/// A structured security event produced by the IDS detection pipeline.
///
/// This is the primary output of the C++ engine.  Events cross the engine →
/// control-plane boundary as JSON conforming to the contracts/events/ schema.
struct SecurityEvent {
    std::string   event_id;       ///< UUID string
    TimePoint     timestamp;
    EventType     event_type{EventType::UNKNOWN};
    Severity      severity{Severity::LOW};
    IPv4Address   source_address;
    IPv4Address   destination_address;
    std::string   description;
    std::unordered_map<std::string, MetadataValue> details;

    /// Serialise to the cross-boundary JSON contract.
    [[nodiscard]] std::string to_json() const;
};

} // namespace intriqo::events
