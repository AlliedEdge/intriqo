/// Unit tests for intriqo::events::SecurityEvent.

#include <gtest/gtest.h>
#include "intriqo/events/security_event.hpp"

using namespace intriqo::events;

TEST(Severity, OrderingIsCorrect) {
    EXPECT_LT(static_cast<int>(Severity::LOW),      static_cast<int>(Severity::MEDIUM));
    EXPECT_LT(static_cast<int>(Severity::MEDIUM),   static_cast<int>(Severity::HIGH));
    EXPECT_LT(static_cast<int>(Severity::HIGH),     static_cast<int>(Severity::CRITICAL));
}

TEST(EventType, PortScanHasExpectedValue) {
    EXPECT_EQ(static_cast<uint16_t>(EventType::PORT_SCAN), 1u);
}

TEST(SecurityEvent, DefaultConstruction) {
    SecurityEvent e;
    EXPECT_TRUE(e.event_id.empty());
    EXPECT_EQ(e.event_type, EventType::UNKNOWN);
    EXPECT_EQ(e.severity,   Severity::LOW);
    EXPECT_TRUE(e.description.empty());
    EXPECT_TRUE(e.details.empty());
}
