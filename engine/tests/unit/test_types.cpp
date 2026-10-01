/// Unit tests for intriqo::common types.
/// These tests establish that the foundation types compile and behave correctly
/// before any protocol parser or detector is implemented.

#include <gtest/gtest.h>
#include "intriqo/common/types.hpp"

using namespace intriqo;

TEST(IPv4Address, DefaultConstructedIsZero) {
    IPv4Address addr{};
    for (auto b : addr.octets) {
        EXPECT_EQ(b, 0);
    }
}

TEST(IPv4Address, EqualitySymmetric) {
    IPv4Address a{{192, 168, 1, 10}};
    IPv4Address b{{192, 168, 1, 10}};
    IPv4Address c{{10,  0,  0,  1}};
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST(Protocol, TCPHasCorrectWireValue) {
    EXPECT_EQ(static_cast<uint8_t>(Protocol::TCP),  6);
    EXPECT_EQ(static_cast<uint8_t>(Protocol::UDP),  17);
    EXPECT_EQ(static_cast<uint8_t>(Protocol::ICMP), 1);
}
