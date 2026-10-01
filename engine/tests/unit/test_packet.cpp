/// Unit tests for intriqo::packet types.

#include <gtest/gtest.h>
#include "intriqo/packet/packet.hpp"

using namespace intriqo;
using namespace intriqo::packet;

TEST(ParsedPacket, TcpFlagHelpers) {
    ParsedPacket pkt;
    pkt.protocol  = Protocol::TCP;
    pkt.tcp_flags = 0x02;  // SYN only
    EXPECT_TRUE(pkt.is_tcp());
    EXPECT_TRUE(pkt.is_syn());
    EXPECT_FALSE(pkt.is_udp());
    EXPECT_FALSE(pkt.is_icmp());
}

TEST(ParsedPacket, UdpPacketNotSyn) {
    ParsedPacket pkt;
    pkt.protocol = Protocol::UDP;
    EXPECT_FALSE(pkt.is_tcp());
    EXPECT_FALSE(pkt.is_syn());
    EXPECT_TRUE(pkt.is_udp());
}

TEST(ParsedPacket, DefaultValuesAreZero) {
    ParsedPacket pkt;
    EXPECT_EQ(pkt.src_port, 0);
    EXPECT_EQ(pkt.dst_port, 0);
    EXPECT_EQ(pkt.total_length, 0u);
    EXPECT_EQ(pkt.payload_length, 0u);
}
