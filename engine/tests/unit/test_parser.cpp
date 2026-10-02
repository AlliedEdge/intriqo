#include <gtest/gtest.h>
#include "intriqo/protocol/protocol_parser.hpp"
#include <array>

using namespace intriqo;
namespace {
std::array<std::byte,54> tcp(std::uint16_t port) { std::array<std::byte,54> b{}; b[12]=std::byte{0x08}; b[13]=std::byte{0x00}; b[14]=std::byte{0x45}; b[16]=std::byte{0}; b[17]=std::byte{40}; b[23]=std::byte{6}; b[26]=std::byte{10}; b[29]=std::byte{1}; b[30]=std::byte{10}; b[33]=std::byte{2}; b[34]=std::byte{0x30}; b[35]=std::byte{0x39}; b[36]=std::byte{static_cast<unsigned char>(port>>8)}; b[37]=std::byte{static_cast<unsigned char>(port)}; b[46]=std::byte{0x50}; b[47]=std::byte{0x02}; return b; }
}
TEST(IPv4Parser, ParsesTcpAndRejectsTruncation) { auto b=tcp(80); protocol::IPv4Parser p; packet::PacketView v{Clock::now(),std::span<const std::byte>(b),1}; auto x=p.parse(v); ASSERT_TRUE(x); EXPECT_EQ(x->src_ip.to_string(),"10.0.0.1"); EXPECT_EQ(x->dst_port,80); EXPECT_TRUE(x->is_syn()); b[16]=std::byte{0}; v.raw_bytes=std::span<const std::byte>(b.data(),20); EXPECT_FALSE(p.parse(v)); }
TEST(IPv4Parser, RejectsInvalidHeaderLength) { auto b=tcp(80); b[14]=std::byte{0x44}; protocol::IPv4Parser p; EXPECT_FALSE(p.parse({Clock::now(),std::span<const std::byte>(b),1})); }
