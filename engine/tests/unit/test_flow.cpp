/// Unit tests for intriqo::flow types.

#include <gtest/gtest.h>
#include "intriqo/flow/flow.hpp"
#include "intriqo/features/features.hpp"
#include <chrono>

using namespace intriqo;
using namespace intriqo::flow;

namespace {

const IPv4Address kClient{{10, 0, 0, 1}};
const IPv4Address kServer{{10, 0, 0, 2}};

TimePoint fixture_time() {
    return TimePoint{std::chrono::seconds{1'700'000'000}};
}

packet::ParsedPacket tcp_packet(const IPv4Address& source,
                                const IPv4Address& destination,
                                Port source_port,
                                Port destination_port,
                                std::uint8_t flags) {
    packet::ParsedPacket packet{};
    packet.timestamp = fixture_time();
    packet.src_ip = source;
    packet.dst_ip = destination;
    packet.src_port = source_port;
    packet.dst_port = destination_port;
    packet.protocol = Protocol::TCP;
    packet.tcp_flags = flags;
    packet.total_length = 40;
    return packet;
}

} // namespace

TEST(FlowKey, EqualityByAllFields) {
    FlowKey a{{{10,0,0,1}}, {{10,0,0,2}}, 12345, 80, Protocol::TCP};
    FlowKey b{{{10,0,0,1}}, {{10,0,0,2}}, 12345, 80, Protocol::TCP};
    FlowKey c{{{10,0,0,1}}, {{10,0,0,2}}, 12345, 81, Protocol::TCP};  // different dst_port
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST(NetworkFlow, DefaultCountersAreZero) {
    NetworkFlow f;
    EXPECT_EQ(f.packet_count, 0u);
    EXPECT_EQ(f.byte_count,   0u);
    EXPECT_FALSE(f.tcp_handshake_started);
    EXPECT_FALSE(f.tcp_syn_ack_seen);
    EXPECT_FALSE(f.tcp_handshake_completed);
}

TEST(FlowTable, OrderedNormalHandshakeSetsMetadata) {
    FlowTable table;
    const auto syn = table.update(tcp_packet(kClient, kServer, 40000, 443, 0x02));
    ASSERT_TRUE(syn.created);
    EXPECT_TRUE(syn.flow.tcp_handshake_started);
    EXPECT_FALSE(syn.flow.tcp_syn_ack_seen);
    EXPECT_FALSE(syn.flow.tcp_handshake_completed);
    EXPECT_EQ(syn.flow.initial_syn_count, 1u);

    const auto syn_ack = table.update(tcp_packet(kServer, kClient, 443, 40000, 0x12));
    EXPECT_FALSE(syn_ack.created);
    EXPECT_TRUE(syn_ack.flow.tcp_handshake_started);
    EXPECT_TRUE(syn_ack.flow.tcp_syn_ack_seen);
    EXPECT_FALSE(syn_ack.flow.tcp_handshake_completed);
    EXPECT_EQ(syn_ack.flow.syn_ack_count, 1u);

    const auto ack = table.update(tcp_packet(kClient, kServer, 40000, 443, 0x10));
    EXPECT_TRUE(ack.flow.tcp_handshake_started);
    EXPECT_TRUE(ack.flow.tcp_syn_ack_seen);
    EXPECT_TRUE(ack.flow.tcp_handshake_completed);
    EXPECT_EQ(ack.flow.ack_count, 1u);
}

TEST(FlowTable, AckOnlyFirstPacketDoesNotStartHandshake) {
    FlowTable table;
    const auto update = table.update(tcp_packet(kClient, kServer, 40000, 443, 0x10));

    EXPECT_FALSE(update.flow.tcp_handshake_started);
    EXPECT_FALSE(update.flow.tcp_syn_ack_seen);
    EXPECT_FALSE(update.flow.tcp_handshake_completed);
    EXPECT_EQ(update.flow.ack_count, 1u);
}

TEST(FlowTable, ReverseAckWithoutSynAckDoesNotComplete) {
    FlowTable table;
    (void)table.update(tcp_packet(kClient, kServer, 40000, 443, 0x02));
    const auto update = table.update(tcp_packet(kServer, kClient, 443, 40000, 0x10));

    EXPECT_TRUE(update.flow.tcp_handshake_started);
    EXPECT_FALSE(update.flow.tcp_syn_ack_seen);
    EXPECT_FALSE(update.flow.tcp_handshake_completed);
}

TEST(FlowTable, SynAckFirstPacketDoesNotStartHandshake) {
    FlowTable table;
    const auto update = table.update(tcp_packet(kServer, kClient, 443, 40000, 0x12));

    EXPECT_FALSE(update.flow.tcp_handshake_started);
    EXPECT_FALSE(update.flow.tcp_syn_ack_seen);
    EXPECT_FALSE(update.flow.tcp_handshake_completed);
    EXPECT_EQ(update.flow.syn_ack_count, 1u);
}

TEST(FlowTable, AckBeforeSynAckDoesNotCompleteInRetrospect) {
    FlowTable table;
    (void)table.update(tcp_packet(kClient, kServer, 40000, 443, 0x02));
    const auto early_ack = table.update(tcp_packet(kClient, kServer, 40000, 443, 0x10));
    EXPECT_FALSE(early_ack.flow.tcp_handshake_completed);

    const auto syn_ack = table.update(tcp_packet(kServer, kClient, 443, 40000, 0x12));
    EXPECT_TRUE(syn_ack.flow.tcp_syn_ack_seen);
    EXPECT_FALSE(syn_ack.flow.tcp_handshake_completed);

    const auto final_ack = table.update(tcp_packet(kClient, kServer, 40000, 443, 0x10));
    EXPECT_TRUE(final_ack.flow.tcp_handshake_completed);
}

TEST(FlowTable, RstAckCannotCompleteHandshake) {
    FlowTable table;
    (void)table.update(tcp_packet(kClient, kServer, 40000, 443, 0x02));
    (void)table.update(tcp_packet(kServer, kClient, 443, 40000, 0x12));
    const auto update = table.update(tcp_packet(kClient, kServer, 40000, 443, 0x14));

    EXPECT_TRUE(update.flow.tcp_syn_ack_seen);
    EXPECT_FALSE(update.flow.tcp_handshake_completed);
}

TEST(FlowTable, FeatureExtractionCopiesHandshakeMetadata) {
    FlowTable table;
    (void)table.update(tcp_packet(kClient, kServer, 40000, 443, 0x02));
    (void)table.update(tcp_packet(kServer, kClient, 443, 40000, 0x12));
    const auto complete = table.update(tcp_packet(kClient, kServer, 40000, 443, 0x10));
    const auto features = features::FlowFeatures::from_flow(complete.flow);

    EXPECT_EQ(features.initial_syn_count, 1u);
    EXPECT_EQ(features.syn_ack_count, 1u);
    EXPECT_EQ(features.ack_count, 1u);
    EXPECT_TRUE(features.tcp_handshake_started);
    EXPECT_TRUE(features.tcp_syn_ack_seen);
    EXPECT_TRUE(features.tcp_handshake_completed);
}

TEST(FlowState, AllVariantsExist) {
    // Compilation test — ensures the enum is complete
    [[maybe_unused]] FlowState s1 = FlowState::ACTIVE;
    [[maybe_unused]] FlowState s2 = FlowState::EXPIRED;
    [[maybe_unused]] FlowState s3 = FlowState::FINISHED;
}
