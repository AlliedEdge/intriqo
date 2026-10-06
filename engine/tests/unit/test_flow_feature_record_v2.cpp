#include <gtest/gtest.h>
#include "intriqo/features/flow_feature_record_v2.hpp"
#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/detection/port_scan_detector.hpp"
#include "intriqo/protocol/protocol_parser.hpp"
#include <array>
#include <cmath>
#include <limits>
#include <vector>

using intriqo::TimePoint;
using intriqo::PacketSize;
using intriqo::Duration;
using intriqo::Protocol;
namespace flow = intriqo::flow;
namespace features = intriqo::features;
namespace pipeline = intriqo::pipeline;
namespace protocol = intriqo::protocol;
namespace {
constexpr auto id = "123e4567-e89b-42d3-a456-426614174000";
intriqo::packet::ParsedPacket packet(std::int64_t nanoseconds, bool reverse = false,
                            PacketSize bytes = 40, std::uint8_t flags = 0x10,
                            Protocol protocol = Protocol::TCP) {
    intriqo::packet::ParsedPacket p{};
    p.timestamp = TimePoint{std::chrono::seconds{1700000000}} + std::chrono::nanoseconds{nanoseconds};
    p.src_ip = {{192,0,2,10}}; p.dst_ip = {{198,51,100,20}};
    p.src_port = 40000; p.dst_port = 443;
    p.total_length = bytes; p.tcp_flags = flags; p.protocol = protocol;
    if (reverse) { std::swap(p.src_ip, p.dst_ip); std::swap(p.src_port, p.dst_port); }
    return p;
}
features::FlowFeatureRecordV2 record(const flow::NetworkFlow& f) {
    return features::FlowFeatureRecordV2::from_flow(f, id, features::FlowExportReason::shutdown_flush);
}

struct V2Records final : intriqo::transport::FlowFeatureSink {
    std::vector<features::FlowFeatureRecordV2> records;

    bool submit(const features::FlowFeatureRecord&) noexcept override { return false; }
    bool submit_v2(const features::FlowFeatureRecordV2& value) noexcept override {
        try {
            records.push_back(value);
            return true;
        } catch (...) {
            return false;
        }
    }
};

std::array<std::byte, 54> tcp_frame() {
    std::array<std::byte, 54> bytes{};
    bytes[12] = std::byte{0x08}; bytes[13] = std::byte{0x00};
    bytes[14] = std::byte{0x45};
    bytes[16] = std::byte{0x00}; bytes[17] = std::byte{0x28}; // IPv4 total length: 40
    bytes[23] = std::byte{0x06};
    bytes[26] = std::byte{192}; bytes[27] = std::byte{0};
    bytes[28] = std::byte{2}; bytes[29] = std::byte{10};
    bytes[30] = std::byte{198}; bytes[31] = std::byte{51};
    bytes[32] = std::byte{100}; bytes[33] = std::byte{20};
    bytes[34] = std::byte{0x9c}; bytes[35] = std::byte{0x40};
    bytes[36] = std::byte{0x01}; bytes[37] = std::byte{0xbb};
    bytes[46] = std::byte{0x50}; bytes[47] = std::byte{0x02};
    return bytes;
}
}

TEST(FlowFeaturesV2, BalancedBidirectionalNormalTcpAndSynAckCountsAsSyn) {
    flow::FlowTable table(Duration{60}, 100, true);
    (void)table.update(packet(0, false, 40, 0x02));
    (void)table.update(packet(1000000000, true, 40, 0x12));
    auto r = record(table.update(packet(3000000000)).flow);
    EXPECT_EQ(r.values.packet_count, 3U);
    EXPECT_DOUBLE_EQ(r.values.duration_seconds, 3);
    EXPECT_DOUBLE_EQ(r.values.packets_per_second, 1);
    EXPECT_DOUBLE_EQ(r.values.minor_direction_packet_fraction, 1.0/3);
    EXPECT_DOUBLE_EQ(r.values.ipv4_direction_byte_imbalance, 1.0/3);
    EXPECT_DOUBLE_EQ(r.values.mean_ipv4_packet_bytes, 40);
    EXPECT_DOUBLE_EQ(r.values.syn_packet_fraction, 2.0/3);
    EXPECT_DOUBLE_EQ(r.values.fin_packet_fraction, 0);
    EXPECT_DOUBLE_EQ(r.values.flow_iat_std_seconds, 0.5);
    EXPECT_TRUE(r.features.tcp_handshake_completed);
    EXPECT_NE(r.to_json().find("\"schema_version\":\"flow_features.v2\""), std::string::npos);
    EXPECT_NE(r.to_json().find("\"measurements\":{"), std::string::npos);
}

TEST(FlowFeaturesV2, BalancedUdp) {
    flow::FlowTable table(Duration{60}, 100, true);
    (void)table.update(packet(0, false, 31, 0, Protocol::UDP));
    auto r = record(table.update(packet(1000000000, true, 31, 0, Protocol::UDP)).flow);
    EXPECT_DOUBLE_EQ(r.values.minor_direction_packet_fraction, 0.5);
    EXPECT_DOUBLE_EQ(r.values.ipv4_direction_byte_imbalance, 0);
    EXPECT_DOUBLE_EQ(r.values.mean_ipv4_packet_bytes, 31);
    EXPECT_DOUBLE_EQ(r.values.syn_packet_fraction, 0);
    EXPECT_DOUBLE_EQ(r.values.fin_packet_fraction, 0);
    EXPECT_DOUBLE_EQ(r.values.flow_iat_std_seconds, 0);
}

TEST(FlowFeaturesV2, OneDirectionalSynHeavyAndFinHeavy) {
    for (std::uint8_t flags : std::array<std::uint8_t,2>{0x02, 0x01}) {
        flow::FlowTable table(Duration{60}, 100, true);
        (void)table.update(packet(0, false, 40, flags));
        (void)table.update(packet(1000000000, false, 40, flags));
        auto r = record(table.update(packet(2000000000, false, 40, flags)).flow);
        EXPECT_DOUBLE_EQ(r.values.minor_direction_packet_fraction, 0);
        EXPECT_DOUBLE_EQ(r.values.ipv4_direction_byte_imbalance, 1);
        EXPECT_DOUBLE_EQ(r.values.syn_packet_fraction, flags == 0x02 ? 1 : 0);
        EXPECT_DOUBLE_EQ(r.values.fin_packet_fraction, flags == 0x01 ? 1 : 0);
        EXPECT_EQ(table.size(), 1U); // FIN did not change retirement.
    }
}

TEST(FlowFeaturesV2, AsymmetricCountsBytesAndOrientationIndependence) {
    for (bool reverse : {false, true}) {
        flow::FlowTable table(Duration{60}, 100, true);
        (void)table.update(packet(0, reverse, 100));
        (void)table.update(packet(1000000000, reverse, 100));
        (void)table.update(packet(2000000000, !reverse, 40));
        auto r = record(table.update(packet(3000000000, reverse, 80)).flow);
        EXPECT_DOUBLE_EQ(r.values.minor_direction_packet_fraction, 0.25);
        EXPECT_DOUBLE_EQ(r.values.ipv4_direction_byte_imbalance, 0.75);
        EXPECT_DOUBLE_EQ(r.values.mean_ipv4_packet_bytes, 80);
    }
}

TEST(FlowFeaturesV2, OnePacketAndTwoPacketPopulationStdAreZero) {
    flow::FlowTable table(Duration{60}, 100, true);
    auto r = record(table.update(packet(0)).flow);
    EXPECT_DOUBLE_EQ(r.values.duration_seconds, 0);
    EXPECT_DOUBLE_EQ(r.values.packets_per_second, 0);
    EXPECT_DOUBLE_EQ(r.values.flow_iat_std_seconds, 0);
    EXPECT_EQ(r.iat_gap_count, 0U);
    r = record(table.update(packet(2000000000)).flow);
    EXPECT_DOUBLE_EQ(r.values.flow_iat_std_seconds, 0);
    EXPECT_EQ(r.iat_gap_count, 1U);
}

TEST(FlowFeaturesV2, MultipleIntervalsUsePopulationNotSampleVariance) {
    flow::FlowTable table(Duration{60}, 100, true);
    (void)table.update(packet(0));
    (void)table.update(packet(1000000000));
    (void)table.update(packet(3000000000));
    auto r = record(table.update(packet(6000000000)).flow);
    EXPECT_NEAR(r.values.flow_iat_std_seconds, std::sqrt(2.0/3), 1e-15);
    EXPECT_EQ(r.iat_gap_count, 3U);
}

TEST(FlowFeaturesV2, EqualTimestampsPreserveZeroDurationBehavior) {
    flow::FlowTable table(Duration{60}, 100, true);
    (void)table.update(packet(0)); (void)table.update(packet(0, true));
    auto r = record(table.update(packet(0)).flow);
    EXPECT_DOUBLE_EQ(r.values.duration_seconds, 0);
    EXPECT_DOUBLE_EQ(r.values.packets_per_second, 0);
    EXPECT_DOUBLE_EQ(r.values.flow_iat_std_seconds, 0);
    EXPECT_FALSE(r.to_json().empty());
}

TEST(FlowFeaturesV2, NanosecondGapsAreNotLostAtLargeEpoch) {
    flow::FlowTable table(Duration{60}, 100, true);
    (void)table.update(packet(0)); (void)table.update(packet(1));
    auto r = record(table.update(packet(4)).flow);
    EXPECT_NEAR(r.values.flow_iat_std_seconds, 1e-9, 1e-24);
}

TEST(FlowFeaturesV2, OutOfOrderTimeInvalidatesV2WithoutChangingV1State) {
    flow::FlowTable v1, v2(Duration{60}, 100000, true);
    for (auto ns : {100, 200, 50, 300}) {
        auto p = packet(ns);
        auto a = v1.update(p).flow; auto b = v2.update(p).flow;
        EXPECT_EQ(features::FlowFeatureRecord::from_flow(a,id,features::FlowExportReason::shutdown_flush).to_json(),
                  features::FlowFeatureRecord::from_flow(b,id,features::FlowExportReason::shutdown_flush).to_json());
        if (ns == 50 || ns == 300) { EXPECT_THROW(record(b), std::invalid_argument); }
    }
}

TEST(FlowFeaturesV2, MissingTimingMeasurementCannotBeInvented) {
    flow::FlowTable table;
    EXPECT_THROW(record(table.update(packet(0)).flow), std::invalid_argument);
}

TEST(FlowFeaturesV2, ZeroDenominatorsAreExplicitAndFinite) {
    flow::NetworkFlow f{}; f.flow_id=1; f.iat.enabled=true;
    auto r=record(f);
    EXPECT_EQ(r.values.packet_count, 0U);
    EXPECT_DOUBLE_EQ(r.values.minor_direction_packet_fraction,0);
    EXPECT_DOUBLE_EQ(r.values.ipv4_direction_byte_imbalance,0);
    EXPECT_DOUBLE_EQ(r.values.mean_ipv4_packet_bytes,0);
    EXPECT_DOUBLE_EQ(r.values.syn_packet_fraction,0);
    EXPECT_DOUBLE_EQ(r.values.fin_packet_fraction,0);
}

TEST(FlowFeaturesV2, NonfiniteAndTamperedValuesAreRejected) {
    flow::FlowTable table(Duration{60}, 100, true);
    auto original=record(table.update(packet(0)).flow);
    const std::array<double features::FlowFeaturesV2::*,8> fields{
        &features::FlowFeaturesV2::duration_seconds, &features::FlowFeaturesV2::packets_per_second,
        &features::FlowFeaturesV2::minor_direction_packet_fraction, &features::FlowFeaturesV2::mean_ipv4_packet_bytes,
        &features::FlowFeaturesV2::ipv4_direction_byte_imbalance, &features::FlowFeaturesV2::syn_packet_fraction,
        &features::FlowFeaturesV2::fin_packet_fraction, &features::FlowFeaturesV2::flow_iat_std_seconds};
    for(auto field:fields) for(auto value:{-1.0, std::numeric_limits<double>::infinity(),
                                         std::numeric_limits<double>::quiet_NaN()}) {
        auto r=original; r.values.*field=value;
        EXPECT_THROW((void)r.to_json(),std::invalid_argument);
    }
    original.iat_gap_count=1;
    EXPECT_THROW((void)original.to_json(),std::invalid_argument);
    original.iat_gap_count=0;
    original.features.duration_seconds=1;
    original.values.duration_seconds=1;
    EXPECT_THROW((void)original.to_json(),std::invalid_argument);
    auto f=table.update(packet(1)).flow; f.iat.m2_ticks=std::numeric_limits<long double>::infinity();
    EXPECT_THROW(record(f),std::invalid_argument);
}

TEST(FlowFeaturesV2, EnabledV2StreamDoesNotChangeDeterministicSecurityEvents) {
    struct Records final : intriqo::transport::FlowFeatureSink {
        std::size_t count{0};
        bool submit(const features::FlowFeatureRecord&) noexcept override { return false; }
        bool submit_v2(const features::FlowFeatureRecordV2&) noexcept override {
            ++count; return true;
        }
    };
    auto sink = std::make_shared<Records>();
    intriqo::pipeline::PipelineImpl a(std::make_unique<intriqo::detection::PortScanDetector>());
    intriqo::pipeline::PipelineImpl b(std::make_unique<intriqo::detection::PortScanDetector>(),
                                    Duration{60}, 100000, sink, id, true);
    std::vector<intriqo::events::SecurityEvent> left, right;
    a.on_event([&](auto e) { left.push_back(std::move(e)); });
    b.on_event([&](auto e) { right.push_back(std::move(e)); });
    for (std::uint16_t port=1; port<=10; ++port) {
        auto p=packet(port, false, 40, 0x02); p.dst_port=port;
        a.ingest(p); b.ingest(p);
    }
    a.flush(); b.flush();
    ASSERT_EQ(left.size(),1U); ASSERT_EQ(right.size(),1U);
    EXPECT_EQ(left[0].timestamp,right[0].timestamp);
    EXPECT_EQ(left[0].event_type,right[0].event_type);
    EXPECT_EQ(left[0].severity,right[0].severity);
    EXPECT_EQ(left[0].source_address,right[0].source_address);
    EXPECT_EQ(left[0].destination_address,right[0].destination_address);
    EXPECT_EQ(left[0].description,right[0].description);
    EXPECT_EQ(left[0].details,right[0].details);
    EXPECT_EQ(sink->count,10U);
    EXPECT_EQ(b.statistics().feature_generation_failures,0U);
}

TEST(FlowFeaturesV2, AcceptedIpv4TotalLengthIsMeasuredAndMalformedInputIsolated) {
    auto bytes = tcp_frame();
    protocol::IPv4Parser parser;
    const auto timestamp = TimePoint{std::chrono::seconds{1700000000}};
    auto accepted = parser.parse({timestamp, std::span<const std::byte>{bytes}, 1,
                                  bytes.size(), bytes.size()});
    ASSERT_TRUE(accepted);
    EXPECT_EQ(accepted->total_length, 40U);

    const auto truncated = parser.parse({timestamp,
        std::span<const std::byte>{bytes.data(), bytes.size() - 1}, 1,
        bytes.size(), bytes.size() - 1});
    EXPECT_FALSE(truncated);

    flow::FlowTable table(Duration{60}, 100, true);
    (void)table.update(*accepted);
    ASSERT_EQ(table.size(), 1U);
    const auto exported = record(table.flush().front());
    EXPECT_EQ(exported.values.packet_count, 1U);
    EXPECT_DOUBLE_EQ(exported.values.mean_ipv4_packet_bytes, 40.0);
}

TEST(FlowFeaturesV2, LifecycleExportsUseV2TimingAtFlushExpirationAndCapacity) {
    auto sink = std::make_shared<V2Records>();
    pipeline::PipelineImpl pipe(std::make_unique<intriqo::detection::PortScanDetector>(),
                                Duration{1}, 1, sink, id, true);

    auto first = packet(0);
    pipe.ingest(first);
    pipe.flush();
    ASSERT_EQ(sink->records.size(), 1U);
    EXPECT_EQ(sink->records[0].export_reason, features::FlowExportReason::shutdown_flush);
    EXPECT_EQ(sink->records[0].values.packet_count, 1U);
    EXPECT_EQ(sink->records[0].iat_gap_count, 0U);
    EXPECT_DOUBLE_EQ(sink->records[0].values.flow_iat_std_seconds, 0.0);

    sink->records.clear();
    pipeline::PipelineImpl expired(std::make_unique<intriqo::detection::PortScanDetector>(),
                                   Duration{1}, 4, sink, id, true);
    expired.ingest(packet(0));
    expired.maintain(packet(1000000000).timestamp);
    ASSERT_EQ(sink->records.size(), 1U);
    EXPECT_EQ(sink->records[0].export_reason, features::FlowExportReason::idle_expired);
    EXPECT_EQ(sink->records[0].values.packet_count, 1U);

    sink->records.clear();
    pipeline::PipelineImpl capacity(std::make_unique<intriqo::detection::PortScanDetector>(),
                                    Duration{60}, 1, sink, id, true);
    auto second = packet(0);
    second.dst_port = 444;
    capacity.ingest(first);
    capacity.ingest(second);
    ASSERT_EQ(sink->records.size(), 1U);
    EXPECT_EQ(sink->records[0].export_reason, features::FlowExportReason::capacity_evicted);
    EXPECT_EQ(sink->records[0].flow_id, 1U);
    capacity.flush();
    ASSERT_EQ(sink->records.size(), 2U);
    EXPECT_EQ(sink->records[1].export_reason, features::FlowExportReason::shutdown_flush);
    EXPECT_EQ(sink->records[1].flow_id, 2U);
}
