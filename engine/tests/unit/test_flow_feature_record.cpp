#include "intriqo/features/flow_feature_record.hpp"
#include <gtest/gtest.h>
#include <charconv>
#include <chrono>
#include <cmath>
#include <limits>
#include <locale>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

using namespace intriqo;
using namespace intriqo::features;

namespace {

constexpr std::string_view kInstanceId = "01234567-89ab-4cde-8f01-23456789abcd";

flow::NetworkFlow fixture(Protocol protocol = Protocol::TCP) {
    flow::NetworkFlow flow;
    flow.flow_id = 42;
    flow.key = {{{10, 0, 0, 1}}, {{10, 0, 0, 2}}, 40000, 443, protocol};
    flow.first_seen = TimePoint{std::chrono::seconds{1'700'000'000}};
    flow.last_seen = flow.first_seen + std::chrono::seconds{1};
    flow.packet_count = 3;
    flow.byte_count = 120;
    flow.fwd_packet_count = 2;
    flow.rev_packet_count = 1;
    flow.fwd_byte_count = 80;
    flow.rev_byte_count = 40;
    if (protocol == Protocol::TCP) {
        flow.syn_count = 2;
        flow.initial_syn_count = 1;
        flow.syn_ack_count = 1;
        flow.ack_count = 1;
        flow.tcp_handshake_started = true;
        flow.tcp_syn_ack_seen = true;
        flow.tcp_handshake_completed = true;
    }
    return flow;
}

FlowFeatureRecord record(Protocol protocol = Protocol::TCP) {
    return FlowFeatureRecord::from_flow(fixture(protocol), kInstanceId,
                                        FlowExportReason::idle_expired);
}

double json_number(const std::string& json, std::string_view name) {
    const auto marker = '"' + std::string(name) + "\":";
    const auto start = json.find(marker);
    EXPECT_NE(start, std::string::npos);
    if (start == std::string::npos) return 0.0;
    const auto value_start = start + marker.size();
    const auto value_end = json.find_first_of(",}", value_start);
    double result = 0.0;
    const auto parsed = std::from_chars(json.data() + value_start,
                                        json.data() + value_end, result);
    EXPECT_EQ(parsed.ec, std::errc{});
    EXPECT_EQ(parsed.ptr, json.data() + value_end);
    return result;
}

class GroupingPunctuation final : public std::numpunct<char> {
    char do_decimal_point() const override { return ','; }
    char do_thousands_sep() const override { return '_'; }
    std::string do_grouping() const override { return "\3"; }
};

class GlobalLocaleGuard {
public:
    GlobalLocaleGuard() : previous_(std::locale()) {}
    ~GlobalLocaleGuard() { std::locale::global(previous_); }
private:
    std::locale previous_;
};

} // namespace

TEST(FlowFeatureRecord, ExactFrozenJsonContainsOnlySupportedFields) {
    const auto actual = record().to_json();
    const std::string expected =
        "{\"schema_version\":\"flow_features.v1\",\"metadata\":{"
        "\"engine_instance_id\":\"01234567-89ab-4cde-8f01-23456789abcd\","
        "\"flow_id\":\"42\",\"first_seen\":\"2023-11-14T22:13:20.000000000Z\","
        "\"timestamp\":\"2023-11-14T22:13:21.000000000Z\","
        "\"export_reason\":\"idle_expired\",\"network\":{"
        "\"src_ip\":\"10.0.0.1\",\"dst_ip\":\"10.0.0.2\","
        "\"src_port\":40000,\"dst_port\":443,\"protocol\":\"TCP\"}},"
        "\"features\":{\"packet_count\":3,\"byte_count\":120,\"duration_seconds\":1,"
        "\"bytes_per_packet\":40,\"packets_per_second\":3,\"bytes_per_second\":120,"
        "\"fwd_packet_count\":2,\"rev_packet_count\":1,"
        "\"fwd_byte_count\":80,\"rev_byte_count\":40,\"syn_count\":2,\"fin_count\":0,"
        "\"rst_count\":0,\"initial_syn_count\":1,\"syn_ack_count\":1,\"ack_count\":1,"
        "\"tcp_handshake_started\":true,\"tcp_syn_ack_seen\":true,"
        "\"tcp_handshake_completed\":true}}";
    EXPECT_EQ(actual, expected);
    EXPECT_EQ(actual.find("connection_attempts"), std::string::npos);
    EXPECT_EQ(actual.find("null"), std::string::npos);
    EXPECT_LT(actual.size(), maximum_flow_feature_record_bytes);
}

TEST(FlowFeatureRecord, SnapshotMatchesExistingExtractorAndPreservesDirection) {
    flow::FlowTable table;
    packet::ParsedPacket packet{};
    packet.src_ip = {{10, 0, 0, 20}};
    packet.dst_ip = {{10, 0, 0, 10}};
    packet.src_port = 54000;
    packet.dst_port = 443;
    packet.protocol = Protocol::TCP;
    packet.total_length = 40;
    packet.timestamp = TimePoint{std::chrono::seconds{1'700'000'000}};
    packet.tcp_flags = 0x02;
    const auto first = table.update(packet);
    std::swap(packet.src_ip, packet.dst_ip);
    std::swap(packet.src_port, packet.dst_port);
    packet.timestamp += std::chrono::milliseconds{250};
    packet.total_length = 60;
    packet.tcp_flags = 0x12;
    (void)table.update(packet);
    std::swap(packet.src_ip, packet.dst_ip);
    std::swap(packet.src_port, packet.dst_port);
    packet.timestamp += std::chrono::milliseconds{125};
    packet.total_length = 41;
    packet.tcp_flags = 0x10;
    const auto final = table.update(packet).flow;
    const auto expected = FlowFeatures::from_flow(final);
    const auto actual = FlowFeatureRecord::from_flow(
        final, kInstanceId, FlowExportReason::shutdown_flush);
    EXPECT_EQ(actual.flow_id, first.flow.flow_id);
    EXPECT_EQ(actual.network, first.flow.key);
    EXPECT_EQ(actual.first_seen, first.flow.first_seen);
    EXPECT_EQ(actual.timestamp, final.last_seen);
    EXPECT_EQ(actual.features.packet_count, expected.packet_count);
    EXPECT_EQ(actual.features.byte_count, expected.byte_count);
    EXPECT_DOUBLE_EQ(actual.features.duration_seconds, expected.duration_seconds);
    EXPECT_DOUBLE_EQ(actual.features.bytes_per_packet, expected.bytes_per_packet);
    EXPECT_DOUBLE_EQ(actual.features.packets_per_second, expected.packets_per_second);
    EXPECT_DOUBLE_EQ(actual.features.bytes_per_second, expected.bytes_per_second);
    EXPECT_EQ(actual.features.syn_count, expected.syn_count);
    EXPECT_EQ(actual.features.fin_count, expected.fin_count);
    EXPECT_EQ(actual.features.rst_count, expected.rst_count);
    EXPECT_EQ(actual.features.initial_syn_count, expected.initial_syn_count);
    EXPECT_EQ(actual.features.syn_ack_count, expected.syn_ack_count);
    EXPECT_EQ(actual.features.ack_count, expected.ack_count);
    EXPECT_EQ(actual.features.tcp_handshake_started, expected.tcp_handshake_started);
    EXPECT_EQ(actual.features.tcp_syn_ack_seen, expected.tcp_syn_ack_seen);
    EXPECT_EQ(actual.features.tcp_handshake_completed, expected.tcp_handshake_completed);
    EXPECT_EQ(actual.features.connection_attempts, 0u);
    EXPECT_EQ(actual.fwd_packet_count, 2u);
    EXPECT_EQ(actual.rev_packet_count, 1u);
    EXPECT_EQ(actual.fwd_byte_count, 81u);
    EXPECT_EQ(actual.rev_byte_count, 60u);
    EXPECT_DOUBLE_EQ(json_number(actual.to_json(), "bytes_per_packet"),
                     expected.bytes_per_packet);
}

TEST(FlowFeatureRecord, ZeroDurationAndEmptyCountersRemainZero) {
    auto flow = fixture(Protocol::UDP);
    flow.last_seen = flow.first_seen;
    const auto instantaneous = FlowFeatureRecord::from_flow(
        flow, kInstanceId, FlowExportReason::capacity_evicted);
    EXPECT_DOUBLE_EQ(json_number(instantaneous.to_json(), "duration_seconds"), 0.0);
    EXPECT_DOUBLE_EQ(json_number(instantaneous.to_json(), "packets_per_second"), 0.0);
    EXPECT_DOUBLE_EQ(json_number(instantaneous.to_json(), "bytes_per_second"), 0.0);
    EXPECT_DOUBLE_EQ(json_number(instantaneous.to_json(), "bytes_per_packet"), 40.0);

    flow::NetworkFlow empty{};
    empty.flow_id = 1;
    const auto zero = FlowFeatureRecord::from_flow(
        empty, kInstanceId, FlowExportReason::shutdown_flush);
    EXPECT_DOUBLE_EQ(json_number(zero.to_json(), "bytes_per_packet"), 0.0);
    EXPECT_NE(zero.to_json().find("\"packet_count\":0"), std::string::npos);
    EXPECT_NE(zero.to_json().find("\"syn_count\":0"), std::string::npos);
}

TEST(FlowFeatureRecord, EverySupportedProtocolAndExportReasonHasItsExactName) {
    for (const auto& [protocol, name] : {
             std::pair{Protocol::TCP, "TCP"}, std::pair{Protocol::UDP, "UDP"},
             std::pair{Protocol::ICMP, "ICMP"}, std::pair{Protocol::OTHER, "OTHER"}}) {
        const auto json = record(protocol).to_json();
        EXPECT_NE(json.find("\"protocol\":\"" + std::string(name) + '"'), std::string::npos);
        if (protocol != Protocol::TCP) {
            EXPECT_NE(json.find("\"syn_count\":0"), std::string::npos);
            EXPECT_NE(json.find("\"tcp_handshake_started\":false"), std::string::npos);
        }
    }
    for (const auto& [reason, name] : {
             std::pair{FlowExportReason::idle_expired, "idle_expired"},
             std::pair{FlowExportReason::capacity_evicted, "capacity_evicted"},
             std::pair{FlowExportReason::shutdown_flush, "shutdown_flush"}}) {
        auto value = record();
        value.export_reason = reason;
        EXPECT_NE(value.to_json().find("\"export_reason\":\"" + std::string(name) + '"'),
                  std::string::npos);
    }
}

TEST(FlowFeatureRecord, FloatingPointValuesRoundTripAtFullPrecision) {
    auto value = record();
    value.features.duration_seconds = std::nextafter(1.0, 2.0);
    value.features.bytes_per_packet = 1.0 / 3.0;
    value.features.packets_per_second = std::numeric_limits<double>::denorm_min();
    value.features.bytes_per_second = std::numeric_limits<double>::max();
    const auto json = value.to_json();
    EXPECT_DOUBLE_EQ(json_number(json, "duration_seconds"), value.features.duration_seconds);
    EXPECT_DOUBLE_EQ(json_number(json, "bytes_per_packet"), value.features.bytes_per_packet);
    EXPECT_DOUBLE_EQ(json_number(json, "packets_per_second"), value.features.packets_per_second);
    EXPECT_DOUBLE_EQ(json_number(json, "bytes_per_second"), value.features.bytes_per_second);
    EXPECT_LT(json.size(), maximum_flow_feature_record_bytes);
}

TEST(FlowFeatureRecord, SerializationAndUuidGenerationIgnoreTheGlobalLocale) {
    auto value = record();
    value.features.duration_seconds = 1234.5678901234567;
    value.features.bytes_per_packet = 1.0 / 3.0;
    const auto expected = value.to_json();
    GlobalLocaleGuard guard;
    std::locale::global(std::locale(std::locale::classic(), new GroupingPunctuation));
    EXPECT_EQ(value.to_json(), expected);
    EXPECT_EQ(value.to_json(), value.to_json());
    const auto id = make_engine_instance_id();
    EXPECT_NO_THROW((void)FlowFeatureRecord::from_flow(
        fixture(), id, FlowExportReason::shutdown_flush));
}

TEST(FlowFeatureRecord, PreEpochAndFractionalTimestampsAreCanonicalUtc) {
    auto flow = fixture(Protocol::UDP);
    flow.first_seen = TimePoint{std::chrono::duration_cast<Clock::duration>(
        std::chrono::nanoseconds{-1'000'000'001})};
    flow.last_seen = TimePoint{std::chrono::duration_cast<Clock::duration>(
        std::chrono::nanoseconds{-1})};
    const auto json = FlowFeatureRecord::from_flow(
        flow, kInstanceId, FlowExportReason::shutdown_flush).to_json();
    EXPECT_NE(json.find("\"first_seen\":\"1969-12-31T23:59:58.999999999Z\""),
              std::string::npos);
    EXPECT_NE(json.find("\"timestamp\":\"1969-12-31T23:59:59.999999999Z\""),
              std::string::npos);

    flow.first_seen = TimePoint{std::chrono::duration_cast<Clock::duration>(
        std::chrono::nanoseconds{951'827'696'123'456'789})};
    flow.last_seen = flow.first_seen;
    EXPECT_NE(FlowFeatureRecord::from_flow(flow, kInstanceId,
        FlowExportReason::shutdown_flush).to_json().find("2000-02-29T12:34:56.123456789Z"),
        std::string::npos);
}

TEST(FlowFeatureRecord, ExtremeClockTicksDoNotOverflow) {
    auto flow = fixture(Protocol::UDP);
    flow.first_seen = TimePoint::min();
    flow.last_seen = TimePoint::max();
    const auto value = FlowFeatureRecord::from_flow(
        flow, kInstanceId, FlowExportReason::shutdown_flush);
    const auto json = value.to_json();
    EXPECT_GT(value.features.duration_seconds, 0.0);
    if constexpr (std::is_same_v<Clock::duration, std::chrono::nanoseconds>) {
        EXPECT_NE(json.find("\"first_seen\":\"1677-09-21T00:12:43.145224192Z\""),
                  std::string::npos);
        EXPECT_NE(json.find("\"timestamp\":\"2262-04-11T23:47:16.854775807Z\""),
                  std::string::npos);
    }
}

TEST(FlowFeatureRecord, Ipv4PortsAndIntegerBoundariesAreLossless) {
    auto flow = fixture();
    flow.flow_id = std::numeric_limits<std::uint64_t>::max();
    flow.key.src_ip = {{0, 0, 0, 0}};
    flow.key.dst_ip = {{255, 255, 255, 255}};
    flow.key.src_port = 0;
    flow.key.dst_port = std::numeric_limits<Port>::max();
    flow.packet_count = flow.byte_count = std::numeric_limits<std::uint64_t>::max();
    flow.fwd_packet_count = flow.fwd_byte_count = flow.packet_count - 1;
    flow.rev_packet_count = flow.rev_byte_count = 1;
    flow.syn_count = flow.initial_syn_count = flow.fin_count = flow.rst_count
        = std::numeric_limits<std::uint32_t>::max();
    flow.syn_ack_count = 0;
    flow.ack_count = std::numeric_limits<std::uint32_t>::max();
    flow.tcp_syn_ack_seen = flow.tcp_handshake_completed = false;
    const auto json = FlowFeatureRecord::from_flow(
        flow, kInstanceId, FlowExportReason::capacity_evicted).to_json();
    EXPECT_NE(json.find("\"flow_id\":\"18446744073709551615\""), std::string::npos);
    EXPECT_NE(json.find("\"packet_count\":18446744073709551615"), std::string::npos);
    EXPECT_NE(json.find("\"byte_count\":18446744073709551615"), std::string::npos);
    EXPECT_NE(json.find("\"fwd_packet_count\":18446744073709551614"), std::string::npos);
    EXPECT_NE(json.find("\"syn_count\":4294967295"), std::string::npos);
    EXPECT_NE(json.find("\"fin_count\":4294967295"), std::string::npos);
    EXPECT_NE(json.find("\"rst_count\":4294967295"), std::string::npos);
    EXPECT_NE(json.find("\"src_ip\":\"0.0.0.0\""), std::string::npos);
    EXPECT_NE(json.find("\"dst_ip\":\"255.255.255.255\""), std::string::npos);
    EXPECT_NE(json.find("\"src_port\":0,\"dst_port\":65535"), std::string::npos);
    EXPECT_LT(json.size(), maximum_flow_feature_record_bytes);
}

TEST(FlowFeatureRecord, PartialAndMidCaptureHandshakesAreNotInvented) {
    auto flow = fixture();
    flow.packet_count = flow.fwd_packet_count = 1;
    flow.rev_packet_count = flow.rev_byte_count = 0;
    flow.byte_count = flow.fwd_byte_count = 40;
    flow.syn_count = flow.initial_syn_count = 1;
    flow.syn_ack_count = flow.ack_count = 0;
    flow.tcp_syn_ack_seen = flow.tcp_handshake_completed = false;
    const auto partial = FlowFeatureRecord::from_flow(
        flow, kInstanceId, FlowExportReason::idle_expired);
    EXPECT_NE(partial.to_json().find("\"tcp_handshake_started\":true"), std::string::npos);
    EXPECT_NE(partial.to_json().find("\"tcp_handshake_completed\":false"), std::string::npos);

    // SYN-ACK observed first: counters alone cannot establish ordered evidence.
    flow.initial_syn_count = 0;
    flow.syn_ack_count = 1;
    flow.tcp_handshake_started = false;
    EXPECT_NO_THROW((void)FlowFeatureRecord::from_flow(
        flow, kInstanceId, FlowExportReason::idle_expired).to_json());
    auto unseen = record();
    unseen.features.tcp_handshake_started = false;
    unseen.features.tcp_syn_ack_seen = false;
    unseen.features.tcp_handshake_completed = false;
    EXPECT_NO_THROW((void)unseen.to_json());
}

TEST(FlowFeatureRecord, GeneratedEngineIdsAreCanonicalVersionFourUuids) {
    const auto first = make_engine_instance_id();
    const auto second = make_engine_instance_id();
    ASSERT_EQ(first.size(), 36u);
    EXPECT_NE(first, second);
    EXPECT_EQ(first[14], '4');
    EXPECT_NE(std::string_view("89ab").find(first[19]), std::string_view::npos);
    for (std::size_t i = 0; i < first.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            EXPECT_EQ(first[i], '-');
        } else {
            EXPECT_TRUE((first[i] >= '0' && first[i] <= '9')
                        || (first[i] >= 'a' && first[i] <= 'f'));
        }
    }
    EXPECT_NO_THROW((void)FlowFeatureRecord::from_flow(
        fixture(), first, FlowExportReason::shutdown_flush));
}

TEST(FlowFeatureRecord, UnsafeAndNonCanonicalIdsAreRejectedBeforeJsonEscaping) {
    for (const auto& id : {std::string{}, std::string("not-a-uuid"),
                          std::string("01234567-89AB-4cde-8f01-23456789abcd"),
                          std::string(kInstanceId) + ' ',
                          ' ' + std::string(kInstanceId),
                          std::string("0123456789ab4cde8f0123456789abcd")}) {
        auto value = record();
        value.engine_instance_id = id;
        EXPECT_THROW((void)value.to_json(), std::invalid_argument);
        EXPECT_THROW((void)FlowFeatureRecord::from_flow(
            fixture(), id, FlowExportReason::shutdown_flush), std::invalid_argument);
    }
    // All JSON escapes and C0 control bytes are barred by the UUID boundary.
    // Rejection also prevents embedded NUL from silently truncating an ID.
    for (unsigned byte = 0; byte < 256; ++byte) {
        if ((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f')) continue;
        auto value = record();
        value.engine_instance_id[0] = static_cast<char>(byte);
        EXPECT_THROW((void)value.to_json(), std::invalid_argument) << "byte=" << byte;
    }
    auto value = record();
    value.engine_instance_id[8] = '0';
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
}

TEST(FlowFeatureRecord, InvalidEnumsZeroIdsAndReversedTimesAreRejected) {
    auto value = record();
    value.flow_id = 0;
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    value = record();
    value.export_reason = static_cast<FlowExportReason>(-1);
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    EXPECT_THROW((void)FlowFeatureRecord::from_flow(fixture(), kInstanceId,
        static_cast<FlowExportReason>(99)), std::invalid_argument);
    value = record();
    value.network.protocol = static_cast<Protocol>(0);
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    value = record();
    value.timestamp = value.first_seen - Clock::duration{1};
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    auto flow = fixture();
    flow.last_seen = flow.first_seen - Clock::duration{1};
    EXPECT_THROW((void)FlowFeatureRecord::from_flow(
        flow, kInstanceId, FlowExportReason::shutdown_flush), std::invalid_argument);
    flow = fixture();
    flow.flow_id = 0;
    EXPECT_THROW((void)FlowFeatureRecord::from_flow(
        flow, kInstanceId, FlowExportReason::shutdown_flush), std::invalid_argument);
}

TEST(FlowFeatureRecord, EveryFloatingMetricRejectsNegativeNanAndInfinity) {
    for (auto member : {&FlowFeatures::duration_seconds, &FlowFeatures::bytes_per_packet,
                        &FlowFeatures::packets_per_second, &FlowFeatures::bytes_per_second}) {
        for (double bad : {-1.0, std::numeric_limits<double>::quiet_NaN(),
                           std::numeric_limits<double>::infinity(),
                           -std::numeric_limits<double>::infinity()}) {
            auto value = record();
            value.features.*member = bad;
            EXPECT_THROW((void)value.to_json(), std::invalid_argument);
        }
    }
}

TEST(FlowFeatureRecord, DirectionalTotalsAreCheckedWithoutOverflow) {
    for (auto member : {&FlowFeatureRecord::fwd_packet_count,
                        &FlowFeatureRecord::rev_packet_count,
                        &FlowFeatureRecord::fwd_byte_count,
                        &FlowFeatureRecord::rev_byte_count}) {
        auto value = record();
        ++(value.*member);
        EXPECT_THROW((void)value.to_json(), std::invalid_argument);
        value.*member = std::numeric_limits<std::uint64_t>::max();
        EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    }
    auto value = record(Protocol::UDP);
    value.features.packet_count = std::numeric_limits<std::uint64_t>::max();
    value.fwd_packet_count = std::numeric_limits<std::uint64_t>::max();
    value.rev_packet_count = std::numeric_limits<std::uint64_t>::max();
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    value = record(Protocol::UDP);
    value.features.byte_count = std::numeric_limits<std::uint64_t>::max();
    value.fwd_byte_count = std::numeric_limits<std::uint64_t>::max();
    value.rev_byte_count = std::numeric_limits<std::uint64_t>::max();
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);

    value = record(Protocol::UDP);
    value.fwd_packet_count = 0;
    value.rev_packet_count = value.features.packet_count;
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    auto flow = fixture();
    ++flow.fwd_packet_count;
    EXPECT_THROW((void)FlowFeatureRecord::from_flow(
        flow, kInstanceId, FlowExportReason::shutdown_flush), std::invalid_argument);
}

TEST(FlowFeatureRecord, TcpCountsAndHandshakeImplicationsAreChecked) {
    for (auto member : {&FlowFeatures::syn_count, &FlowFeatures::fin_count,
                        &FlowFeatures::rst_count, &FlowFeatures::initial_syn_count,
                        &FlowFeatures::syn_ack_count, &FlowFeatures::ack_count}) {
        auto value = record();
        value.features.*member = 4;
        EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    }
    auto value = record();
    value.features.initial_syn_count = 2;
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    value = record();
    value.features.ack_count = 2;
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    value = record();
    value.features.initial_syn_count = 0;
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    value = record();
    value.features.tcp_handshake_started = false;
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    value = record();
    value.features.syn_ack_count = 0;
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    value = record();
    value.features.tcp_syn_ack_seen = false;
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    value = record();
    value.features.ack_count = 0;
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
    value = record();
    value.fwd_packet_count = 1;
    value.rev_packet_count = 2;
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);

    value = record();
    value.features.packet_count = std::numeric_limits<std::uint64_t>::max();
    value.fwd_packet_count = value.features.packet_count - 1;
    value.features.initial_syn_count = value.features.syn_ack_count
        = value.features.syn_count = std::numeric_limits<std::uint32_t>::max();
    EXPECT_THROW((void)value.to_json(), std::invalid_argument);
}

TEST(FlowFeatureRecord, NonTcpFlowsRejectEveryTcpCounterAndFlag) {
    for (const auto protocol : {Protocol::UDP, Protocol::ICMP, Protocol::OTHER}) {
        for (auto member : {&FlowFeatures::syn_count, &FlowFeatures::fin_count,
                            &FlowFeatures::rst_count, &FlowFeatures::initial_syn_count,
                            &FlowFeatures::syn_ack_count, &FlowFeatures::ack_count}) {
            auto value = record(protocol);
            value.features.*member = 1;
            EXPECT_THROW((void)value.to_json(), std::invalid_argument);
        }
        for (auto member : {&FlowFeatures::tcp_handshake_started, &FlowFeatures::tcp_syn_ack_seen,
                            &FlowFeatures::tcp_handshake_completed}) {
            auto value = record(protocol);
            value.features.*member = true;
            EXPECT_THROW((void)value.to_json(), std::invalid_argument);
        }
        auto flow = fixture(protocol);
        flow.fin_count = 1;
        EXPECT_THROW((void)FlowFeatureRecord::from_flow(
            flow, kInstanceId, FlowExportReason::shutdown_flush), std::invalid_argument);
    }
}

TEST(FlowFeatureRecord, LegacyConnectionAttemptsIsNeverCopiedOrSerialized) {
    auto value = record();
    EXPECT_EQ(value.features.connection_attempts, 0u);
    const auto expected = value.to_json();
    value.features.connection_attempts = std::numeric_limits<std::uint32_t>::max();
    EXPECT_EQ(value.to_json(), expected);
}
