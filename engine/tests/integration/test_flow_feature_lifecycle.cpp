#include <gtest/gtest.h>
#include "intriqo/detection/detector_registry.hpp"
#include "intriqo/detection/port_scan_detector.hpp"
#include "intriqo/detection/syn_flood_detector.hpp"
#include "intriqo/pipeline/pipeline_impl.hpp"

using namespace intriqo;
using features::FlowExportReason;
namespace {
struct Records final : transport::FlowFeatureSink {
    std::vector<features::FlowFeatureRecord> records;
    bool closed{false};
    bool submit(const features::FlowFeatureRecord& record) noexcept override {
        try { records.push_back(record); return true; } catch (...) { return false; }
    }
    bool flush() noexcept override { closed = true; return true; }
};
packet::ParsedPacket parsed_packet(Port port = 443, int milliseconds = 0,
                                    std::uint8_t flags = 2, bool reverse = false,
                                    Protocol protocol = Protocol::TCP) {
    packet::ParsedPacket p{};
    p.timestamp = TimePoint{std::chrono::seconds{1700000000}} + std::chrono::milliseconds{milliseconds};
    p.src_ip = {{192, 0, 2, 10}}; p.dst_ip = {{198, 51, 100, 20}};
    p.src_port = 40000; p.dst_port = port;
    p.protocol = protocol; p.tcp_flags = flags; p.total_length = 40;
    if (reverse) { std::swap(p.src_ip, p.dst_ip); std::swap(p.src_port, p.dst_port); }
    return p;
}
std::unique_ptr<detection::DetectorRegistry> registry() {
    auto result = std::make_unique<detection::DetectorRegistry>();
    result->add(std::make_unique<detection::PortScanDetector>());
    result->add(std::make_unique<detection::SynFloodDetector>());
    return result;
}
}

TEST(FlowFeatureLifecycle, FinRstRemainCountersAndNoPacketSnapshotsAreEmitted) {
    auto sink = std::make_shared<Records>();
    pipeline::PipelineImpl pipe(registry(), Duration{1}, 8, sink);
    pipe.ingest(parsed_packet());
    pipe.ingest(parsed_packet(443, 100, 0x12, true));
    pipe.ingest(parsed_packet(443, 200, 0x10));
    pipe.ingest(parsed_packet(443, 300, 0x11));
    pipe.ingest(parsed_packet(443, 400, 0x14, true));
    EXPECT_TRUE(sink->records.empty());
    pipe.maintain(parsed_packet(443, 1399).timestamp);
    EXPECT_TRUE(sink->records.empty());
    pipe.maintain(parsed_packet(443, 1400).timestamp);
    ASSERT_EQ(sink->records.size(), 1U);
    const auto& r = sink->records.front();
    EXPECT_EQ(r.flow_id, 1U); EXPECT_EQ(r.export_reason, FlowExportReason::idle_expired);
    EXPECT_EQ(r.features.packet_count, 5U); EXPECT_EQ(r.features.byte_count, 200U);
    EXPECT_EQ(r.fwd_packet_count, 3U); EXPECT_EQ(r.rev_packet_count, 2U);
    EXPECT_EQ(r.features.fin_count, 1U); EXPECT_EQ(r.features.rst_count, 1U);
    EXPECT_TRUE(r.features.tcp_handshake_completed);
    EXPECT_DOUBLE_EQ(r.features.duration_seconds, 0.4);
    EXPECT_DOUBLE_EQ(r.features.packets_per_second, 12.5);
    EXPECT_DOUBLE_EQ(r.features.bytes_per_second, 500.0);
    EXPECT_NE(r.to_json().find("idle_expired"), std::string::npos);
    pipe.flush(); pipe.flush();
    EXPECT_EQ(sink->records.size(), 1U); EXPECT_TRUE(sink->closed);
}

TEST(FlowFeatureLifecycle, IncompleteShortAndUdpFlowsExpireBeforePacketAdmission) {
    auto sink = std::make_shared<Records>();
    pipeline::PipelineImpl pipe(registry(), Duration{1}, 8, sink);
    pipe.ingest(parsed_packet());
    pipe.ingest(parsed_packet(53, 100, 0, false, Protocol::UDP));
    pipe.ingest(parsed_packet(53, 200, 0, true, Protocol::UDP));
    pipe.ingest(parsed_packet(443, 1200));
    ASSERT_EQ(sink->records.size(), 2U);
    EXPECT_TRUE(sink->records[0].features.tcp_handshake_started);
    EXPECT_FALSE(sink->records[0].features.tcp_handshake_completed);
    EXPECT_DOUBLE_EQ(sink->records[0].features.packets_per_second, 0.0);
    EXPECT_EQ(sink->records[1].network.protocol, Protocol::UDP);
    EXPECT_EQ(sink->records[1].features.packet_count, 2U);
    EXPECT_EQ(sink->records[1].rev_packet_count, 1U);
    EXPECT_DOUBLE_EQ(sink->records[1].features.duration_seconds, 0.1);
    EXPECT_EQ(sink->records[1].export_reason, FlowExportReason::idle_expired);
    pipe.flush();
    ASSERT_EQ(sink->records.size(), 3U);
    EXPECT_EQ(sink->records[2].flow_id, 3U);
    EXPECT_EQ(sink->records[2].export_reason, FlowExportReason::shutdown_flush);
}

TEST(FlowFeatureLifecycle, CapacityEvictionAndShutdownKeepFlowsIndependent) {
    auto sink = std::make_shared<Records>();
    pipeline::PipelineImpl pipe(registry(), Duration{60}, 2, sink);
    pipe.ingest(parsed_packet(80)); pipe.ingest(parsed_packet(81));
    pipe.ingest(parsed_packet(81, 100)); pipe.ingest(parsed_packet(82, 200));
    ASSERT_EQ(sink->records.size(), 1U);
    EXPECT_EQ(sink->records[0].flow_id, 1U);
    EXPECT_EQ(sink->records[0].export_reason, FlowExportReason::capacity_evicted);
    pipe.flush();
    ASSERT_EQ(sink->records.size(), 3U);
    EXPECT_EQ(sink->records[1].flow_id, 2U); EXPECT_EQ(sink->records[2].flow_id, 3U);
    EXPECT_EQ(sink->records[1].features.packet_count, 2U);
    EXPECT_EQ(sink->records[2].features.packet_count, 1U);
    EXPECT_EQ(sink->records[0].features.packet_count, 1U);
    EXPECT_EQ(sink->records[0].engine_instance_id, sink->records[2].engine_instance_id);
    EXPECT_EQ(pipe.statistics().feature_generation_failures, 0U);
}

TEST(FlowFeatureLifecycle, BadGenerationCannotInterruptDeterministicDetection) {
    auto sink = std::make_shared<Records>();
    pipeline::PipelineImpl pipe(registry(), Duration{60}, 100, sink, "invalid-instance-id");
    unsigned count = 0; pipe.on_event([&](events::SecurityEvent) { ++count; });
    for (Port port = 1; port <= 10; ++port) pipe.ingest(parsed_packet(port));
    EXPECT_NO_THROW(pipe.flush());
    EXPECT_EQ(count, 1U); EXPECT_TRUE(sink->records.empty());
    EXPECT_EQ(pipe.statistics().feature_generation_failures, 10U);
    EXPECT_EQ(pipe.statistics().flows_active, 0U); EXPECT_TRUE(sink->closed);
}

TEST(FlowFeatureLifecycle, CallbackFailureStillExportsFinalFlows) {
    auto sink = std::make_shared<Records>();
    pipeline::PipelineImpl pipe(registry(), Duration{60}, 100, sink);
    pipe.on_event([](events::SecurityEvent) { throw std::runtime_error("test observer"); });
    for (Port port = 1; port < 10; ++port) pipe.ingest(parsed_packet(port));
    EXPECT_THROW(pipe.ingest(parsed_packet(10)), std::runtime_error);
    EXPECT_NO_THROW(pipe.flush());
    EXPECT_EQ(sink->records.size(), 10U); EXPECT_TRUE(sink->closed);
}

TEST(FlowFeatureLifecycle, PortScanAndSynFloodEvidenceMatchesDisabledStream) {
    auto exercise = [](bool stream) {
        detection::SynFloodConfig config;
        config.minimum_attempts = 3; config.minimum_rate_per_second = 0.1;
        config.minimum_incomplete_handshakes = 3; config.minimum_observation_seconds = 0.1;
        auto detectors = std::make_unique<detection::DetectorRegistry>();
        detectors->add(std::make_unique<detection::PortScanDetector>(detection::PortScanConfig{10, 3, 3, events::Severity::HIGH}));
        detectors->add(std::make_unique<detection::SynFloodDetector>(config));
        auto records = stream ? std::make_shared<Records>() : nullptr;
        pipeline::PipelineImpl pipe(std::move(detectors), Duration{60}, 100, records);
        std::vector<events::SecurityEvent> output;
        pipe.on_event([&](events::SecurityEvent e) { output.push_back(std::move(e)); });
        for (Port port = 1; port <= 3; ++port) pipe.ingest(parsed_packet(port, 100 * port));
        for (Port sport = 40001; sport <= 40003; ++sport) {
            auto p = parsed_packet(443, 1000 + 100 * (sport - 40000)); p.src_port = sport; pipe.ingest(p);
        }
        pipe.flush();
        EXPECT_EQ(pipe.statistics().feature_generation_failures, 0U);
        if (records) { EXPECT_EQ(records->records.size(), 6U); }
        return output;
    };
    const auto baseline = exercise(false), candidate = exercise(true);
    ASSERT_EQ(baseline.size(), 2U); ASSERT_EQ(candidate.size(), baseline.size());
    EXPECT_EQ(baseline[0].event_type, events::EventType::PORT_SCAN);
    EXPECT_EQ(baseline[1].event_type, events::EventType::SYN_FLOOD);
    for (std::size_t i = 0; i < baseline.size(); ++i) {
        EXPECT_EQ(candidate[i].event_type, baseline[i].event_type);
        EXPECT_EQ(candidate[i].severity, baseline[i].severity);
        EXPECT_EQ(candidate[i].timestamp, baseline[i].timestamp);
        EXPECT_EQ(candidate[i].source_address, baseline[i].source_address);
        EXPECT_EQ(candidate[i].destination_address, baseline[i].destination_address);
        EXPECT_EQ(candidate[i].details, baseline[i].details);
    }
}

TEST(FlowFeatureLifecycle, EngineLifetimesScopeTheSameExistingFlowId) {
    auto first = std::make_shared<Records>(), second = std::make_shared<Records>();
    pipeline::PipelineImpl a(registry(), Duration{60}, 8, first), b(registry(), Duration{60}, 8, second);
    a.ingest(parsed_packet()); b.ingest(parsed_packet()); a.flush(); b.flush();
    ASSERT_EQ(first->records.size(), 1U); ASSERT_EQ(second->records.size(), 1U);
    EXPECT_EQ(first->records[0].flow_id, second->records[0].flow_id);
    EXPECT_NE(first->records[0].engine_instance_id, second->records[0].engine_instance_id);
}
