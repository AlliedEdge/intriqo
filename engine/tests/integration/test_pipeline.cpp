#include <gtest/gtest.h>
#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/detection/port_scan_detector.hpp"
#include "intriqo/detection/detector_registry.hpp"
#include "intriqo/detection/syn_flood_detector.hpp"
using namespace intriqo;
TEST(Pipeline, SyntheticPortScanProducesContractEvent) { auto detector=std::make_unique<detection::PortScanDetector>(detection::PortScanConfig{10,3,3,events::Severity::HIGH}); pipeline::PipelineImpl pipe(std::move(detector)); std::vector<events::SecurityEvent> out; pipe.on_event([&](events::SecurityEvent e){out.push_back(std::move(e));}); auto t=Clock::now(); for(int i=0;i<3;i++){packet::ParsedPacket p{};p.timestamp=t;p.src_ip={{10,0,0,1}};p.dst_ip={{10,0,0,2}};p.src_port=40000;p.dst_port=static_cast<Port>(80+i);p.protocol=Protocol::TCP;p.total_length=54;p.tcp_flags=0x02;pipe.ingest(p);} ASSERT_EQ(out.size(),1u); EXPECT_NE(out[0].to_json().find("source_address"),std::string::npos); }

TEST(Pipeline, RegistryDispatchesSynFloodFromParsedInitialSYNs) {
    detection::SynFloodConfig config;
    config.window_seconds = 10.0;
    config.minimum_attempts = 3;
    config.minimum_rate_per_second = 0.1;
    config.incomplete_ratio_threshold = 0.75;
    config.minimum_incomplete_handshakes = 3;
    config.max_tracked_buckets = 8;
    config.max_tracked_flows = 8;
    config.minimum_observation_seconds = 0.1;

    auto registry = std::make_unique<detection::DetectorRegistry>();
    registry->add(std::make_unique<detection::PortScanDetector>());
    registry->add(std::make_unique<detection::SynFloodDetector>(config));
    EXPECT_EQ(registry->names(), (std::vector<std::string>{"port_scan", "syn_flood"}));

    pipeline::PipelineImpl pipe(std::move(registry));
    std::vector<events::SecurityEvent> out;
    pipe.on_event([&](events::SecurityEvent event) { out.push_back(std::move(event)); });
    const auto start = TimePoint{std::chrono::seconds{1'700'000'000}};
    for (int i = 0; i < 3; ++i) {
        packet::ParsedPacket packet{};
        packet.timestamp = start + std::chrono::milliseconds{100 * i};
        packet.src_ip = {{10, 0, 0, 1}};
        packet.dst_ip = {{192, 0, 2, 10}};
        packet.src_port = static_cast<Port>(40'000 + i);
        packet.dst_port = 443;
        packet.protocol = Protocol::TCP;
        packet.total_length = 40;
        packet.tcp_flags = 0x02;
        pipe.ingest(packet);
    }

    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out.front().event_type, events::EventType::SYN_FLOOD);
    EXPECT_EQ(pipe.statistics().detection.detections, 1u);
}
