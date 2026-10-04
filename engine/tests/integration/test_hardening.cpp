#include <gtest/gtest.h>
#include "runtime_fixture.hpp"
#include "intriqo/detection/port_scan_detector.hpp"
#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/runtime/engine_impl.hpp"
#include <future>
#include <limits>
#include <thread>

using namespace intriqo;
using namespace runtime_test;
namespace {
packet::ParsedPacket parsed(Port port, double seconds=0) {
    packet::ParsedPacket p{};
    p.timestamp=TimePoint{std::chrono::seconds(1700000000)}+
        std::chrono::duration_cast<Clock::duration>(Duration{seconds});
    p.src_ip={{192,0,2,10}}; p.dst_ip={{198,51,100,20}};
    p.src_port=40000; p.dst_port=port; p.protocol=Protocol::TCP; p.tcp_flags=2; p.total_length=40;
    return p;
}
flow::NetworkFlow observation(FlowId id, Port port, double seconds=0, unsigned source=10) {
    flow::NetworkFlow f{}; auto p=parsed(port,seconds);
    p.src_ip.octets[3]=static_cast<std::uint8_t>(source);
    f.flow_id=id; f.key={p.src_ip,p.dst_ip,p.src_port,p.dst_port,p.protocol};
    f.first_seen=f.last_seen=p.timestamp; f.packet_count=1; return f;
}
struct Sink final : transport::SecurityEventSink {
    bool fail{false}; unsigned submitted{0};
    bool submit(const events::SecurityEvent&) noexcept override { ++submitted; return !fail; }
};
}

TEST(HardeningFlow, EligibleExpiryBeforeAdmissionAndCapacityBound) {
    flow::FlowTable table(Duration{1},2);
    auto a=table.update(parsed(1)); auto b=table.update(parsed(2));
    EXPECT_EQ(a.flow.fwd_packet_count,1U); EXPECT_EQ(a.flow.rev_packet_count,0U);
    auto c=table.update(parsed(3,2));
    EXPECT_EQ(c.expired.size(),2U); EXPECT_FALSE(c.evicted); EXPECT_EQ(table.size(),1U);
    EXPECT_EQ(table.flush().size(),1U); EXPECT_EQ(table.size(),0U);
    (void)b;
}
TEST(HardeningFlow, OldestIdleEvictionIsDeterministic) {
    flow::FlowTable table(Duration{60},2);
    const auto first=table.update(parsed(1)).flow.flow_id;
    const auto second=table.update(parsed(2)).flow.flow_id;
    auto replacement=table.update(parsed(3));
    ASSERT_TRUE(replacement.evicted); EXPECT_EQ(replacement.evicted->flow_id,first);
    auto retained=table.update(parsed(2)); EXPECT_FALSE(retained.created); EXPECT_EQ(retained.flow.flow_id,second);
    EXPECT_EQ(table.size(),2U);
}
TEST(HardeningFlow, ReverseDirectionAndLateTimeDoNotCorruptState) {
    flow::FlowTable table;
    auto p=parsed(1,2); auto first=table.update(p);
    std::swap(p.src_ip,p.dst_ip); std::swap(p.src_port,p.dst_port); p.timestamp-=std::chrono::seconds(1);
    auto reverse=table.update(p); EXPECT_FALSE(reverse.created);
    EXPECT_EQ(reverse.flow.flow_id,first.flow.flow_id); EXPECT_EQ(reverse.flow.last_seen,first.flow.last_seen);
    EXPECT_EQ(reverse.flow.fwd_packet_count,1U); EXPECT_EQ(reverse.flow.rev_packet_count,1U);
    EXPECT_GE(reverse.flow.duration_seconds(),0);
}
TEST(HardeningFlow, RepeatedUpdatesDoNotGrowIndexes) {
    flow::FlowTable table(Duration{60},8);
    for(unsigned i=0;i<100000;++i) {
        auto update=table.update(parsed(static_cast<Port>(1+i%16),i*0.0001));
        EXPECT_LE(table.size(),8U);
        EXPECT_TRUE(update.expired.empty());
    }
    EXPECT_EQ(table.flush().size(),8U);
}
TEST(HardeningFlow, InvalidConfigurationRejected) {
    EXPECT_THROW(flow::FlowTable(Duration{0},10),std::invalid_argument);
    EXPECT_THROW(flow::FlowTable(Duration{1},0),std::invalid_argument);
    EXPECT_THROW(flow::FlowTable(Duration{std::numeric_limits<double>::infinity()},10),std::invalid_argument);
}

TEST(HardeningDetector, SourceExpiryDoesNotRecountActiveFlow) {
    detection::PortScanDetector detector({1,2,2,events::Severity::HIGH});
    auto first=observation(1,1);
    EXPECT_TRUE(detector.evaluate(first,{}).empty());
    detector.expire(parsed(1,2).timestamp);
    EXPECT_EQ(detector.statistics().state_sources,0U); EXPECT_EQ(detector.statistics().state_observations,1U);
    first.last_seen=parsed(1,2).timestamp;
    EXPECT_TRUE(detector.evaluate(first,{}).empty());
    EXPECT_EQ(detector.statistics().observations,1U);
    detector.retire_flow(1); EXPECT_EQ(detector.statistics().state_observations,0U);
}
TEST(HardeningDetector, SourceAndObservationAdmissionHaveExplicitBounds) {
    detection::PortScanConfig config{10,3,3,events::Severity::HIGH,1,2};
    detection::PortScanDetector detector(config);
    (void)detector.evaluate(observation(1,1),{});
    (void)detector.evaluate(observation(2,2,0,11),{});
    EXPECT_EQ(detector.statistics().state_rejections,1U);
    (void)detector.evaluate(observation(3,2),{});
    (void)detector.evaluate(observation(4,3),{});
    auto stats=detector.statistics(); EXPECT_EQ(stats.state_sources,1U); EXPECT_EQ(stats.state_observations,2U);
    EXPECT_EQ(stats.state_rejections,2U);
    detector.retire_flow(1);
    auto events=detector.evaluate(observation(4,3),{}); ASSERT_EQ(events.size(),1U);
    EXPECT_EQ(detector.statistics().observations,3U);
}
TEST(HardeningDetector, BufferedLatePacketWithinWindowIsAccepted) {
    detection::PortScanDetector detector({10,1,1,events::Severity::HIGH});
    detector.expire(parsed(1,0.1).timestamp);
    auto events=detector.evaluate(observation(1,1),{}); EXPECT_EQ(events.size(),1U);
    EXPECT_EQ(detector.statistics().state_rejections,0U);
}
TEST(HardeningDetector, WindowBoundaryAndOneEventPerSource) {
    detection::PortScanDetector detector({1,2,2,events::Severity::HIGH});
    (void)detector.evaluate(observation(1,1),{});
    auto event=detector.evaluate(observation(2,2,1),{}); EXPECT_EQ(event.size(),1U);
    EXPECT_TRUE(detector.evaluate(observation(3,3,1),{}).empty());
    detector.retire_flow(1); detector.retire_flow(2); detector.retire_flow(3);
    (void)detector.evaluate(observation(4,1,2),{});
    EXPECT_EQ(detector.evaluate(observation(5,2,2),{}).size(),1U);
    auto before=detector.statistics(); detector.reset(); auto after=detector.statistics();
    EXPECT_EQ(after.state_sources,0U); EXPECT_EQ(after.state_observations,0U);
    EXPECT_EQ(after.detections,before.detections);
}
TEST(HardeningDetector, ConcurrentEvaluationAndSnapshotsAreRaceSafe) {
    detection::PortScanDetector detector;
    std::vector<std::thread> threads;
    for(unsigned thread=0;thread<4;++thread) threads.emplace_back([&,thread] {
        for(unsigned i=0;i<1000;++i) {
            const auto id=1+thread*1000+i;
            (void)detector.evaluate(observation(id,static_cast<Port>(1+i%20)),{});
            (void)detector.statistics(); detector.retire_flow(id);
        }
    });
    for(auto& thread:threads) thread.join();
    EXPECT_EQ(detector.statistics().state_observations,0U);
    EXPECT_EQ(detector.statistics().detections,1U);
}
TEST(HardeningPipeline, IdleMaintenanceAndShutdownClearBoundedState) {
    pipeline::PipelineImpl pipeline(std::make_unique<detection::PortScanDetector>(),Duration{1},2);
    for(Port port=1;port<=10;++port) pipeline.ingest(parsed(port));
    EXPECT_EQ(pipeline.statistics().flows_evicted,8U);
    EXPECT_EQ(pipeline.statistics().peak_active_flows,2U);
    EXPECT_EQ(pipeline.statistics().detection.observations,10U);
    pipeline.maintain(parsed(1,2).timestamp);
    EXPECT_EQ(pipeline.statistics().flows_expired,2U); EXPECT_EQ(pipeline.active_flow_count(),0U);
    EXPECT_EQ(pipeline.statistics().detection.state_observations,0U);
    pipeline.flush(); EXPECT_EQ(pipeline.statistics().detection.state_sources,0U);
}
TEST(HardeningRuntime, EventObserverSeesCurrentDetectorMetrics) {
    runtime::EngineImpl engine(std::make_unique<capture::SyntheticCaptureSource>(),
        std::make_unique<pipeline::PipelineImpl>(std::make_unique<detection::PortScanDetector>()),std::make_unique<Sink>());
    engine.on_event([&](events::SecurityEvent) { EXPECT_EQ(engine.metrics().detector_observations,10U); });
    engine.run(); auto m=engine.metrics();
    EXPECT_EQ(m.packets_captured,10U); EXPECT_EQ(m.packets_processed,10U);
    EXPECT_EQ(m.detector_observations,10U); EXPECT_EQ(m.detector_state_observations,0U);
    EXPECT_EQ(m.detector_state_sources,0U); EXPECT_GT(m.processing_seconds,0);
}

TEST(HardeningRuntime, CaptureCountersDoNotConflateKernelParserAndProcessing) {
    struct Source final : capture::CaptureSource {
        capture::PacketCallback callback;
        void set_callback(capture::PacketCallback cb) override { callback=std::move(cb); }
        void start() override {
            auto data=packets(1).at(0);
            callback({Clock::now(),data,1,54,54});
            data.at(12)=std::byte{0x86}; data.at(13)=std::byte{0xdd};
            callback({Clock::now(),data,1,54,54});
            callback({Clock::now(),data,1,64,54});
        }
        void stop() noexcept override {}
        std::string description() const override { return "structured-capture-counters"; }
        capture::CaptureStatistics statistics() const noexcept override { return {99,7,2,3,1,true}; }
    };
    runtime::EngineImpl engine(std::make_unique<Source>(),
        std::make_unique<pipeline::PipelineImpl>(std::make_unique<detection::PortScanDetector>()),std::make_unique<Sink>());
    engine.run(); auto m=engine.metrics();
    EXPECT_EQ(m.packets_seen,99U); EXPECT_EQ(m.packets_captured,3U); EXPECT_EQ(m.packets_received,3U);
    EXPECT_EQ(m.capture_drops,7U); EXPECT_EQ(m.interface_drops,2U); EXPECT_EQ(m.capture_errors,1U);
    EXPECT_TRUE(m.capture_statistics_available);
    EXPECT_EQ(m.packets_parsed,1U); EXPECT_EQ(m.packets_processed,1U);
    EXPECT_EQ(m.packets_unsupported,1U); EXPECT_EQ(m.packets_truncated,1U);
    EXPECT_EQ(m.packets_malformed,1U); EXPECT_EQ(m.packets_rejected,2U);
}

TEST(HardeningRuntime, UnavailableCaptureStatisticsRemainExplicit) {
    struct Empty final : capture::CaptureSource {
        void set_callback(capture::PacketCallback) override {}
        void start() override {} void stop() noexcept override {}
        std::string description() const override { return "unavailable"; }
    };
    runtime::EngineImpl engine(std::make_unique<Empty>(),
        std::make_unique<pipeline::PipelineImpl>(std::make_unique<detection::PortScanDetector>()),std::make_unique<Sink>());
    engine.run(); EXPECT_FALSE(engine.metrics().capture_statistics_available);
}

TEST(HardeningRuntime, FailedPcapIsAnObservableCaptureError) {
    runtime::EngineImpl engine(std::make_unique<capture::PcapReplaySource>(capture::PcapReplayConfig{"/no/such/intriqo.pcap",false}),
        std::make_unique<pipeline::PipelineImpl>(std::make_unique<detection::PortScanDetector>()),std::make_unique<Sink>());
    EXPECT_THROW(engine.run(),std::runtime_error); EXPECT_EQ(engine.metrics().capture_errors,1U);
}

TEST(HardeningRuntime, SlowSynchronousSinkTimeIsMeasuredWithoutAQueue) {
    struct Slow final : transport::SecurityEventSink {
        bool submit(const events::SecurityEvent&) noexcept override {
            std::this_thread::sleep_for(std::chrono::milliseconds(20)); return true;
        }
    };
    runtime::EngineImpl engine(std::make_unique<capture::SyntheticCaptureSource>(),
        std::make_unique<pipeline::PipelineImpl>(std::make_unique<detection::PortScanDetector>()),std::make_unique<Slow>());
    engine.run(); const auto m=engine.metrics();
    EXPECT_EQ(m.events_emitted,1U); EXPECT_GE(m.event_sink_seconds,0.015);
    EXPECT_GE(m.processing_seconds,m.event_sink_seconds-0.001); EXPECT_EQ(m.packets_processed,10U);
}

TEST(HardeningRuntime, NewInstancesSupportRepeatedStartStopCycles) {
    for(unsigned i=0;i<5;++i) {
        runtime::EngineImpl engine(std::make_unique<capture::SyntheticCaptureSource>(),
            std::make_unique<pipeline::PipelineImpl>(std::make_unique<detection::PortScanDetector>()),std::make_unique<Sink>());
        engine.on_started([&] { if(i%2==0) engine.stop(); });
        engine.run(); EXPECT_EQ(engine.metrics().flows_active,0U);
        EXPECT_EQ(engine.metrics().detector_state_observations,0U);
        EXPECT_THROW(engine.run(),std::logic_error);
    }
}
