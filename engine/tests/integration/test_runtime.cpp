#include <gtest/gtest.h>
#include "runtime_fixture.hpp"
#include "intriqo/runtime/engine_impl.hpp"
#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/detection/detector_registry.hpp"
#include "intriqo/detection/port_scan_detector.hpp"
#include <condition_variable>
#include <future>
#include <thread>

using namespace intriqo;
using namespace runtime_test;
namespace {
struct Sink final : transport::SecurityEventSink {
    std::vector<events::SecurityEvent> events;
    bool fail{false}, flush_fail{false}, flushed{false};
    bool submit(const events::SecurityEvent& event) noexcept override {
        if (fail) return false;
        try { events.push_back(event); return true; } catch (...) { return false; }
    }
    bool flush() noexcept override { flushed = true; return !flush_fail; }
    std::string error() const override { return "test delivery error"; }
};
struct Source final : capture::CaptureSource {
    capture::PacketCallback callback;
    std::vector<std::vector<std::byte>> data;
    bool failure{false};
    std::atomic<bool> stopped{false};
    void set_callback(capture::PacketCallback cb) override { callback = std::move(cb); }
    void start() override {
        for (const auto& bytes : data) {
            if (stopped.load()) break;
            callback({TimePoint{std::chrono::seconds(1700000000)}, bytes, 1});
        }
        if (failure) throw std::runtime_error("controlled capture failure");
    }
    void stop() noexcept override { stopped = true; }
    std::string description() const override { return "unit-source"; }
};
std::unique_ptr<pipeline::PipelineImpl> pipe(Duration timeout = Duration{60}) {
    auto registry = std::make_unique<detection::DetectorRegistry>();
    registry->add(std::make_unique<detection::PortScanDetector>());
    return std::make_unique<pipeline::PipelineImpl>(std::move(registry), timeout);
}
}

TEST(Runtime, SyntheticStartsProcessesDetectsAndEmits) {
    auto sink = std::make_unique<Sink>(); auto* observed = sink.get();
    runtime::EngineImpl engine(std::make_unique<capture::SyntheticCaptureSource>(), pipe(), std::move(sink));
    unsigned ready = 0; engine.on_started([&] { ++ready; });
    EXPECT_NO_THROW(engine.run());
    const auto m = engine.metrics();
    EXPECT_EQ(ready, 1U);
    EXPECT_EQ(m.packets_received, 10U); EXPECT_EQ(m.packets_parsed, 10U);
    EXPECT_EQ(m.packets_malformed, 0U); EXPECT_EQ(m.packets_rejected, 0U);
    EXPECT_EQ(m.flows_created, 10U); EXPECT_EQ(m.flows_flushed, 10U); EXPECT_EQ(m.flows_active, 0U);
    EXPECT_EQ(m.detections_fired, 1U); EXPECT_EQ(m.events_emitted, 1U); EXPECT_EQ(m.sink_failures, 0U);
    ASSERT_EQ(observed->events.size(), 1U);
    EXPECT_EQ(observed->events[0].event_type, events::EventType::PORT_SCAN);
    EXPECT_EQ(observed->events[0].severity, events::Severity::HIGH);
    EXPECT_NE(observed->events[0].to_json().find("PORT_SCAN"), std::string::npos);
    EXPECT_TRUE(observed->flushed); EXPECT_GT(m.runtime_seconds, 0); EXPECT_GT(m.pps, 0);
    EXPECT_THROW(engine.run(), std::logic_error);
}

TEST(Runtime, EmptyInputFlushesWithoutEvents) {
    auto sink = std::make_unique<Sink>(); auto* observed = sink.get();
    runtime::EngineImpl engine(std::make_unique<capture::SyntheticCaptureSource>(capture::SyntheticCaptureConfig{0,10}), pipe(), std::move(sink));
    engine.run(); auto m = engine.metrics();
    EXPECT_EQ(m.packets_received, 0U); EXPECT_EQ(m.detections_fired, 0U); EXPECT_EQ(m.flows_active, 0U);
    EXPECT_TRUE(observed->flushed);
}

TEST(Runtime, MalformedAndUnsupportedPacketsAccountedSeparately) {
    auto source = std::make_unique<Source>(); source->data = packets(1);
    source->data.push_back(std::vector<std::byte>(3));
    auto bad_version = source->data.at(0); bad_version.at(14) = std::byte{0x35}; source->data.push_back(bad_version);
    auto arp = source->data.at(0); arp.at(12) = std::byte{8}; arp.at(13) = std::byte{6}; source->data.push_back(arp);
    runtime::EngineImpl engine(std::move(source), pipe(), std::make_unique<Sink>());
    engine.run(); auto m = engine.metrics();
    EXPECT_EQ(m.packets_received, 4U); EXPECT_EQ(m.packets_parsed, 1U);
    EXPECT_EQ(m.packets_rejected, 3U); EXPECT_EQ(m.packets_malformed, 2U);
    EXPECT_EQ(m.packets_received, m.packets_parsed + m.packets_rejected);
}

TEST(Runtime, CaptureFailurePropagatesAndFlushes) {
    auto source = std::make_unique<Source>(); source->data = packets(1); source->failure = true;
    auto sink = std::make_unique<Sink>(); auto* observed = sink.get();
    runtime::EngineImpl engine(std::move(source), pipe(), std::move(sink));
    try { engine.run(); FAIL() << "expected failure"; }
    catch (const std::runtime_error& error) { EXPECT_NE(std::string(error.what()).find("controlled capture failure"), std::string::npos); }
    EXPECT_TRUE(observed->flushed); EXPECT_EQ(engine.metrics().flows_flushed, 1U);
}

TEST(Runtime, SinkFailureStopsAndReportsActualCounters) {
    auto sink = std::make_unique<Sink>(); auto* observed = sink.get(); sink->fail = true;
    runtime::EngineImpl engine(std::make_unique<capture::SyntheticCaptureSource>(capture::SyntheticCaptureConfig{100,10}), pipe(), std::move(sink));
    EXPECT_THROW(engine.run(), std::runtime_error);
    auto m = engine.metrics(); EXPECT_EQ(m.packets_received, 10U); EXPECT_EQ(m.detections_fired, 1U);
    EXPECT_EQ(m.events_emitted, 0U); EXPECT_EQ(m.sink_failures, 1U); EXPECT_EQ(m.flows_active, 0U);
    EXPECT_TRUE(observed->flushed);
}

TEST(Runtime, SinkFlushFailureIsNotSilent) {
    auto sink = std::make_unique<Sink>(); sink->flush_fail = true;
    runtime::EngineImpl engine(std::make_unique<Source>(), pipe(), std::move(sink));
    EXPECT_THROW(engine.run(), std::runtime_error); EXPECT_EQ(engine.metrics().sink_failures, 1U);
}

TEST(Runtime, StopBeforeRunRemainsEffective) {
    runtime::EngineImpl engine(std::make_unique<capture::SyntheticCaptureSource>(), pipe(), std::make_unique<Sink>());
    engine.stop(); engine.run(); EXPECT_EQ(engine.metrics().packets_received, 0U);
}

TEST(Runtime, ConcurrentStopAndMetricsWakeIdleCapture) {
    struct Idle final : capture::CaptureSource {
        std::mutex mutex; std::condition_variable wake; bool stopped{false};
        std::promise<void> started;
        void set_callback(capture::PacketCallback) override {}
        void start() override {
            std::unique_lock lock(mutex); started.set_value();
            wake.wait(lock, [&] { return stopped; });
        }
        void stop() noexcept override { std::lock_guard lock(mutex); stopped = true; wake.notify_all(); }
        std::string description() const override { return "idle-test"; }
    };
    auto source = std::make_unique<Idle>(); auto started = source->started.get_future();
    runtime::EngineImpl engine(std::move(source), pipe(), std::make_unique<Sink>());
    auto task = std::async(std::launch::async, [&] { engine.run(); });
    ASSERT_EQ(started.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(engine.metrics().packets_received, 0U);
    EXPECT_THROW(engine.set_pipeline(pipe()), std::logic_error);
    engine.stop(); EXPECT_EQ(task.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_NO_THROW(task.get()); EXPECT_EQ(engine.metrics().flows_active, 0U);
}

TEST(Runtime, EventObserverFailuresStillFlush) {
    auto sink = std::make_unique<Sink>(); auto* observed = sink.get();
    runtime::EngineImpl engine(std::make_unique<capture::SyntheticCaptureSource>(), pipe(), std::move(sink));
    engine.on_event([](events::SecurityEvent) { throw std::runtime_error("observer failure"); });
    EXPECT_THROW(engine.run(), std::runtime_error); EXPECT_TRUE(observed->flushed);
    EXPECT_EQ(engine.metrics().events_emitted, 1U); EXPECT_EQ(engine.metrics().flows_active, 0U);
}

TEST(Runtime, PcapModeDetectsAndCountsExpiration) {
    TempFile file; pcap(file.path, packets(), 1, true, false, 0, 1);
    auto source = std::make_unique<capture::PcapReplaySource>(capture::PcapReplayConfig{file.path.string(),false});
    runtime::EngineImpl engine(std::move(source), pipe(Duration{0.5}), std::make_unique<Sink>());
    engine.run(); auto m = engine.metrics();
    EXPECT_EQ(m.packets_parsed, 10U); EXPECT_EQ(m.flows_created, 10U);
    EXPECT_EQ(m.flows_expired, 9U); EXPECT_EQ(m.flows_flushed, 1U); EXPECT_EQ(m.events_emitted, 1U);
}

TEST(Runtime, TruncatedPcapPacketIsRejected) {
    TempFile file; pcap(file.path, packets(1), 1, true, false, 10);
    runtime::EngineImpl engine(std::make_unique<capture::PcapReplaySource>(capture::PcapReplayConfig{file.path.string(),false}), pipe(), std::make_unique<Sink>());
    engine.run(); auto m = engine.metrics();
    EXPECT_EQ(m.packets_received, 1U); EXPECT_EQ(m.packets_malformed, 1U); EXPECT_EQ(m.packets_parsed, 0U);
}

TEST(Registry, NamesRegistrationAndFreeze) {
    detection::DetectorRegistry registry;
    EXPECT_THROW(registry.add(nullptr), std::invalid_argument);
    registry.add(std::make_unique<detection::PortScanDetector>());
    EXPECT_EQ(registry.names(), std::vector<std::string>{"port_scan"});
    EXPECT_THROW(registry.add(std::make_unique<detection::PortScanDetector>()), std::invalid_argument);
    flow::NetworkFlow flow{}; features::FlowFeatures features{};
    EXPECT_TRUE(registry.evaluate(flow, features).empty());
    EXPECT_THROW(registry.add(std::make_unique<detection::PortScanDetector>()), std::logic_error);
    registry.reset();
}

TEST(Registry, DispatchesEveryRegisteredDetectorAndResets) {
    struct Counting final : detection::Detector {
        std::string label; int evaluated{0}, resets{0};
        explicit Counting(std::string n) : label(std::move(n)) {}
        std::string_view name() const noexcept override { return label; }
        std::vector<events::SecurityEvent> evaluate(const flow::NetworkFlow&, const features::FlowFeatures&) noexcept override { ++evaluated; return {}; }
        void reset() noexcept override { ++resets; }
    };
    detection::DetectorRegistry registry;
    auto first = std::make_unique<Counting>("first"); auto* a = first.get();
    auto second = std::make_unique<Counting>("second"); auto* b = second.get();
    registry.add(std::move(first)); registry.add(std::move(second));
    (void)registry.evaluate({},{}); registry.reset();
    EXPECT_EQ(a->evaluated, 1); EXPECT_EQ(b->evaluated, 1); EXPECT_EQ(a->resets, 1); EXPECT_EQ(b->resets, 1);
}

TEST(Runtime, DependenciesMustNotBeNull) {
    EXPECT_THROW((runtime::EngineImpl(nullptr, pipe(), std::make_unique<Sink>())), std::invalid_argument);
    EXPECT_THROW((runtime::EngineImpl(std::make_unique<Source>(), nullptr, std::make_unique<Sink>())), std::invalid_argument);
    EXPECT_THROW((runtime::EngineImpl(std::make_unique<Source>(), pipe(), nullptr)), std::invalid_argument);
}

TEST(Runtime, DropRateIsBoundedWhenKernelDropsExceedDeliveredPackets) {
    metrics::EngineMetrics m;
    EXPECT_DOUBLE_EQ(m.drop_rate(), 0.0);
    m.packets_received = 10; m.packets_dropped = 30;
    EXPECT_DOUBLE_EQ(m.drop_rate(), 0.75);
    m.packets_received = 0; EXPECT_DOUBLE_EQ(m.drop_rate(), 1.0);
}
