#include <gtest/gtest.h>
#include "intriqo/capture/capture.hpp"
#include "intriqo/detection/port_scan_detector.hpp"
#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/runtime/engine_impl.hpp"
#include "intriqo/transport/flow_feature_sink.hpp"
#include <utility>
#include <vector>

using namespace intriqo;

namespace {
struct FeatureObserver final : transport::FlowFeatureSink {
    std::vector<features::FlowFeatureRecord> records;
    bool reject{false};
    unsigned flushes{0};
    transport::FlowFeatureSinkStatistics counters;
    bool submit(const features::FlowFeatureRecord& record) noexcept override {
        ++counters.records_submitted;
        if (!reject) {
            try { records.push_back(record); return true; } catch (...) {}
        }
        ++counters.records_dropped;
        return false;
    }
    bool flush() noexcept override { ++flushes; return !reject; }
    transport::FlowFeatureSinkStatistics statistics() const noexcept override { return counters; }
};

struct Events final : transport::SecurityEventSink {
    unsigned delivered{0};
    bool submit(const events::SecurityEvent&) noexcept override { ++delivered; return true; }
};

// Reuse genuine synthetic packet bytes and the runtime's idle callback. Only
// time is controlled here; parsing, flow tracking and feature extraction are real.
struct IdleAfterSynthetic final : capture::CaptureSource {
    capture::SyntheticCaptureSource source;
    std::function<void(TimePoint)> idle;
    void set_callback(capture::PacketCallback callback) override {
        source.set_callback(std::move(callback));
    }
    void set_idle_callback(std::function<void(TimePoint)> callback) override {
        idle = std::move(callback);
    }
    void start() override {
        source.start();
        const auto now = TimePoint{std::chrono::seconds{1'700'000'002}};
        idle(now);
        idle(now); // maintenance is idempotent after retirement
    }
    void stop() noexcept override { source.stop(); }
    std::string description() const override { return "synthetic-with-controlled-idle"; }
};

std::unique_ptr<pipeline::PipelineImpl> pipeline_with(
        const std::shared_ptr<FeatureObserver>& sink) {
    return std::make_unique<pipeline::PipelineImpl>(
        std::make_unique<detection::PortScanDetector>(), Duration{1}, 32, sink,
        "01234567-89ab-4cde-8f01-23456789abcd");
}
} // namespace

TEST(FlowFeaturePipeline, IdleMaintenanceExportsEveryFlowOnceBeforeShutdown) {
    auto features = std::make_shared<FeatureObserver>();
    runtime::EngineImpl engine(std::make_unique<IdleAfterSynthetic>(),
        pipeline_with(features), std::make_unique<Events>());
    ASSERT_NO_THROW(engine.run());
    const auto metrics = engine.metrics();
    EXPECT_EQ(metrics.packets_parsed, 10U);
    EXPECT_EQ(metrics.flows_expired, 10U);
    EXPECT_EQ(metrics.flows_flushed, 0U);
    EXPECT_EQ(metrics.feature_records_generated, 10U);
    EXPECT_EQ(metrics.flows_active, 0U);
    ASSERT_EQ(features->records.size(), 10U);
    for (std::size_t index = 0; index < features->records.size(); ++index) {
        const auto& record = features->records[index];
        EXPECT_EQ(record.flow_id, index + 1);
        EXPECT_EQ(record.export_reason, features::FlowExportReason::idle_expired);
        EXPECT_EQ(record.features.packet_count, 1U);
        EXPECT_EQ(record.features.byte_count, 40U);
        EXPECT_NO_THROW((void)record.to_json());
    }
    EXPECT_EQ(features->flushes, 1U);
    EXPECT_EQ(metrics.events_emitted, 1U);
}

TEST(FlowFeaturePipeline, FailedFeatureAdmissionAndFlushDoNotStopDeterministicDetection) {
    auto features = std::make_shared<FeatureObserver>();
    features->reject = true;
    auto events = std::make_unique<Events>();
    auto* observed = events.get();
    runtime::EngineImpl engine(std::make_unique<capture::SyntheticCaptureSource>(),
        pipeline_with(features), std::move(events));
    ASSERT_NO_THROW(engine.run());
    const auto metrics = engine.metrics();
    EXPECT_EQ(metrics.packets_parsed, 10U);
    EXPECT_EQ(metrics.flows_flushed, 10U);
    EXPECT_EQ(metrics.flows_active, 0U);
    EXPECT_EQ(metrics.feature_records_generated, 10U);
    EXPECT_EQ(metrics.feature_stream.records_submitted, 10U);
    EXPECT_EQ(metrics.feature_stream.records_dropped, 10U);
    EXPECT_EQ(metrics.events_emitted, 1U);
    EXPECT_EQ(metrics.sink_failures, 0U);
    EXPECT_EQ(observed->delivered, 1U);
    EXPECT_EQ(features->flushes, 1U);
}
