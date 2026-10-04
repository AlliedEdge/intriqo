#include <gtest/gtest.h>
#include "runtime_fixture.hpp"
#include "intriqo/runtime/engine_impl.hpp"
#include "intriqo/transport/queued_event_sink.hpp"
#include "../../tools/runtime_reporting.hpp"
#include <atomic>
#include <condition_variable>
#include <future>
#include <sstream>
#include <thread>

using namespace intriqo;
using namespace runtime_test;

namespace {
constexpr auto wait_limit = std::chrono::seconds(5);

struct Step {
    std::mutex mutex;
    std::condition_variable changed;
    bool open{false};

    void release() {
        std::lock_guard lock(mutex);
        open = true;
        changed.notify_all();
    }
    void wait() {
        std::unique_lock lock(mutex);
        if (!changed.wait_for(lock, wait_limit, [&] { return open; })) {
            throw std::runtime_error("test step was not released");
        }
    }
};

// The worker stays in submit until explicitly released. No timing assumptions
// or sleeps determine whether an event is in flight, pending, or acknowledged.
struct GatedSink final : transport::SecurityEventSink {
    mutable std::mutex mutex;
    mutable std::condition_variable changed;
    std::vector<std::string> submitted;
    unsigned permits{0};
    bool released{false};
    bool acknowledge{true}, prepare_ok{true}, flush_ok{true};
    unsigned flush_calls{0};
    mutable unsigned error_calls{0};

    bool prepare() noexcept override { return prepare_ok; }
    bool submit(const events::SecurityEvent& event) noexcept override {
        std::unique_lock lock(mutex);
        submitted.push_back(event.event_id);
        changed.notify_all();
        changed.wait(lock, [&] { return released || permits != 0; });
        if (!released) --permits;
        return acknowledge;
    }
    bool flush() noexcept override {
        std::lock_guard lock(mutex);
        ++flush_calls;
        return flush_ok;
    }
    std::string error() const override {
        std::lock_guard lock(mutex);
        ++error_calls;
        changed.notify_all();
        return "HTTP event endpoint returned status 503";
    }
    bool wait_entered(std::size_t count) const {
        std::unique_lock lock(mutex);
        return changed.wait_for(lock, wait_limit, [&] { return submitted.size() >= count; });
    }
    bool wait_error() const {
        std::unique_lock lock(mutex);
        // QueuedEventSink publishes its failure counter before asking for error().
        return changed.wait_for(lock, wait_limit, [&] { return error_calls != 0; });
    }
    void release_one() {
        std::lock_guard lock(mutex);
        ++permits;
        changed.notify_all();
    }
    void release_all() {
        std::lock_guard lock(mutex);
        released = true;
        changed.notify_all();
    }
    std::vector<std::string> order() const {
        std::lock_guard lock(mutex);
        return submitted;
    }
};

struct Cleanup {
    GatedSink& sink;
    Step* step{nullptr};
    ~Cleanup() {
        if (step) step->release();
        sink.release_all();
    }
};

struct ScriptedCapture final : capture::CaptureSource {
    capture::PacketCallback packet_callback;
    std::function<void(TimePoint)> idle_callback;
    std::function<void(ScriptedCapture&)> script;
    std::atomic<bool> stopped{false};
    std::vector<std::byte> data{packets(1).front()};

    void set_callback(capture::PacketCallback cb) override { packet_callback = std::move(cb); }
    void set_idle_callback(std::function<void(TimePoint)> cb) override { idle_callback = std::move(cb); }
    void start() override { if (script) script(*this); }
    void stop() noexcept override { stopped = true; }
    std::string description() const override { return "queued-delivery-script"; }
    void packet() { packet_callback({Clock::now(), data, 1}); }
    void malformed_packet() {
        const std::vector<std::byte> bytes(3);
        packet_callback({Clock::now(), bytes, 1});
    }
    void idle() { idle_callback(Clock::now()); }
};

struct EventPipeline final : pipeline::Pipeline {
    pipeline::EventCallback callback;
    std::function<void(EventPipeline&)> ingestion;
    unsigned next_id{0}, final_events{0};
    std::atomic<unsigned> ingests{0}, maintenance{0};

    void emit() {
        events::SecurityEvent event{};
        event.event_id = std::to_string(++next_id);
        callback(std::move(event));
    }
    void ingest(const packet::ParsedPacket&) override {
        ++ingests;
        if (ingestion) ingestion(*this); else emit();
    }
    void on_event(pipeline::EventCallback cb) override { callback = std::move(cb); }
    void flush() override { for (unsigned i = 0; i < final_events; ++i) emit(); }
    void maintain(TimePoint) override { ++maintenance; }
    std::size_t active_flow_count() const noexcept override { return 0; }
};

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::string run_result(runtime::EngineImpl& engine) {
    try {
        engine.run();
        return {};
    } catch (const std::exception& error) {
        return error.what();
    }
}
} // namespace

TEST(QueuedDelivery, AdmissionIsNotAcknowledgmentAndShutdownDrainsInOrder) {
    auto sink = std::make_unique<GatedSink>(); auto* gated = sink.get();
    auto queued = std::make_unique<transport::QueuedEventSink>(std::move(sink), 2);
    auto* delivery = queued.get();
    std::promise<void> admitted;
    auto ready = admitted.get_future();
    auto source = std::make_unique<ScriptedCapture>();
    source->script = [&](ScriptedCapture& capture) {
        capture.packet();
        require(gated->wait_entered(1), "worker did not start first event");
        capture.packet();
        capture.packet();
        admitted.set_value();
    };
    runtime::EngineImpl engine(std::move(source), std::make_unique<EventPipeline>(), std::move(queued));
    // Snapshot from an event observer must not acquire the processing mutex.
    engine.on_event([&](events::SecurityEvent) {
        EXPECT_EQ(engine.metrics().events_emitted, 0U);
    });
    auto run = std::async(std::launch::async, [&] { return run_result(engine); });
    Cleanup cleanup{*gated};
    ASSERT_EQ(ready.wait_for(wait_limit), std::future_status::ready);
    auto m = engine.metrics();
    EXPECT_EQ(m.detections_fired, 3U);
    EXPECT_EQ(m.events_emitted, 0U);
    EXPECT_EQ(m.sink_failures, 0U);
    EXPECT_EQ(m.queue_depth, 2U);
    EXPECT_EQ(m.queue_peak_depth, 2U);
    EXPECT_EQ(m.queue_overflows, 0U);
    EXPECT_EQ(run.wait_for(std::chrono::seconds(0)), std::future_status::timeout);

    gated->release_one();
    ASSERT_TRUE(gated->wait_entered(2));
    m = engine.metrics();
    EXPECT_EQ(m.events_emitted, 1U);
    EXPECT_EQ(m.queue_depth, 1U);
    gated->release_all();
    ASSERT_EQ(run.wait_for(wait_limit), std::future_status::ready);
    EXPECT_TRUE(run.get().empty());
    m = engine.metrics();
    EXPECT_EQ(m.events_emitted, 3U);
    EXPECT_EQ(m.queue_depth, 0U);
    EXPECT_EQ(m.queue_peak_depth, 2U);
    EXPECT_EQ(m.sink_failures, 0U);
    EXPECT_GT(m.event_sink_seconds, 0.0);
    // The runtime must not add time spent joining/draining to worker timing.
    EXPECT_DOUBLE_EQ(m.event_sink_seconds, delivery->delivery_statistics()->event_sink_seconds);
    EXPECT_EQ(gated->order(), (std::vector<std::string>{"1", "2", "3"}));
    EXPECT_EQ(gated->flush_calls, 1U);
}

TEST(QueuedDelivery, CapacityPlusOneInFlightRejectsOverflowAndCountsItOnce) {
    auto sink = std::make_unique<GatedSink>(); auto* gated = sink.get();
    auto queued = std::make_unique<transport::QueuedEventSink>(std::move(sink), 2);
    auto source = std::make_unique<ScriptedCapture>(); auto* capture = source.get();
    std::promise<void> submitted; auto ready = submitted.get_future();
    source->script = [&](ScriptedCapture& input) {
        input.packet();
        require(gated->wait_entered(1), "worker did not start first event");
        input.packet();
        input.packet();
        input.packet();
        submitted.set_value();
    };
    runtime::EngineImpl engine(std::move(source), std::make_unique<EventPipeline>(), std::move(queued));
    auto run = std::async(std::launch::async, [&] { return run_result(engine); });
    Cleanup cleanup{*gated};
    ASSERT_EQ(ready.wait_for(wait_limit), std::future_status::ready);
    auto m = engine.metrics();
    EXPECT_EQ(m.detections_fired, 4U);
    EXPECT_EQ(m.events_emitted, 0U);
    EXPECT_EQ(m.queue_depth, 2U);
    EXPECT_EQ(m.queue_peak_depth, 2U);
    EXPECT_EQ(m.queue_overflows, 1U);
    EXPECT_EQ(m.sink_failures, 1U);
    EXPECT_TRUE(capture->stopped.load());
    gated->release_all();
    ASSERT_EQ(run.wait_for(wait_limit), std::future_status::ready);
    EXPECT_NE(run.get().find("capacity exceeded"), std::string::npos);
    m = engine.metrics();
    EXPECT_EQ(m.events_emitted, 3U);
    EXPECT_EQ(m.sink_failures, 1U); // flush(false) reports the same overflow.
    EXPECT_EQ(m.queue_overflows, 1U);
    EXPECT_EQ(m.queue_depth, 0U);
    EXPECT_EQ(gated->order(), (std::vector<std::string>{"1", "2", "3"}));
    std::ostringstream report;
    tools::detailed_counters(report, m);
    EXPECT_NE(report.str().find(" queue_depth=0 queue_peak_depth=2 queue_overflows=1"), std::string::npos);
}

namespace {
void asynchronous_failure_notice(bool idle) {
    auto sink = std::make_unique<GatedSink>(); auto* gated = sink.get();
    gated->acknowledge = false;
    auto queued = std::make_unique<transport::QueuedEventSink>(std::move(sink), 2);
    auto source = std::make_unique<ScriptedCapture>(); auto* capture = source.get();
    auto pipeline = std::make_unique<EventPipeline>(); auto* processing = pipeline.get();
    Step resume;
    std::promise<void> received; auto receipt_ready = received.get_future();
    std::promise<void> failed; auto failure_ready = failed.get_future();
    std::promise<bool> noticed; auto stop_ready = noticed.get_future();
    source->script = [&](ScriptedCapture& input) {
        input.packet();
        received.set_value();
        require(gated->wait_error(), "worker did not report the failed acknowledgment");
        failed.set_value();
        resume.wait();
        if (idle) input.idle(); else input.malformed_packet();
        noticed.set_value(input.stopped.load());
    };
    runtime::EngineImpl engine(std::move(source), std::move(pipeline), std::move(queued));
    auto run = std::async(std::launch::async, [&] { return run_result(engine); });
    Cleanup cleanup{*gated, &resume};
    ASSERT_TRUE(gated->wait_entered(1));
    ASSERT_EQ(receipt_ready.wait_for(wait_limit), std::future_status::ready);
    gated->release_one();
    ASSERT_EQ(failure_ready.wait_for(wait_limit), std::future_status::ready);
    const auto live = engine.metrics();
    EXPECT_EQ(live.events_emitted, 0U);
    EXPECT_EQ(live.sink_failures, 1U);
    EXPECT_GT(live.event_sink_seconds, 0.0);
    EXPECT_FALSE(capture->stopped.load()); // metrics() reports; it does not stop.
    resume.release();
    ASSERT_EQ(stop_ready.wait_for(wait_limit), std::future_status::ready);
    EXPECT_TRUE(stop_ready.get());
    ASSERT_EQ(run.wait_for(wait_limit), std::future_status::ready);
    EXPECT_NE(run.get().find("HTTP event endpoint returned status 503"), std::string::npos);
    const auto final = engine.metrics();
    EXPECT_EQ(final.sink_failures, 1U);
    EXPECT_EQ(final.events_emitted, 0U);
    EXPECT_EQ(final.queue_depth, 0U);
    EXPECT_EQ(processing->ingests.load(), 1U);
    EXPECT_EQ(processing->maintenance.load(), 0U);
    EXPECT_EQ(final.packets_received, idle ? 1U : 2U);
}
} // namespace

TEST(QueuedDelivery, IdleMaintenanceNoticesAsynchronousHttpEquivalentFailure) {
    asynchronous_failure_notice(true);
}

TEST(QueuedDelivery, PacketReceiptNoticesAsynchronousFailureEvenForRejectedPacket) {
    asynchronous_failure_notice(false);
}

TEST(QueuedDelivery, SubsequentEventCountsFailedDeliveryAndRejectedAdmissionSeparately) {
    auto sink = std::make_unique<GatedSink>(); auto* gated = sink.get();
    gated->acknowledge = false;
    auto queued = std::make_unique<transport::QueuedEventSink>(std::move(sink), 2);
    auto pipeline = std::make_unique<EventPipeline>();
    pipeline->ingestion = [&](EventPipeline& processing) {
        processing.emit();
        require(gated->wait_error(), "worker did not fail the first delivery");
        processing.emit();
    };
    auto source = std::make_unique<ScriptedCapture>();
    source->script = [](ScriptedCapture& capture) { capture.packet(); };
    runtime::EngineImpl engine(std::move(source), std::move(pipeline), std::move(queued));
    auto run = std::async(std::launch::async, [&] { return run_result(engine); });
    Cleanup cleanup{*gated};
    ASSERT_TRUE(gated->wait_entered(1));
    gated->release_all();
    ASSERT_EQ(run.wait_for(wait_limit), std::future_status::ready);
    EXPECT_NE(run.get().find("HTTP event endpoint returned status 503"), std::string::npos);
    const auto m = engine.metrics();
    EXPECT_EQ(m.detections_fired, 2U);
    EXPECT_EQ(m.events_emitted, 0U);
    EXPECT_EQ(m.sink_failures, 2U);
    EXPECT_EQ(m.queue_overflows, 0U);
    EXPECT_EQ(gated->order(), (std::vector<std::string>{"1"}));
}

TEST(QueuedDelivery, ShutdownSurfacesWorkerFailureWithoutCountingFailedFlushAgain) {
    auto sink = std::make_unique<GatedSink>(); auto* gated = sink.get();
    gated->acknowledge = false;
    auto queued = std::make_unique<transport::QueuedEventSink>(std::move(sink), 2);
    auto pipeline = std::make_unique<EventPipeline>();
    pipeline->final_events = 1; // Events generated by pipeline shutdown are drained too.
    runtime::EngineImpl engine(std::make_unique<ScriptedCapture>(), std::move(pipeline), std::move(queued));
    auto run = std::async(std::launch::async, [&] { return run_result(engine); });
    Cleanup cleanup{*gated};
    ASSERT_TRUE(gated->wait_entered(1));
    EXPECT_EQ(engine.metrics().detections_fired, 1U);
    EXPECT_EQ(engine.metrics().events_emitted, 0U);
    gated->release_all();
    ASSERT_EQ(run.wait_for(wait_limit), std::future_status::ready);
    EXPECT_NE(run.get().find("HTTP event endpoint returned status 503"), std::string::npos);
    EXPECT_EQ(engine.metrics().sink_failures, 1U);
    EXPECT_EQ(engine.metrics().events_emitted, 0U);
    EXPECT_EQ(gated->flush_calls, 1U);
}

TEST(QueuedDelivery, InitializationAndUnderlyingFlushFailuresUseAuthoritativeCounts) {
    for (bool fail_prepare : {true, false}) {
        auto sink = std::make_unique<GatedSink>(); auto* gated = sink.get();
        gated->prepare_ok = !fail_prepare;
        gated->flush_ok = fail_prepare;
        auto queued = std::make_unique<transport::QueuedEventSink>(std::move(sink), 2);
        runtime::EngineImpl engine(std::make_unique<ScriptedCapture>(),
                                   std::make_unique<EventPipeline>(), std::move(queued));
        const auto error = run_result(engine);
        EXPECT_NE(error.find("HTTP event endpoint returned status 503"), std::string::npos);
        EXPECT_EQ(engine.metrics().sink_failures, 1U);
        EXPECT_EQ(engine.metrics().events_emitted, 0U);
        EXPECT_EQ(gated->flush_calls, 1U);
    }
}

TEST(QueuedDelivery, OrdinarySinkPreservesSynchronousAcknowledgmentsAndFailureCounting) {
    struct Immediate final : transport::SecurityEventSink {
        bool success;
        explicit Immediate(bool ok) : success(ok) {}
        bool submit(const events::SecurityEvent&) noexcept override { return success; }
        bool flush() noexcept override { return success; }
        std::string error() const override { return "synchronous sink failed"; }
    };
    for (bool success : {true, false}) {
        auto source = std::make_unique<ScriptedCapture>();
        source->script = [](ScriptedCapture& capture) { capture.packet(); };
        runtime::EngineImpl engine(std::move(source), std::make_unique<EventPipeline>(),
                                   std::make_unique<Immediate>(success));
        engine.on_event([&](events::SecurityEvent) {
            EXPECT_EQ(engine.metrics().events_emitted, success ? 1U : 0U);
            EXPECT_EQ(engine.metrics().sink_failures, success ? 0U : 1U);
        });
        const auto error = run_result(engine);
        EXPECT_EQ(error.empty(), success);
        const auto m = engine.metrics();
        EXPECT_EQ(m.detections_fired, 1U);
        EXPECT_EQ(m.events_emitted, success ? 1U : 0U);
        EXPECT_EQ(m.sink_failures, success ? 0U : 2U);
        EXPECT_EQ(m.queue_depth, 0U);
        EXPECT_EQ(m.queue_peak_depth, 0U);
        EXPECT_EQ(m.queue_overflows, 0U);
        EXPECT_GT(m.event_sink_seconds, 0.0);
    }
}
