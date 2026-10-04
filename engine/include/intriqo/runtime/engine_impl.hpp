#pragma once

#include "intriqo/runtime/engine.hpp"
#include "intriqo/protocol/protocol_parser.hpp"
#include "intriqo/transport/event_sink.hpp"
#include <atomic>
#include <mutex>
#include <string>

namespace intriqo::runtime {

/// Blocking, single-run capture runtime. Configure before run(); stop() and
/// metrics() may be called concurrently with run(). Capture start() must return
/// only after its packet callbacks have finished, and report failures by throwing.
class EngineImpl final : public Engine {
public:
    EngineImpl(std::unique_ptr<capture::CaptureSource> capture,
               std::unique_ptr<pipeline::Pipeline> pipeline,
               std::unique_ptr<transport::SecurityEventSink> sink);

    void set_capture(std::unique_ptr<capture::CaptureSource>) override;
    void set_pipeline(std::unique_ptr<pipeline::Pipeline>) override;
    void on_event(pipeline::EventCallback) override;
    /// Notified once the concrete capture source is ready. Configure before run().
    void on_started(std::function<void()>);
    void run() override;
    void stop() noexcept override;
    [[nodiscard]] metrics::EngineMetrics metrics() const override;

private:
    enum class Lifecycle { ready, running, finished };
    void receive_packet(packet::PacketView);
    void receive_event(events::SecurityEvent);
    void maintain(TimePoint);
    void sync_pipeline_statistics();
    void sync_capture_statistics();
    /// Returns true when the sink owns authoritative delivery accounting.
    /// Called on the processing/run thread; snapshots do not request stop.
    bool sync_sink_statistics(const char* operation);
    void record_sink_failure(const char* operation);

    mutable std::mutex lifecycle_mutex_;
    Lifecycle lifecycle_{Lifecycle::ready};
    std::atomic<bool> stop_requested_{false};
    std::unique_ptr<capture::CaptureSource> capture_;
    std::unique_ptr<pipeline::Pipeline> pipeline_;
    std::unique_ptr<transport::SecurityEventSink> sink_;
    pipeline::EventCallback event_callback_;
    std::function<void()> started_callback_;
    protocol::IPv4Parser parser_;
    std::mutex processing_mutex_;
    mutable std::mutex metrics_mutex_;
    metrics::EngineMetrics counters_;
    std::chrono::steady_clock::time_point started_at_{};
    bool started_{false};
    bool finished_{false};
    std::string sink_error_;
};

} // namespace intriqo::runtime
