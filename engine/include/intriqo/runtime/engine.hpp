#pragma once

#include "intriqo/capture/capture.hpp"
#include "intriqo/pipeline/pipeline.hpp"
#include "intriqo/metrics/metrics.hpp"
#include <memory>

namespace intriqo::runtime {

/// Top-level engine runtime.
///
/// Wires together: CaptureSource → PacketParser → Pipeline → Detectors → Events
///
/// Callers configure the engine, attach an event callback, and call run().
class Engine {
public:
    virtual ~Engine() = default;

    /// Attach a live capture source.
    virtual void set_capture(std::unique_ptr<capture::CaptureSource> source) = 0;

    /// Attach the processing pipeline.
    virtual void set_pipeline(std::unique_ptr<pipeline::Pipeline> pipe) = 0;

    /// Register event callback (forwarded to the pipeline).
    virtual void on_event(pipeline::EventCallback cb) = 0;

    /// Start the engine (blocks the calling thread until stop() is called).
    virtual void run() = 0;

    /// Request a graceful shutdown.
    virtual void stop() noexcept = 0;

    /// Current engine metrics snapshot.
    [[nodiscard]] virtual metrics::EngineMetrics metrics() const = 0;
};

} // namespace intriqo::runtime
