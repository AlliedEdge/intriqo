#include "intriqo/runtime/engine_impl.hpp"
#include <algorithm>
#include <exception>
#include <optional>
#include <stdexcept>

namespace intriqo::runtime {
namespace {

enum class PacketKind { ipv4, malformed, unsupported, truncated };

PacketKind classify(packet::PacketView packet) noexcept {
    const auto bytes = packet.raw_bytes;
    const auto caplen = packet.captured_length != 0 ? packet.captured_length : bytes.size();
    if (packet.wire_length != 0 && packet.wire_length > caplen) {
        return PacketKind::truncated;
    }
    std::size_t ip_offset = 0;
    if (packet.link_layer_type == 1) { // DLT_EN10MB
        if (bytes.size() < 14) return PacketKind::malformed;
        if (bytes[12] != std::byte{0x08} || bytes[13] != std::byte{0x00}) {
            return PacketKind::unsupported;
        }
        ip_offset = 14;
    } else if (packet.link_layer_type != 12 && packet.link_layer_type != 101 &&
               packet.link_layer_type != 228) { // DLT_RAW / LINKTYPE_RAW / DLT_IPV4
        return PacketKind::unsupported;
    }
    if (bytes.size() <= ip_offset) return PacketKind::malformed;
    if ((std::to_integer<unsigned char>(bytes[ip_offset]) >> 4) != 4) {
        // An Ethernet frame advertised as IPv4 (or DLT_IPV4) with a wrong
        // version is malformed. Valid raw IPv6 is merely unsupported.
        const auto version = std::to_integer<unsigned char>(bytes[ip_offset]) >> 4;
        return version == 6 && packet.link_layer_type != 1 && packet.link_layer_type != 228
            ? PacketKind::unsupported : PacketKind::malformed;
    }
    return PacketKind::ipv4;
}

void apply_pipeline_statistics(metrics::EngineMetrics& counters,
                               const pipeline::PipelineStatistics& statistics) noexcept {
    counters.flows_created = statistics.flows_created;
    counters.flows_expired = statistics.flows_expired;
    counters.flows_flushed = statistics.flows_flushed;
    counters.flows_active = statistics.flows_active;
    counters.flows_evicted = statistics.flows_evicted;
    counters.peak_active_flows = statistics.peak_active_flows;
    const auto& detection = statistics.detection;
    counters.detector_observations = detection.observations;
    counters.detector_state_sources = detection.state_sources;
    counters.detector_state_observations = detection.state_observations;
    counters.detector_peak_sources = detection.peak_sources;
    counters.detector_peak_observations = detection.peak_observations;
    counters.detector_expired_sources = detection.expired_sources;
    counters.detector_expired_observations = detection.expired_observations;
    counters.detector_state_rejections = detection.state_rejections;
    counters.detector_state_evictions = detection.state_evictions;
    counters.detector_syn_observations = detection.syn_observations;
    counters.detector_syn_ack_observations = detection.syn_ack_observations;
    counters.detector_ack_completions = detection.ack_completions;
    counters.detector_incomplete_handshakes = detection.incomplete_handshakes;
    counters.detector_errors = detection.errors;
}

void apply_capture_statistics(metrics::EngineMetrics& counters,
                              const capture::CaptureStatistics& statistics) noexcept {
    counters.packets_seen = statistics.packets_received;
    // Old/custom CaptureSource implementations may have only the default
    // statistics(). The runtime still knows how many callbacks it received.
    counters.packets_captured = std::max(counters.packets_received, statistics.packets_captured);
    counters.capture_drops = statistics.packets_dropped;
    counters.interface_drops = statistics.interface_dropped;
    counters.packets_dropped = statistics.packets_dropped + statistics.interface_dropped;
    counters.capture_errors = statistics.errors;
    counters.capture_statistics_available = statistics.statistics_available;
}

void apply_delivery_statistics(metrics::EngineMetrics& counters,
                               const transport::EventDeliveryStatistics& statistics) noexcept {
    counters.events_emitted = statistics.events_emitted;
    counters.sink_failures = statistics.event_sink_failures;
    counters.event_sink_seconds = statistics.event_sink_seconds;
    counters.queue_depth = statistics.queue_depth;
    counters.queue_peak_depth = statistics.queue_peak_depth;
    counters.queue_overflows = statistics.queue_overflows;
}

std::string exception_message(const std::exception_ptr& exception) {
    try {
        std::rethrow_exception(exception);
    } catch (const std::exception& error) {
        return error.what();
    } catch (...) {
        return "unknown exception";
    }
}

} // namespace

EngineImpl::EngineImpl(std::unique_ptr<capture::CaptureSource> capture,
                       std::unique_ptr<pipeline::Pipeline> pipeline,
                       std::unique_ptr<transport::SecurityEventSink> sink)
    : capture_(std::move(capture)), pipeline_(std::move(pipeline)), sink_(std::move(sink)) {
    if (!capture_) throw std::invalid_argument("engine requires a capture source");
    if (!pipeline_) throw std::invalid_argument("engine requires a pipeline");
    if (!sink_) throw std::invalid_argument("engine requires an event sink");
}

void EngineImpl::set_capture(std::unique_ptr<capture::CaptureSource> capture) {
    if (!capture) throw std::invalid_argument("engine requires a capture source");
    std::unique_ptr<capture::CaptureSource> previous;
    {
        std::lock_guard lock(lifecycle_mutex_);
        if (lifecycle_ != Lifecycle::ready) {
            throw std::logic_error("capture cannot be changed after engine run starts");
        }
        previous = std::move(capture_);
        capture_ = std::move(capture);
    }
}

void EngineImpl::set_pipeline(std::unique_ptr<pipeline::Pipeline> pipeline) {
    if (!pipeline) throw std::invalid_argument("engine requires a pipeline");
    std::unique_ptr<pipeline::Pipeline> previous;
    {
        std::lock_guard lock(lifecycle_mutex_);
        if (lifecycle_ != Lifecycle::ready) {
            throw std::logic_error("pipeline cannot be changed after engine run starts");
        }
        previous = std::move(pipeline_);
        pipeline_ = std::move(pipeline);
    }
}

void EngineImpl::on_event(pipeline::EventCallback callback) {
    std::lock_guard lock(lifecycle_mutex_);
    if (lifecycle_ != Lifecycle::ready) {
        throw std::logic_error("event callback cannot be changed after engine run starts");
    }
    event_callback_ = std::move(callback);
}

void EngineImpl::stop() noexcept {
    stop_requested_.store(true, std::memory_order_release);
    capture::CaptureSource* capture = nullptr;
    {
        std::lock_guard lock(lifecycle_mutex_);
        if (lifecycle_ == Lifecycle::running) capture = capture_.get();
    }
    // Capture can be blocking; never call it while holding a runtime mutex.
    if (capture) capture->stop();
}

void EngineImpl::on_started(std::function<void()> callback) {
    std::lock_guard lock(lifecycle_mutex_);
    if (lifecycle_ != Lifecycle::ready) throw std::logic_error("Configure readiness before engine run");
    started_callback_ = std::move(callback);
}

void EngineImpl::sync_pipeline_statistics() {
    const auto statistics = pipeline_->statistics();
    std::lock_guard lock(metrics_mutex_);
    apply_pipeline_statistics(counters_, statistics);
}

void EngineImpl::sync_capture_statistics() {
    const auto statistics = capture_->statistics();
    std::lock_guard lock(metrics_mutex_);
    apply_capture_statistics(counters_, statistics);
}

bool EngineImpl::sync_sink_statistics(const char* operation) {
    const auto statistics = sink_->delivery_statistics();
    if (!statistics) return false;
    std::string detail;
    if (statistics->event_sink_failures != 0) {
        try {
            detail = sink_->error();
        } catch (...) {
            detail = "sink error details unavailable";
        }
    }
    {
        std::lock_guard lock(metrics_mutex_);
        apply_delivery_statistics(counters_, *statistics);
        if (statistics->event_sink_failures != 0) {
            // Refresh details after drain, when the worker has finished recording
            // its underlying error. A snapshot can see the counter slightly sooner.
            sink_error_ = operation;
            if (!detail.empty()) sink_error_ += ": " + detail;
        }
    }
    if (statistics->event_sink_failures != 0) stop();
    return true;
}

void EngineImpl::record_sink_failure(const char* operation) {
    // Queued sinks already count failed delivery and each rejected admission.
    // In particular, flush(false) can merely report an earlier worker failure.
    if (sync_sink_statistics(operation)) return;
    std::string detail;
    try {
        detail = sink_->error();
    } catch (...) {
        detail = "sink error details unavailable";
    }
    std::lock_guard lock(metrics_mutex_);
    ++counters_.sink_failures;
    if (sink_error_.empty()) {
        sink_error_ = operation;
        if (!detail.empty()) sink_error_ += ": " + detail;
    }
}

void EngineImpl::receive_event(events::SecurityEvent event) {
    {
        std::lock_guard lock(metrics_mutex_);
        ++counters_.detections_fired;
    }
    const auto sink_started = std::chrono::steady_clock::now();
    const bool submitted = sink_->submit(event);
    const auto sink_seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - sink_started).count();
    if (!sync_sink_statistics(submitted ? "event delivery failed" : "event submission failed")) {
        std::lock_guard lock(metrics_mutex_);
        counters_.event_sink_seconds += sink_seconds;
        if (submitted) ++counters_.events_emitted;
    }
    if (!submitted) {
        record_sink_failure("event submission failed");
        stop();
    }
    if (event_callback_) {
        try {
            event_callback_(std::move(event));
        } catch (...) {
            throw std::runtime_error("event callback failed: " +
                                     exception_message(std::current_exception()));
        }
    }
}

void EngineImpl::receive_packet(packet::PacketView packet) {
    std::lock_guard processing_lock(processing_mutex_);
    const auto processing_started = std::chrono::steady_clock::now();
    sync_sink_statistics("event delivery failed");
    const auto kind = classify(packet);
    const auto parsed = kind == PacketKind::ipv4 ? parser_.parse(packet) : std::nullopt;
    {
        std::lock_guard lock(metrics_mutex_);
        ++counters_.packets_received;
        ++counters_.packets_captured;
        if (parsed) {
            ++counters_.packets_parsed;
        } else {
            ++counters_.packets_rejected;
            if (kind == PacketKind::unsupported) ++counters_.packets_unsupported;
            else ++counters_.packets_malformed;
            if (kind == PacketKind::truncated) ++counters_.packets_truncated;
        }
    }
    const auto finish_processing = [&](bool processed) {
        const auto elapsed = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - processing_started).count();
        std::lock_guard lock(metrics_mutex_);
        counters_.processing_seconds += elapsed;
        if (processed) ++counters_.packets_processed;
    };
    if (parsed && !stop_requested_.load(std::memory_order_acquire)) {
        try {
            pipeline_->ingest(*parsed);
        } catch (...) {
            finish_processing(false);
            throw std::runtime_error("pipeline ingestion failed: " +
                                     exception_message(std::current_exception()));
        }
        finish_processing(true);
    } else {
        finish_processing(false);
    }
}

void EngineImpl::maintain(TimePoint now) {
    std::lock_guard processing_lock(processing_mutex_);
    sync_sink_statistics("event delivery failed");
    if (stop_requested_.load(std::memory_order_acquire)) return;
    try {
        pipeline_->maintain(now);
    } catch (...) {
        sync_pipeline_statistics();
        throw std::runtime_error("pipeline maintenance failed: " +
                                 exception_message(std::current_exception()));
    }
    sync_pipeline_statistics();
}

void EngineImpl::run() {
    {
        std::lock_guard lock(lifecycle_mutex_);
        if (lifecycle_ != Lifecycle::ready) {
            throw std::logic_error("engine run may only be called once");
        }
        lifecycle_ = Lifecycle::running;
    }
    {
        std::lock_guard lock(metrics_mutex_);
        started_at_ = std::chrono::steady_clock::now();
        started_ = true;
    }

    std::exception_ptr capture_failure;
    std::exception_ptr pipeline_failure;
    const char* phase = "engine setup failed";
    try {
        pipeline_->on_event([this](events::SecurityEvent event) {
            receive_event(std::move(event));
        });
        if (!sink_->prepare()) {
            record_sink_failure("event sink initialization failed");
            throw std::runtime_error("configured event sink is unavailable");
        }
        capture_->set_callback([this](packet::PacketView packet) { receive_packet(packet); });
        capture_->set_ready_callback(started_callback_);
        capture_->set_idle_callback([this](TimePoint now) { maintain(now); });
        phase = "capture failed";
        // A stop requested before run is deliberately retained.
        if (!stop_requested_.load(std::memory_order_acquire)) capture_->start();
    } catch (...) {
        capture_failure = std::current_exception();
    }

    capture_->stop();
    {
        std::lock_guard lock(processing_mutex_);
        try {
            pipeline_->flush();
        } catch (...) {
            pipeline_failure = std::current_exception();
        }
        sync_pipeline_statistics();
    }
    const auto flush_started = std::chrono::steady_clock::now();
    const bool flushed = sink_->flush();
    const auto flush_seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - flush_started).count();
    if (!sync_sink_statistics("event delivery failed")) {
        {
            std::lock_guard lock(metrics_mutex_);
            counters_.event_sink_seconds += flush_seconds;
        }
        if (!flushed) record_sink_failure("event sink flush failed");
    }
    sync_capture_statistics();
    std::uint64_t sink_failures = 0;
    std::string sink_error;
    {
        std::lock_guard lock(metrics_mutex_);
        counters_.runtime_seconds = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - started_at_).count();
        finished_ = true;
        sink_failures = counters_.sink_failures;
        sink_error = sink_error_;
    }
    {
        std::lock_guard lock(lifecycle_mutex_);
        lifecycle_ = Lifecycle::finished;
    }

    std::string failure;
    auto append_failure = [&](const char* context, const std::exception_ptr& error) {
        if (!error) return;
        if (!failure.empty()) failure += "; ";
        failure += std::string(context) + ": " + exception_message(error);
    };
    append_failure(phase, capture_failure);
    append_failure("pipeline flush failed", pipeline_failure);
    if (sink_failures != 0) {
        if (!failure.empty()) failure += "; ";
        failure += "event sink failed (" + std::to_string(sink_failures) +
                   " failures): " + sink_error;
    }
    if (!failure.empty()) throw std::runtime_error(failure);
}

metrics::EngineMetrics EngineImpl::metrics() const {
    pipeline::PipelineStatistics pipeline_statistics;
    capture::CaptureStatistics capture_statistics;
    std::optional<transport::EventDeliveryStatistics> delivery_statistics;
    {
        // Keep dependencies alive during configuration changes. Never acquire
        // processing_mutex_: metrics() is valid inside an event observer.
        std::lock_guard lock(lifecycle_mutex_);
        pipeline_statistics = pipeline_->statistics();
        capture_statistics = capture_->statistics();
        delivery_statistics = sink_->delivery_statistics();
    }
    metrics::EngineMetrics result;
    {
        std::lock_guard lock(metrics_mutex_);
        result = counters_;
        if (started_ && !finished_) {
            result.runtime_seconds = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - started_at_).count();
        }
    }
    apply_pipeline_statistics(result, pipeline_statistics);
    apply_capture_statistics(result, capture_statistics);
    // Read-only live accounting: reporting an asynchronous failure must not
    // itself stop capture or wait for the worker/network.
    if (delivery_statistics) apply_delivery_statistics(result, *delivery_statistics);
    result.snapshot_time = Clock::now();
    result.pps = result.runtime_seconds > 0.0
        ? static_cast<double>(result.packets_received) / result.runtime_seconds : 0.0;
    result.processing_packets_per_second = result.processing_seconds > 0.0
        ? static_cast<double>(result.packets_processed) / result.processing_seconds : 0.0;
    return result;
}

} // namespace intriqo::runtime
