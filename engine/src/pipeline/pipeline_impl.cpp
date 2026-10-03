#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/features/features.hpp"
#include <stdexcept>

namespace intriqo::pipeline {

PipelineImpl::PipelineImpl(std::unique_ptr<detection::Detector> detector, Duration timeout)
    : flows_(timeout), detector_(std::move(detector)) {
    if (!detector_) throw std::invalid_argument("pipeline requires a detector");
}

void PipelineImpl::publish_statistics() {
    counters_.flows_active = flows_.size();
    std::lock_guard lock(statistics_mutex_);
    snapshot_ = counters_;
}

void PipelineImpl::evaluate(const flow::NetworkFlow& flow, std::exception_ptr& callback_error) {
    auto events = detector_->evaluate(flow, features::FlowFeatures::from_flow(flow));
    for (auto& event : events) {
        if (!callback_) continue;
        try {
            callback_(std::move(event));
        } catch (...) {
            if (!callback_error) callback_error = std::current_exception();
        }
    }
}

void PipelineImpl::ingest(const packet::ParsedPacket& packet) {
    std::lock_guard lock(processing_mutex_);
    std::exception_ptr callback_error;
    // Expire before update so a packet arriving after the timeout creates a new flow.
    auto expired = flows_.expire(packet.timestamp);
    counters_.flows_expired += expired.size();
    publish_statistics();
    for (const auto& flow : expired) evaluate(flow, callback_error);

    auto update = flows_.update(packet);
    if (update.created) ++counters_.flows_created;
    publish_statistics();
    evaluate(update.flow, callback_error);
    if (callback_error) std::rethrow_exception(callback_error);
}

void PipelineImpl::on_event(EventCallback callback) {
    std::lock_guard lock(processing_mutex_);
    callback_ = std::move(callback);
}

void PipelineImpl::flush() {
    std::lock_guard lock(processing_mutex_);
    auto flushed = flows_.flush();
    counters_.flows_flushed += flushed.size();
    publish_statistics();
    std::exception_ptr callback_error;
    try {
        for (const auto& flow : flushed) evaluate(flow, callback_error);
    } catch (...) {
        detector_->reset();
        throw;
    }
    detector_->reset();
    if (callback_error) std::rethrow_exception(callback_error);
}

std::size_t PipelineImpl::active_flow_count() const noexcept {
    return statistics().flows_active;
}

PipelineStatistics PipelineImpl::statistics() const noexcept {
    std::lock_guard lock(statistics_mutex_);
    return snapshot_;
}

} // namespace intriqo::pipeline
