#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/features/features.hpp"
#include <algorithm>
#include <stdexcept>

namespace intriqo::pipeline {

PipelineImpl::PipelineImpl(std::unique_ptr<detection::Detector> detector,
                           Duration timeout, std::size_t max_flows)
    : flows_(timeout, max_flows), detector_(std::move(detector)) {
    if (!detector_) throw std::invalid_argument("pipeline requires a detector");
    publish_statistics();
}

void PipelineImpl::publish_statistics() {
    counters_.flows_active = flows_.size();
    counters_.peak_active_flows = std::max(counters_.peak_active_flows,
                                         counters_.flows_active);
    counters_.detection = detector_->statistics();
    std::lock_guard lock(statistics_mutex_);
    snapshot_ = counters_;
}

void PipelineImpl::evaluate(const flow::NetworkFlow& flow, std::exception_ptr& callback_error) {
    auto events = detector_->evaluate(flow, features::FlowFeatures::from_flow(flow));
    publish_statistics();
    for (auto& event : events) {
        if (!callback_) continue;
        try {
            callback_(std::move(event));
        } catch (...) {
            if (!callback_error) callback_error = std::current_exception();
        }
    }
}

void PipelineImpl::retire(const flow::NetworkFlow& flow, std::exception_ptr& callback_error) {
    // Evaluate while the detector still remembers this ID, avoiding a recount.
    evaluate(flow, callback_error);
    detector_->retire_flow(flow.flow_id);
}

void PipelineImpl::ingest(const packet::ParsedPacket& packet) {
    std::lock_guard lock(processing_mutex_);
    std::exception_ptr callback_error;
    auto update = flows_.update(packet);
    counters_.flows_expired += update.expired.size();
    if (update.evicted) ++counters_.flows_evicted;
    if (update.created) ++counters_.flows_created;
    publish_statistics();
    for (const auto& flow : update.expired) retire(flow, callback_error);
    if (update.evicted) retire(*update.evicted, callback_error);
    // Maintenance follows retirement so expiring detector deduplication cannot
    // cause the completed flow to be counted a second time.
    detector_->expire(packet.timestamp);
    evaluate(update.flow, callback_error);
    publish_statistics();
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
        for (const auto& flow : flushed) retire(flow, callback_error);
    } catch (...) {
        detector_->reset();
        publish_statistics();
        throw;
    }
    detector_->reset();
    publish_statistics();
    if (callback_error) std::rethrow_exception(callback_error);
}

void PipelineImpl::maintain(TimePoint now) {
    std::lock_guard lock(processing_mutex_);
    auto expired = flows_.expire(now);
    counters_.flows_expired += expired.size();
    publish_statistics();
    std::exception_ptr callback_error;
    for (const auto& flow : expired) retire(flow, callback_error);
    detector_->expire(now);
    publish_statistics();
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
