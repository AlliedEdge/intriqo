#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/features/features.hpp"
#include <algorithm>
#include <stdexcept>

namespace intriqo::pipeline {

PipelineImpl::PipelineImpl(std::unique_ptr<detection::Detector> detector,
                           Duration timeout, std::size_t max_flows,
                           std::shared_ptr<transport::FlowFeatureSink> feature_sink,
                           std::string engine_instance_id, bool feature_version2)
     : flows_(timeout, max_flows, feature_version2), detector_(std::move(detector)),
       feature_sink_(std::move(feature_sink)), engine_instance_id_(std::move(engine_instance_id)),
       feature_version2_(feature_version2) {
    if (!detector_) throw std::invalid_argument("pipeline requires a detector");
    if (feature_sink_ && engine_instance_id_.empty()) {
        try { engine_instance_id_ = features::make_engine_instance_id(); }
        catch (...) { ++counters_.feature_setup_failures; }
    }
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

void PipelineImpl::export_features(const flow::NetworkFlow& flow,
                                   features::FlowExportReason reason) noexcept {
    if (!feature_sink_) return;
    const auto started = std::chrono::steady_clock::now();
    try {
        if (feature_version2_) {
            auto record = features::FlowFeatureRecordV2::from_flow(flow, engine_instance_id_, reason);
            ++counters_.feature_records_generated;
            (void)feature_sink_->submit_v2(record);
        } else {
            auto record = features::FlowFeatureRecord::from_flow(flow, engine_instance_id_, reason);
            ++counters_.feature_records_generated;
            (void)feature_sink_->submit(record);
        }
    } catch (...) {
        ++counters_.feature_generation_failures;
    }
    counters_.feature_generation_seconds += std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started).count();
}

void PipelineImpl::retire(const flow::NetworkFlow& flow, std::exception_ptr& callback_error,
                          features::FlowExportReason reason) {
    // Evaluate while the detector still remembers this ID, avoiding a recount.
    evaluate(flow, callback_error);
    detector_->retire_flow(flow.flow_id);
    export_features(flow, reason);
}

void PipelineImpl::ingest(const packet::ParsedPacket& packet) {
    std::lock_guard lock(processing_mutex_);
    std::exception_ptr callback_error;
    auto update = flows_.update(packet);
    counters_.flows_expired += update.expired.size();
    if (update.evicted) ++counters_.flows_evicted;
    if (update.created) ++counters_.flows_created;
    publish_statistics();
    for (const auto& flow : update.expired)
        retire(flow, callback_error, features::FlowExportReason::idle_expired);
    if (update.evicted)
        retire(*update.evicted, callback_error, features::FlowExportReason::capacity_evicted);
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
        for (const auto& flow : flushed)
            retire(flow, callback_error, features::FlowExportReason::shutdown_flush);
    } catch (...) {
        detector_->reset();
        if (feature_sink_) (void)feature_sink_->flush();
        publish_statistics();
        throw;
    }
    detector_->reset();
    if (feature_sink_) (void)feature_sink_->flush();
    publish_statistics();
    if (callback_error) std::rethrow_exception(callback_error);
}

void PipelineImpl::maintain(TimePoint now) {
    std::lock_guard lock(processing_mutex_);
    auto expired = flows_.expire(now);
    counters_.flows_expired += expired.size();
    publish_statistics();
    std::exception_ptr callback_error;
    for (const auto& flow : expired)
        retire(flow, callback_error, features::FlowExportReason::idle_expired);
    detector_->expire(now);
    publish_statistics();
    if (callback_error) std::rethrow_exception(callback_error);
}

std::size_t PipelineImpl::active_flow_count() const noexcept {
    return statistics().flows_active;
}

PipelineStatistics PipelineImpl::statistics() const noexcept {
    PipelineStatistics result;
    {
        std::lock_guard lock(statistics_mutex_);
        result = snapshot_;
    }
    // Read worker counters on demand, not on every packet/statistics publication.
    if (feature_sink_) result.feature_stream = feature_sink_->statistics();
    return result;
}

} // namespace intriqo::pipeline
