#pragma once

#include "intriqo/pipeline/pipeline.hpp"
#include "intriqo/flow/flow.hpp"
#include "intriqo/detection/detector.hpp"
#include <memory>
#include <mutex>
#include <exception>

namespace intriqo::pipeline {

class PipelineImpl final : public Pipeline {
public:
    explicit PipelineImpl(std::unique_ptr<detection::Detector> detector,
                          Duration flow_timeout = Duration{60.0},
                          std::size_t max_flows = 100000,
                          std::shared_ptr<transport::FlowFeatureSink> feature_sink = nullptr,
                          std::string engine_instance_id = {},
                          bool feature_version2 = false);
    void ingest(const packet::ParsedPacket&) override;
    void on_event(EventCallback) override;
    void flush() override;
    void maintain(TimePoint) override;
    [[nodiscard]] std::size_t active_flow_count() const noexcept override;
    [[nodiscard]] PipelineStatistics statistics() const noexcept override;
private:
    void evaluate(const flow::NetworkFlow&, std::exception_ptr& callback_error);
    void retire(const flow::NetworkFlow&, std::exception_ptr& callback_error,
                features::FlowExportReason);
    void export_features(const flow::NetworkFlow&, features::FlowExportReason) noexcept;
    void publish_statistics();

    std::mutex processing_mutex_;
    mutable std::mutex statistics_mutex_;
    flow::FlowTable flows_;
    std::unique_ptr<detection::Detector> detector_;
    const std::shared_ptr<transport::FlowFeatureSink> feature_sink_;
    std::string engine_instance_id_;
    const bool feature_version2_;
    EventCallback callback_;
    PipelineStatistics counters_;
    PipelineStatistics snapshot_;
};

} // namespace intriqo::pipeline
