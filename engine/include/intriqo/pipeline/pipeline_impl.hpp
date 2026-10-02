#pragma once

#include "intriqo/pipeline/pipeline.hpp"
#include "intriqo/flow/flow.hpp"
#include "intriqo/detection/detector.hpp"
#include <memory>

namespace intriqo::pipeline {

class PipelineImpl final : public Pipeline {
public:
    explicit PipelineImpl(std::unique_ptr<detection::Detector> detector,
                          Duration flow_timeout = Duration{60.0});
    void ingest(const packet::ParsedPacket&) override;
    void on_event(EventCallback) override;
    void flush() override;
    [[nodiscard]] std::size_t active_flow_count() const noexcept override;
private:
    flow::FlowTable flows_;
    std::unique_ptr<detection::Detector> detector_;
    EventCallback callback_;
};

} // namespace intriqo::pipeline
