#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/features/features.hpp"

namespace intriqo::pipeline {
PipelineImpl::PipelineImpl(std::unique_ptr<detection::Detector> d,Duration timeout):flows_(timeout),detector_(std::move(d)){}
void PipelineImpl::ingest(const packet::ParsedPacket& p){ auto u=flows_.update(p); auto events=detector_->evaluate(u.flow,features::FlowFeatures::from_flow(u.flow)); for(auto& e:events)if(callback_)callback_(std::move(e)); for(auto& f:flows_.expire(p.timestamp)){auto es=detector_->evaluate(f,features::FlowFeatures::from_flow(f));for(auto& e:es)if(callback_)callback_(std::move(e));} }
void PipelineImpl::on_event(EventCallback cb){callback_=std::move(cb);}
void PipelineImpl::flush(){for(auto& f:flows_.flush()){auto es=detector_->evaluate(f,features::FlowFeatures::from_flow(f));for(auto& e:es)if(callback_)callback_(std::move(e));} detector_->reset();}
std::size_t PipelineImpl::active_flow_count() const noexcept{return flows_.size();}
}
