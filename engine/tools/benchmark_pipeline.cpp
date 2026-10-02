#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/detection/port_scan_detector.hpp"
#include <chrono>
#include <iostream>
using namespace intriqo;
int main(int argc,char**){const std::size_t n=100000; auto d=std::make_unique<detection::PortScanDetector>(detection::PortScanConfig{10,1000000,1000000,events::Severity::LOW});pipeline::PipelineImpl p(std::move(d)); auto t=Clock::now(); auto start=std::chrono::steady_clock::now(); for(std::size_t i=0;i<n;++i){packet::ParsedPacket x{};x.timestamp=t;x.src_ip={{10,0,0,1}};x.dst_ip={{10,0,0,2}};x.src_port=40000;x.dst_port=static_cast<Port>((i%1000)+1);x.protocol=Protocol::TCP;x.total_length=54;x.tcp_flags=2;p.ingest(x);}auto elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();std::cout<<"packets="<<n<<" elapsed_seconds="<<elapsed<<" packets_per_second="<<(n/elapsed)<<" active_flows="<<p.active_flow_count()<<"\n";}
