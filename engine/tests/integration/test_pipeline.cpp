#include <gtest/gtest.h>
#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/detection/port_scan_detector.hpp"
using namespace intriqo;
TEST(Pipeline, SyntheticPortScanProducesContractEvent) { auto detector=std::make_unique<detection::PortScanDetector>(detection::PortScanConfig{10,3,3,events::Severity::HIGH}); pipeline::PipelineImpl pipe(std::move(detector)); std::vector<events::SecurityEvent> out; pipe.on_event([&](events::SecurityEvent e){out.push_back(std::move(e));}); auto t=Clock::now(); for(int i=0;i<3;i++){packet::ParsedPacket p{};p.timestamp=t;p.src_ip={{10,0,0,1}};p.dst_ip={{10,0,0,2}};p.src_port=40000;p.dst_port=static_cast<Port>(80+i);p.protocol=Protocol::TCP;p.total_length=54;p.tcp_flags=0x02;pipe.ingest(p);} ASSERT_EQ(out.size(),1u); EXPECT_NE(out[0].to_json().find("source_address"),std::string::npos); }
