#include "intriqo/protocol/protocol_parser.hpp"
#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/detection/port_scan_detector.hpp"
#include "intriqo/transport/event_sink.hpp"
#include <array>
#include <iostream>

using namespace intriqo;
static std::array<std::byte,54> syn(std::uint16_t port, TimePoint) { std::array<std::byte,54> b{}; b[12]=std::byte{8};b[13]=std::byte{0};b[14]=std::byte{0x45};b[16]=std::byte{0};b[17]=std::byte{40};b[23]=std::byte{6};b[26]=std::byte{10};b[29]=std::byte{1};b[30]=std::byte{10};b[33]=std::byte{2};b[34]=std::byte{0x9c};b[35]=std::byte{0x40};b[36]=std::byte{static_cast<unsigned char>(port>>8)};b[37]=std::byte{static_cast<unsigned char>(port)};b[46]=std::byte{0x50};b[47]=std::byte{2};return b; }
int main(int argc,char** argv) { std::string output=argc>1?argv[1]:"port-scan-events.jsonl"; auto sink=std::make_shared<transport::FileEventSink>(output); auto detector=std::make_unique<detection::PortScanDetector>(detection::PortScanConfig{10.0,10,10,events::Severity::HIGH}); pipeline::PipelineImpl pipe(std::move(detector)); pipe.on_event([&](events::SecurityEvent e){std::cout<<e.to_json()<<'\n'; sink->submit(e);}); protocol::IPv4Parser parser; auto t=Clock::now(); for(std::uint16_t port=1;port<=10;++port){auto bytes=syn(port,t); auto parsed=parser.parse({t,std::span<const std::byte>(bytes),1}); if(parsed) pipe.ingest(*parsed);} std::cout<<"wrote events to "<<output<<"\n"; return 0; }
