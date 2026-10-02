#include "intriqo/protocol/protocol_parser.hpp"
#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/detection/port_scan_detector.hpp"
#include "intriqo/transport/event_sink.hpp"
#include <array>
#include <cstdlib>
#include <iostream>
#include <memory>

using namespace intriqo;
static std::array<std::byte,54> syn(std::uint16_t port) { std::array<std::byte,54> b{}; b[12]=std::byte{8};b[13]=std::byte{0};b[14]=std::byte{0x45};b[16]=std::byte{0};b[17]=std::byte{40};b[23]=std::byte{6};b[26]=std::byte{10};b[29]=std::byte{1};b[30]=std::byte{10};b[33]=std::byte{2};b[34]=std::byte{0x9c};b[35]=std::byte{0x40};b[36]=std::byte{static_cast<unsigned char>(port>>8)};b[37]=std::byte{static_cast<unsigned char>(port)};b[46]=std::byte{0x50};b[47]=std::byte{2};return b; }
static const char* env(const char* name) { return std::getenv(name); }

int main(int argc, char** argv) {
    const auto output = argc > 1 ? argv[1] : "port-scan-events.jsonl";
    std::unique_ptr<transport::SecurityEventSink> sink;
    const auto base_url = env("INTRIQO_CONTROL_PLANE_URL");
    if (base_url) {
        std::string endpoint = env("INTRIQO_CONTROL_PLANE_ENDPOINT") ? env("INTRIQO_CONTROL_PLANE_ENDPOINT") : "/api/v1/events";
        sink = std::make_unique<transport::HttpEventSink>(transport::HttpEventSink::Config{
            std::string(base_url) + endpoint, 3, env("INTRIQO_CONTROL_PLANE_TOKEN") ? env("INTRIQO_CONTROL_PLANE_TOKEN") : ""});
    } else sink = std::make_unique<transport::FileEventSink>(output);
    auto detector = std::make_unique<detection::PortScanDetector>(detection::PortScanConfig{10.0,10,10,events::Severity::HIGH});
    bool delivery_failed = false;
    pipeline::PipelineImpl pipe(std::move(detector));
    pipe.on_event([&](events::SecurityEvent event) {
        const auto json = event.to_json();
        std::cout << json << '\n';
        if (!sink->submit(event)) { delivery_failed = true; std::cerr << "event delivery failed: " << (dynamic_cast<transport::HttpEventSink*>(sink.get()) ? dynamic_cast<transport::HttpEventSink*>(sink.get())->last_error() : "file sink failure") << '\n'; }
        else std::cerr << "event delivered: " << event.event_id << '\n';
    });
    protocol::IPv4Parser parser; const auto timestamp = Clock::now();
    for (std::uint16_t port = 1; port <= 10; ++port) { auto bytes=syn(port); auto parsed=parser.parse({timestamp,std::span<const std::byte>(bytes),1}); if(parsed) pipe.ingest(*parsed); }
    if (!base_url) std::cout << "wrote events to " << output << '\n';
    return delivery_failed ? 2 : 0;
}
