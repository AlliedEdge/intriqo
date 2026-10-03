#include <gtest/gtest.h>
#include "runtime_fixture.hpp"
#include "intriqo/protocol/protocol_parser.hpp"
#include "intriqo/detection/port_scan_detector.hpp"
#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/runtime/engine_impl.hpp"
#include <future>
using namespace intriqo;
using namespace runtime_test;

TEST(Capture, SyntheticStopAndSingleUse) {
    capture::SyntheticCaptureSource source({100,10}); unsigned count = 0;
    source.set_callback([&](packet::PacketView p) {
        EXPECT_EQ(p.wire_length, 54U); EXPECT_EQ(p.raw_bytes.size(), 54U);
        ++count; source.stop();
    });
    source.start(); EXPECT_EQ(count, 1U); EXPECT_EQ(source.statistics().packets_received, 1U);
    EXPECT_THROW(source.start(), std::logic_error);
    EXPECT_THROW(source.set_callback({}), std::logic_error);
}

TEST(Capture, CallbackErrorsPropagateAndMissingCallbackIsError) {
    capture::SyntheticCaptureSource source;
    source.set_callback([](packet::PacketView) { throw std::runtime_error("callback failed"); });
    EXPECT_THROW(source.start(), std::runtime_error);
    capture::SyntheticCaptureSource empty;
    EXPECT_THROW(empty.start(), std::invalid_argument);
}

TEST(Capture, PcapEndianAndTimestampPrecision) {
    for (bool little : {false,true}) for (bool nano : {false,true}) {
        TempFile file; pcap(file.path, packets(1), 1, little, nano);
        capture::PcapReplaySource source({file.path.string(),false}); unsigned count = 0;
        source.set_callback([&](packet::PacketView p) {
            ++count; EXPECT_EQ(p.wire_length, 54U);
            const auto expected = TimePoint{std::chrono::seconds(1700000000)} +
                (nano ? std::chrono::nanoseconds(123456789) : std::chrono::nanoseconds(123456000));
            EXPECT_EQ(p.timestamp, expected); EXPECT_TRUE(protocol::IPv4Parser{}.parse(p));
        });
        source.start(); EXPECT_EQ(count, 1U);
    }
}

TEST(Capture, PcapShortHeadersBodiesAndUnsupportedDatalinkFailClearly) {
    TempFile file;
    for (unsigned length : {0U,23U,25U,39U,40U,45U}) {
        pcap(file.path, packets(1)); std::filesystem::resize_file(file.path, length);
        capture::PcapReplaySource source({file.path.string(),false}); source.set_callback([](packet::PacketView) {});
        EXPECT_THROW(source.start(), std::runtime_error) << "length=" << length;
    }
    pcap(file.path, {}, 999);
    capture::PcapReplaySource source({file.path.string(),false}); source.set_callback([](packet::PacketView) {});
    EXPECT_THROW(source.start(), std::runtime_error);
}

TEST(Capture, PcapEmptyFileWithValidHeaderIsValidInput) {
    TempFile file; pcap(file.path, {});
    capture::PcapReplaySource source({file.path.string(),false}); unsigned count = 0;
    source.set_callback([&](packet::PacketView) { ++count; }); source.start(); EXPECT_EQ(count, 0U);
}

TEST(Capture, CookedAndLoopbackFramesNormalizeWithoutFalseTruncation) {
    struct NullSink final : transport::SecurityEventSink {
        bool submit(const events::SecurityEvent&) noexcept override { return true; }
    };
    const auto ethernet = packets(1)[0];
    for (std::uint32_t link : {0U,108U,113U,276U,101U}) {
        std::size_t header = link == 0 || link == 108 ? 4 : link == 113 ? 16 : link == 276 ? 20 : 0;
        std::vector<std::byte> frame(header);
        if (link == 0) frame[0] = std::byte{2};
        if (link == 108) frame[3] = std::byte{2};
        if (link == 113) frame[14] = std::byte{8};
        if (link == 276) frame[0] = std::byte{8};
        frame.insert(frame.end(), ethernet.begin()+14, ethernet.end());
        TempFile file; pcap(file.path, {frame}, link);
        runtime::EngineImpl engine(std::make_unique<capture::PcapReplaySource>(capture::PcapReplayConfig{file.path.string(),false}),
            std::make_unique<pipeline::PipelineImpl>(std::make_unique<detection::PortScanDetector>()), std::make_unique<NullSink>());
        engine.run(); EXPECT_EQ(engine.metrics().packets_parsed, 1U) << link;
        EXPECT_EQ(engine.metrics().packets_malformed, 0U) << link;
    }
}

TEST(Capture, RealtimePacingIsInterruptibleWhileIdle) {
    TempFile file; pcap(file.path, packets(2), 1, true, false, 0, 60);
    capture::PcapReplaySource source({file.path.string(),true});
    std::promise<void> first; auto ready = first.get_future();
    std::atomic<unsigned> count{0};
    source.set_callback([&](packet::PacketView) { if (++count == 1) first.set_value(); });
    auto run = std::async(std::launch::async, [&] { source.start(); });
    EXPECT_EQ(ready.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    source.stop(); EXPECT_EQ(run.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_NO_THROW(run.get()); EXPECT_EQ(count.load(), 1U);
}

TEST(Capture, LiveUnsupportedOrInvalidInterfaceReportsErrorWithoutHardware) {
    capture::LiveCaptureConfig config; config.interface_name = "intriqo_nonexistent_interface";
    capture::LiveCaptureSource source(config);
    source.set_callback([](packet::PacketView) {});
    EXPECT_THROW(source.start(), std::runtime_error);
    capture::LiveCaptureSource stopped(config);
    stopped.stop(); EXPECT_NO_THROW(stopped.start());
}
