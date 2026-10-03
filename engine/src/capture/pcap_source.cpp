#include "intriqo/capture/capture.hpp"
#include "capture_internal.hpp"

#include <array>
#include <fstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace intriqo::capture {

struct PcapReplaySource::State : detail::CaptureState {};

PcapReplaySource::PcapReplaySource(PcapReplayConfig config)
    : config_(std::move(config)), state_(std::make_unique<State>()) {}

PcapReplaySource::~PcapReplaySource() = default;

void PcapReplaySource::set_callback(PacketCallback cb) { state_->set_callback(std::move(cb)); }
void PcapReplaySource::set_ready_callback(std::function<void()> cb) { state_->set_ready_callback(std::move(cb)); }
void PcapReplaySource::stop() noexcept { state_->stop(); }
std::string PcapReplaySource::description() const { return "pcap:" + config_.file_path; }
CaptureStatistics PcapReplaySource::statistics() const noexcept { return state_->statistics(); }

void PcapReplaySource::start() {
    const auto callback = state_->begin();
    if (!callback) return;

    const auto fail = [this](const std::string& reason) {
        return std::runtime_error("PCAP replay '" + config_.file_path + "': " + reason);
    };
    std::ifstream input(config_.file_path, std::ios::binary);
    if (!input) throw fail("cannot open file");

    std::array<unsigned char, 24> global{};
    input.read(reinterpret_cast<char*>(global.data()), global.size());
    if (input.gcount() != static_cast<std::streamsize>(global.size())) {
        throw fail("short global header (expected 24 bytes)");
    }

    const auto magic = detail::read32(global.data(), false);
    bool little_endian = false;
    bool nanoseconds = false;
    switch (magic) {
        case 0xd4c3b2a1: little_endian = true; break;
        case 0xa1b2c3d4: break;
        case 0x4d3cb2a1: little_endian = true; nanoseconds = true; break;
        case 0xa1b23c4d: nanoseconds = true; break;
        default: throw fail("unsupported magic number (expected a classic PCAP file)");
    }
    if (detail::read16(global.data() + 4, little_endian) != 2
        || detail::read16(global.data() + 6, little_endian) != 4) {
        throw fail("unsupported PCAP version (expected 2.4)");
    }
    const auto snaplen = detail::read32(global.data() + 16, little_endian);
    if (snaplen == 0 || snaplen > detail::max_packet_length) {
        throw fail("invalid snaplen (must be between 1 and 16777216 bytes)");
    }
    // Modern classic PCAP permits FCS metadata in the high bits of this field.
    const auto network = detail::read32(global.data() + 20, little_endian);
    if ((network & 0x0bff0000U) != 0
        || ((network & 0xf0000000U) != 0 && (network & 0x04000000U) == 0)) {
        throw fail("invalid datalink/FCS metadata (reserved bits must be zero)");
    }
    const auto link_type = network & 0xffffU;
    try {
        detail::validate_link_type(link_type);
    } catch (const std::exception& error) {
        throw fail(error.what());
    }

    std::vector<std::byte> bytes;
    state_->ready();
    std::vector<std::byte> normalized_storage;
    std::uint64_t record = 0;
    TimePoint first_timestamp{};
    std::chrono::steady_clock::time_point replay_start{};
    while (!state_->stopped.load()) {
        std::array<unsigned char, 16> header{};
        input.read(reinterpret_cast<char*>(header.data()), header.size());
        const auto header_size = input.gcount();
        if (header_size == 0 && input.eof() && !input.bad()) break;
        ++record;
        const auto record_fail = [&](const std::string& reason) {
            return fail("record " + std::to_string(record) + ": " + reason);
        };
        if (header_size != static_cast<std::streamsize>(header.size())) {
            throw record_fail("short record header (expected 16 bytes)");
        }

        const auto seconds = detail::read32(header.data(), little_endian);
        const auto fraction = detail::read32(header.data() + 4, little_endian);
        const auto captured_length = detail::read32(header.data() + 8, little_endian);
        const auto wire_length = detail::read32(header.data() + 12, little_endian);
        if (fraction >= (nanoseconds ? 1'000'000'000U : 1'000'000U)) {
            throw record_fail("timestamp fraction is out of range");
        }
        if (captured_length > snaplen || captured_length > detail::max_packet_length
            || captured_length > wire_length || wire_length > detail::max_packet_length) {
            throw record_fail("invalid captured/original packet lengths");
        }

        bytes.resize(captured_length);
        if (captured_length != 0) {
            input.read(reinterpret_cast<char*>(bytes.data()), captured_length);
            if (input.gcount() != static_cast<std::streamsize>(captured_length)) {
                throw record_fail("short packet body (expected "
                                  + std::to_string(captured_length) + " bytes)");
            }
        }
        const auto subsecond = nanoseconds ? std::chrono::nanoseconds(fraction)
                                          : std::chrono::nanoseconds(std::chrono::microseconds(fraction));
        const auto timestamp = TimePoint{std::chrono::duration_cast<Clock::duration>(
            std::chrono::seconds(seconds) + subsecond)};

        if (record == 1) {
            first_timestamp = timestamp;
            replay_start = std::chrono::steady_clock::now();
        }
        if (config_.realtime && timestamp > first_timestamp) {
            const auto delay = std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                timestamp - first_timestamp);
            if (delay > std::chrono::steady_clock::time_point::max() - replay_start) {
                throw record_fail("realtime timestamp delay is out of range");
            }
            if (state_->wait_until(replay_start + delay)) break;
        }
        if (state_->stopped.load()) break;
        const auto normalized = detail::normalize(bytes, link_type, normalized_storage);
        state_->received.fetch_add(1);
        callback({timestamp, normalized.bytes, normalized.link_type, wire_length, captured_length});
    }
}

} // namespace intriqo::capture
