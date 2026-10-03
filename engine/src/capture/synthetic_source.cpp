#include "intriqo/capture/capture.hpp"
#include "capture_internal.hpp"

#include <array>
#include <stdexcept>
#include <utility>

namespace intriqo::capture {
namespace {

void write16(std::array<std::byte, 54>& bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = std::byte(value >> 8);
    bytes[offset + 1] = std::byte(value & 0xff);
}

std::uint16_t checksum(std::span<const std::byte> bytes, std::uint32_t sum = 0) {
    for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
        sum += (std::to_integer<std::uint16_t>(bytes[i]) << 8)
             | std::to_integer<std::uint16_t>(bytes[i + 1]);
    }
    if (bytes.size() % 2 != 0) sum += std::to_integer<std::uint16_t>(bytes.back()) << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}

std::array<std::byte, 54> tcp_packet(std::size_t index, std::size_t unique_ports) {
    std::array<std::byte, 54> bytes{};
    // Locally administered MACs and documentation-only IPv4 addresses.
    bytes[0] = std::byte{0x02}; bytes[5] = std::byte{0x02};
    bytes[6] = std::byte{0x02}; bytes[11] = std::byte{0x01};
    write16(bytes, 12, 0x0800);
    bytes[14] = std::byte{0x45};
    write16(bytes, 16, 40);
    write16(bytes, 18, static_cast<std::uint16_t>(index));
    write16(bytes, 20, 0x4000); // Don't fragment
    bytes[22] = std::byte{64}; bytes[23] = std::byte{6};
    bytes[26] = std::byte{192}; bytes[27] = std::byte{0};
    bytes[28] = std::byte{2}; bytes[29] = std::byte{10};
    bytes[30] = std::byte{198}; bytes[31] = std::byte{51};
    bytes[32] = std::byte{100}; bytes[33] = std::byte{20};
    write16(bytes, 34, 49152);
    write16(bytes, 36, static_cast<std::uint16_t>(1 + index % unique_ports));
    const auto sequence = static_cast<std::uint32_t>(index);
    bytes[38] = std::byte(sequence >> 24);
    bytes[39] = std::byte((sequence >> 16) & 0xff);
    bytes[40] = std::byte((sequence >> 8) & 0xff);
    bytes[41] = std::byte(sequence & 0xff);
    bytes[46] = std::byte{0x50}; bytes[47] = std::byte{0x02}; // TCP SYN
    write16(bytes, 48, 64240);
    write16(bytes, 24, checksum(std::span(bytes).subspan(14, 20)));
    // IPv4 TCP pseudo-header: source/destination, protocol, and TCP length.
    const auto address_sum = static_cast<std::uint16_t>(~checksum(std::span(bytes).subspan(26, 8)));
    write16(bytes, 50, checksum(std::span(bytes).subspan(34, 20), address_sum + 6U + 20U));
    return bytes;
}

} // namespace

struct SyntheticCaptureSource::State : detail::CaptureState {};

SyntheticCaptureSource::SyntheticCaptureSource(SyntheticCaptureConfig config)
    : config_(config), state_(std::make_unique<State>()) {
    if (config_.unique_ports == 0 || config_.unique_ports > 65535) {
        throw std::invalid_argument("Synthetic capture unique_ports must be between 1 and 65535");
    }
}

SyntheticCaptureSource::~SyntheticCaptureSource() = default;

void SyntheticCaptureSource::set_callback(PacketCallback cb) { state_->set_callback(std::move(cb)); }
void SyntheticCaptureSource::set_ready_callback(std::function<void()> cb) { state_->set_ready_callback(std::move(cb)); }
void SyntheticCaptureSource::stop() noexcept { state_->stop(); }
std::string SyntheticCaptureSource::description() const { return "synthetic"; }
CaptureStatistics SyntheticCaptureSource::statistics() const noexcept { return state_->statistics(); }

void SyntheticCaptureSource::start() {
    const auto callback = state_->begin();
    if (!callback) return;
    auto timestamp = TimePoint{std::chrono::seconds(1'700'000'000)};
    state_->ready();
    for (std::size_t i = 0; i < config_.packet_count && !state_->stopped.load(); ++i) {
        const auto bytes = tcp_packet(i, config_.unique_ports);
        state_->received.fetch_add(1);
        callback({timestamp, bytes, detail::ethernet_link_type, bytes.size()});
        timestamp += std::chrono::milliseconds(1);
    }
}

} // namespace intriqo::capture
