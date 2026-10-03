#pragma once

#include "intriqo/capture/capture.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>

namespace intriqo::capture::detail {

constexpr std::uint32_t max_packet_length = 16U * 1024U * 1024U;
constexpr std::size_t ethernet_link_type = 1;
constexpr std::size_t raw_ip_link_type = 101;

// A stop request is never reset. Synchronizing it with the wait mutex prevents
// lost notifications between the pacing predicate and its condition-variable wait.
struct CaptureState {
    std::mutex mutex;
    std::condition_variable wake;
    std::atomic<bool> stopped{false};
    bool started{false}; // protected by mutex
    PacketCallback callback;
    std::function<void()> ready_callback;
    std::atomic<std::uint64_t> received{0};
    std::atomic<std::uint64_t> dropped{0};
    std::atomic<std::uint64_t> interface_dropped{0};

    void set_callback(PacketCallback cb) {
        std::lock_guard lock(mutex);
        if (started) {
            throw std::logic_error("Capture source is single-use; set its callback before start()");
        }
        callback = std::move(cb);
    }

    PacketCallback begin() {
        std::lock_guard lock(mutex);
        if (started) {
            throw std::logic_error("Capture source is single-use; start() has already been called");
        }
        started = true;
        if (stopped.load()) return {};
        if (!callback) throw std::invalid_argument("Capture source requires a packet callback");
        return callback;
    }

    void set_ready_callback(std::function<void()> cb) {
        std::lock_guard lock(mutex);
        if (started) throw std::logic_error("Set readiness callback before capture starts");
        ready_callback = std::move(cb);
    }
    void ready() {
        // Configuration is immutable after begin(); no lock across user code.
        if (ready_callback && !stopped.load()) ready_callback();
    }

    void stop() noexcept {
        {
            std::lock_guard lock(mutex);
            stopped.store(true);
        }
        wake.notify_all();
    }

    bool wait_until(std::chrono::steady_clock::time_point deadline) {
        std::unique_lock lock(mutex);
        return wake.wait_until(lock, deadline, [this] { return stopped.load(); });
    }

    CaptureStatistics statistics() const noexcept {
        return {received.load(), dropped.load(), interface_dropped.load()};
    }
};

inline std::uint16_t read16(const unsigned char* bytes, bool little_endian) noexcept {
    if (little_endian) {
        return std::uint16_t(bytes[0]) | (std::uint16_t(bytes[1]) << 8);
    }
    return (std::uint16_t(bytes[0]) << 8) | std::uint16_t(bytes[1]);
}

inline std::uint32_t read32(const unsigned char* bytes, bool little_endian) noexcept {
    if (little_endian) {
        return std::uint32_t(bytes[0]) | (std::uint32_t(bytes[1]) << 8)
             | (std::uint32_t(bytes[2]) << 16) | (std::uint32_t(bytes[3]) << 24);
    }
    return (std::uint32_t(bytes[0]) << 24) | (std::uint32_t(bytes[1]) << 16)
         | (std::uint32_t(bytes[2]) << 8) | std::uint32_t(bytes[3]);
}

inline void validate_link_type(std::size_t type) {
    switch (type) {
        case 0:   // BSD NULL/loopback, native-endian address family
        case 1:   // Ethernet
        case 12:  // Linux DLT_RAW (classic savefiles normally use LINKTYPE_RAW=101)
        case 101: // Raw IP
        case 108: // BSD LOOP, network-endian address family
        case 113: // Linux cooked capture v1
        case 228: // Raw IPv4
        case 229: // Raw IPv6
        case 276: // Linux cooked capture v2
            return;
        default:
            throw std::runtime_error("Unsupported capture datalink type " + std::to_string(type));
    }
}

struct NormalizedPacket {
    std::span<const std::byte> bytes;
    std::size_t link_type;
};

// wire_length is deliberately left unchanged by callers: it describes the
// original captured frame, even when a cooked/loopback header is normalized.
inline NormalizedPacket normalize(std::span<const std::byte> bytes,
                                  std::size_t type,
                                  std::vector<std::byte>& storage) {
    if (type == ethernet_link_type) return {bytes, ethernet_link_type};
    if (type == 12 || type == 101 || type == 228 || type == 229) {
        return {bytes, raw_ip_link_type};
    }

    std::size_t header_length = 0;
    std::uint16_t ether_type = 0;
    if (type == 113 || type == 276) {
        header_length = type == 113 ? 16 : 20;
        if (bytes.size() < header_length) return {bytes.first(0), ethernet_link_type};
        const std::size_t protocol = type == 113 ? 14 : 0;
        ether_type = (std::to_integer<std::uint16_t>(bytes[protocol]) << 8)
                   | std::to_integer<std::uint16_t>(bytes[protocol + 1]);
    } else if (type == 0 || type == 108) {
        header_length = 4;
        if (bytes.size() < header_length) return {bytes.first(0), ethernet_link_type};
        const auto* family_bytes = reinterpret_cast<const unsigned char*>(bytes.data());
        const auto family_be = read32(family_bytes, false);
        const auto family_le = read32(family_bytes, true);
        // NULL captures may retain the original producer's byte order even in
        // a byte-swapped savefile. LOOP always uses network byte order.
        const auto family = type == 108 ? family_be
                         : family_be < family_le ? family_be : family_le;
        if (family == 2) ether_type = 0x0800;
        else if (family == 10 || family == 24 || family == 28 || family == 30) {
            ether_type = 0x86dd;
        }
    } else {
        validate_link_type(type);
    }

    storage.assign(14 + bytes.size() - header_length, std::byte{0});
    storage[12] = std::byte(ether_type >> 8);
    storage[13] = std::byte(ether_type & 0xff);
    std::copy(bytes.begin() + header_length, bytes.end(), storage.begin() + 14);
    return {storage, ethernet_link_type};
}

} // namespace intriqo::capture::detail
