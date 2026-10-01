#pragma once

#include "intriqo/packet/packet.hpp"
#include <functional>
#include <string>
#include <chrono>

namespace intriqo::capture {

/// Callback type for received packets.
using PacketCallback = std::function<void(packet::PacketView)>;

/// Abstract capture source (live interface or PCAP replay).
///
/// The capture layer is deliberately thin — it converts raw bytes from
/// whatever source into PacketView objects and forwards them upstream.
/// It does NOT parse, track flows, or perform detection.
class CaptureSource {
public:
    virtual ~CaptureSource() = default;

    /// Register the callback invoked for every captured packet.
    virtual void set_callback(PacketCallback cb) = 0;

    /// Start capture (blocking until stop() is called or EOF for PCAP).
    virtual void start() = 0;

    /// Signal capture to stop after the current packet.
    virtual void stop() noexcept = 0;

    /// Human-readable description of the capture source (interface name, file path).
    [[nodiscard]] virtual std::string description() const = 0;
};

/// Configuration for live interface capture.
struct LiveCaptureConfig {
    std::string interface_name;              ///< e.g. "eth0"
    int         snaplen{65535};              ///< Max bytes captured per packet
    bool        promiscuous{true};
    std::chrono::milliseconds timeout{100};  ///< Packet buffer timeout
    std::string bpf_filter;                  ///< Optional BPF filter expression
};

/// Configuration for PCAP file replay.
struct PcapReplayConfig {
    std::string file_path;
    bool        realtime{false};    ///< Honour inter-packet timestamps
};

} // namespace intriqo::capture
