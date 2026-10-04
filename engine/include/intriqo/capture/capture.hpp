#pragma once

#include "intriqo/packet/packet.hpp"
#include <functional>
#include <string>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace intriqo::capture {

/// Callback type for received packets.
using PacketCallback = std::function<void(packet::PacketView)>;

struct CaptureStatistics {
    // Live sources report libpcap/kernel counters; finite sources count input
    // packets delivered to the callback. A parser rejection is still received.
    std::uint64_t packets_received{0};
    std::uint64_t packets_dropped{0};
    std::uint64_t interface_dropped{0};
    std::uint64_t packets_captured{0}; ///< Actual packet callback invocations
    std::uint64_t errors{0};           ///< Capture/setup/statistics errors, not callback errors
    bool statistics_available{false}; ///< Kernel counters available (or finite input counted)
};

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

    /// Optional notification after source initialization succeeds, before packets.
    virtual void set_ready_callback(std::function<void()>) {}

    /// Optional live-idle maintenance notification. Offline replay does not use
    /// wall-clock time to expire historical input.
    virtual void set_idle_callback(std::function<void(TimePoint)>) {}

    /// Start capture (blocking until stop() is called or EOF for PCAP).
    virtual void start() = 0;

    /// Signal capture to stop after the current packet.
    virtual void stop() noexcept = 0;

    /// Human-readable description of the capture source (interface name, file path).
    [[nodiscard]] virtual std::string description() const = 0;

    /// Thread-safe snapshot; sources without counters may use this default.
    [[nodiscard]] virtual CaptureStatistics statistics() const noexcept { return {}; }
};

/// Configuration for live interface capture.
struct LiveCaptureConfig {
    std::string interface_name;              ///< e.g. "eth0"
    int         snaplen{65535};              ///< Max bytes captured per packet
    bool        promiscuous{true};
    std::chrono::milliseconds timeout{100};  ///< Packet buffer timeout
    std::string bpf_filter;                  ///< Optional BPF filter expression
    int         buffer_size{16 * 1024 * 1024}; ///< Kernel capture buffer request, bytes
    bool        immediate{false};            ///< Disable packet-buffer batching when requested
};

/// Configuration for PCAP file replay.
struct PcapReplayConfig {
    std::string file_path;
    bool        realtime{false};    ///< Honour inter-packet timestamps
};

class PcapReplaySource final : public CaptureSource {
public:
    explicit PcapReplaySource(PcapReplayConfig config);
    ~PcapReplaySource() override;
    void set_callback(PacketCallback cb) override;
    void set_ready_callback(std::function<void()> cb) override;
    void start() override;
    void stop() noexcept override;
    [[nodiscard]] std::string description() const override;
    [[nodiscard]] CaptureStatistics statistics() const noexcept override;
private:
    struct State;
    PcapReplayConfig config_;
    std::unique_ptr<State> state_;
};

struct SyntheticCaptureConfig {
    std::size_t packet_count{10};
    std::size_t unique_ports{10}; ///< Distinct destination ports, in [1, 65535]
};

/// Finite, deterministic Ethernet/IPv4/TCP SYN input for processing and benchmarks.
class SyntheticCaptureSource final : public CaptureSource {
public:
    explicit SyntheticCaptureSource(SyntheticCaptureConfig config = {});
    ~SyntheticCaptureSource() override;
    void set_callback(PacketCallback cb) override;
    void set_ready_callback(std::function<void()> cb) override;
    void start() override;
    void stop() noexcept override;
    [[nodiscard]] std::string description() const override;
    [[nodiscard]] CaptureStatistics statistics() const noexcept override;
private:
    struct State;
    SyntheticCaptureConfig config_;
    std::unique_ptr<State> state_;
};

/// Passive Linux interface capture. start() throws if built without libpcap.
class LiveCaptureSource final : public CaptureSource {
public:
    explicit LiveCaptureSource(LiveCaptureConfig config);
    ~LiveCaptureSource() override;
    void set_callback(PacketCallback cb) override;
    void set_ready_callback(std::function<void()> cb) override;
    void set_idle_callback(std::function<void(TimePoint)> cb) override;
    void start() override;
    void stop() noexcept override;
    [[nodiscard]] std::string description() const override;
    [[nodiscard]] CaptureStatistics statistics() const noexcept override;
private:
    struct State;
    LiveCaptureConfig config_;
    std::unique_ptr<State> state_;
};

// Concrete sources are single-use: a second start(), or changing the callback
// after start(), throws std::logic_error. stop() is thread-safe and remains
// effective when called before start(). The source must outlive its start() call.
// Callbacks run without internal locks and their exceptions propagate to start().

} // namespace intriqo::capture
