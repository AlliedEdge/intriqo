#include "intriqo/capture/capture.hpp"
#include "intriqo/detection/detector_registry.hpp"
#include "intriqo/detection/port_scan_detector.hpp"
#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/runtime/engine_impl.hpp"
#include "intriqo/transport/event_sink.hpp"

#include <atomic>
#include <charconv>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <iomanip>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <sys/resource.h>

namespace {
using namespace intriqo;

class OptionError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct Options {
    bool help{false};
    bool synthetic{false};
    bool pcap{false};
    bool live{false};
    capture::LiveCaptureConfig live_config;
    double duration_seconds{3.0};
    bool synthetic_option_set{false};
    std::string pcap_path;
    capture::SyntheticCaptureConfig input{100000, 1000};
    detection::PortScanConfig detector;
};

void usage() {
    std::cout << R"(Usage: intriqo-runtime-benchmark (--synthetic | --pcap FILE | --interface IFACE) [options]

  --synthetic                        Generate Ethernet/IPv4/TCP SYN packets
  --pcap FILE                        Replay raw PCAP packets (not parsed fixtures)
  --interface IFACE                  Passive live capture (requires Linux/libpcap)
  --filter EXPR                      Live BPF filter
  --duration-seconds SECONDS          Bounded live measurement (default 3; max 3600)
  --synthetic-packets COUNT           Positive packet count (default 100000)
  --synthetic-unique-ports COUNT       Ports 1..COUNT (1..65535; default 1000)
  --portscan-window SECONDS           Finite positive detection window (default 10)
  --portscan-unique-port-threshold N   Distinct ports required (1..65535; default 10)
  --portscan-minimum-attempts N        Positive minimum attempts (default 10)
  --help                             Show this help

Measures CaptureSource -> Engine parser -> Pipeline -> DetectorRegistry -> real
PortScanDetector -> FileEventSink(/dev/null), including JSON serialization and
file transport. Events are actually generated and submitted, never pre-counted.
Latency is capture-to-Engine-observer, not isolated transport latency; it includes
work before the runtime invokes the observer. PCAP latency is N/A because replay
timestamps can be historical. SIGINT/SIGTERM flush and report.
Aliases: --synthetic-packet-count and --portscan-window-seconds.
)";
}

std::size_t positive_integer(std::string_view text, std::string_view flag,
                             std::size_t maximum = std::numeric_limits<std::size_t>::max()) {
    std::size_t result = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), result);
    if (error != std::errc{} || end != text.data() + text.size() || result == 0 || result > maximum)
        throw OptionError(std::string(flag) + " requires a positive integer in range");
    return result;
}

double positive_seconds(std::string_view text, std::string_view flag) {
    double result = 0.0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), result);
    if (error != std::errc{} || end != text.data() + text.size() || !std::isfinite(result) || result <= 0.0)
        throw OptionError(std::string(flag) + " requires finite positive seconds");
    return result;
}

Options parse_options(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--help") {
            options.help = true;
            return options;
        }
    }
    bool mode_set = false;
    for (int i = 1; i < argc; ++i) {
        const std::string_view flag(argv[i]);
        auto value = [&]() -> std::string_view {
            if (i + 1 >= argc || std::string_view(argv[i + 1]).starts_with("--"))
                throw OptionError("option requires a value (use --help for supported options)");
            const std::string_view result(argv[++i]);
            if (result.empty()) throw OptionError("option values must not be empty");
            return result;
        };
        if (flag == "--synthetic" || flag == "--pcap" || flag == "--interface") {
            if (mode_set) throw OptionError("select exactly one capture mode");
            mode_set = true;
            options.synthetic = flag == "--synthetic";
            options.pcap = flag == "--pcap";
            options.live = flag == "--interface";
            if (options.pcap) options.pcap_path = value();
            if (options.live) { options.live_config.interface_name = value(); options.live_config.promiscuous = false; }
        } else if (flag == "--filter") {
            options.live_config.bpf_filter = value();
        } else if (flag == "--duration-seconds") {
            options.duration_seconds = positive_seconds(value(), flag);
            if (options.duration_seconds > 3600) throw OptionError("live duration must not exceed 3600 seconds");
        } else if (flag == "--synthetic-packets" || flag == "--synthetic-packet-count") {
            options.input.packet_count = positive_integer(value(), flag);
            options.synthetic_option_set = true;
        } else if (flag == "--synthetic-unique-ports") {
            options.input.unique_ports = positive_integer(value(), flag, 65535);
            options.synthetic_option_set = true;
        } else if (flag == "--portscan-window" || flag == "--portscan-window-seconds") {
            options.detector.window_seconds = positive_seconds(value(), flag);
        } else if (flag == "--portscan-unique-port-threshold") {
            options.detector.unique_port_threshold = positive_integer(value(), flag, 65535);
        } else if (flag == "--portscan-minimum-attempts") {
            options.detector.minimum_attempts = positive_integer(value(), flag);
        } else {
            throw OptionError("unknown option (use --help for supported options)");
        }
    }
    if (!mode_set) throw OptionError("select exactly one capture mode");
    if (!options.live && !options.live_config.bpf_filter.empty()) throw OptionError("--filter requires --interface");
    if (options.synthetic_option_set && !options.synthetic)
        throw OptionError("synthetic options require --synthetic");
    return options;
}

std::string safe_label(std::string_view text) {
    if (text.find("://") != std::string_view::npos) return "<redacted-url>";
    std::string result;
    for (const char c : text.substr(0, 240)) {
        const auto byte = static_cast<unsigned char>(c);
        result += byte >= 32 && byte <= 126 ? c : '?';
    }
    if (text.size() > 240) result += "...";
    return result;
}

// The handler only stores a lock-free flag; stop() runs on the watcher thread.
static_assert(std::atomic<bool>::is_always_lock_free);
std::atomic<bool> stop_requested{false};
extern "C" void request_stop(int) { stop_requested.store(true, std::memory_order_relaxed); }

class SignalStopper {
public:
    explicit SignalStopper(runtime::EngineImpl& engine) : engine_(engine) {
        stop_requested.store(false, std::memory_order_relaxed);
        struct sigaction action{};
        action.sa_handler = request_stop;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, &old_int_) != 0)
            throw std::runtime_error("could not install SIGINT handler");
        if (sigaction(SIGTERM, &action, &old_term_) != 0) {
            sigaction(SIGINT, &old_int_, nullptr);
            throw std::runtime_error("could not install SIGTERM handler");
        }
        try {
            watcher_ = std::thread([this] {
                std::unique_lock lock(mutex_);
                while (!finished_) {
                    if (stop_requested.load(std::memory_order_relaxed)) {
                        lock.unlock();
                        engine_.stop();
                        return;
                    }
                    wake_.wait_for(lock, std::chrono::milliseconds{20}, [this] { return finished_; });
                }
            });
        } catch (...) {
            restore_handlers();
            throw;
        }
    }
    ~SignalStopper() {
        {
            std::lock_guard lock(mutex_);
            finished_ = true;
        }
        wake_.notify_one();
        if (watcher_.joinable()) watcher_.join();
        restore_handlers();
    }
    SignalStopper(const SignalStopper&) = delete;
    SignalStopper& operator=(const SignalStopper&) = delete;
    void before_run() {
        if (stop_requested.load(std::memory_order_relaxed)) engine_.stop();
    }
private:
    void restore_handlers() noexcept {
        sigaction(SIGINT, &old_int_, nullptr);
        sigaction(SIGTERM, &old_term_, nullptr);
    }
    runtime::EngineImpl& engine_;
    struct sigaction old_int_{};
    struct sigaction old_term_{};
    std::mutex mutex_;
    std::condition_variable wake_;
    bool finished_{false};
    std::thread watcher_;
};

struct Latency {
    std::uint64_t samples{0};
    std::uint64_t unavailable{0};
    double total_seconds{0.0};
    double minimum_seconds{std::numeric_limits<double>::infinity()};
    double maximum_seconds{0.0};

    void observe(const events::SecurityEvent& event, bool synthetic) {
        const auto now = Clock::now();
        // Offline replay has no meaningful wall-clock capture latency. Reject
        // zero/future timestamps and clock discontinuities for synthetic data.
        const double elapsed = Duration(now - event.timestamp).count();
        if (!synthetic || event.timestamp == TimePoint{} || !std::isfinite(elapsed) ||
            elapsed < 0.0 || elapsed > 60.0) {
            ++unavailable;
            return;
        }
        ++samples;
        total_seconds += elapsed;
        if (elapsed < minimum_seconds) minimum_seconds = elapsed;
        if (elapsed > maximum_seconds) maximum_seconds = elapsed;
    }
};

double cpu_seconds(const timeval& time) {
    return static_cast<double>(time.tv_sec) + static_cast<double>(time.tv_usec) / 1000000.0;
}

double per_second(std::uint64_t count, double elapsed) {
    return elapsed > 0.0 ? static_cast<double>(count) / elapsed : 0.0;
}

long resident_rss_kib() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.starts_with("VmRSS:")) {
            const auto start = line.find_first_of("0123456789");
            long value = 0;
            if (start != std::string::npos) {
                const auto result = std::from_chars(line.data()+start, line.data()+line.size(), value);
                if (result.ec == std::errc{}) return value;
            }
        }
    }
    return -1;
}

void report(const Options& options, const metrics::EngineMetrics& metrics, double wall_seconds,
            const rusage& before, const rusage& after, bool have_usage, const Latency& latency, bool failed) {
    std::cout << std::fixed << std::setprecision(6)
              << "benchmark mode=" << (options.synthetic ? "synthetic" : options.live ? "live" : "pcap")
              << " source=" << std::quoted(safe_label(options.synthetic ? "generated-tcp-syn" : options.live ? options.live_config.interface_name : options.pcap_path))
              << " status=" << (failed ? "error" : stop_requested.load(std::memory_order_relaxed) ? "interrupted" : "complete")
              << " detector=port_scan registry=enabled sink=file output=/dev/null transport=included"
              << " portscan_window_seconds=" << options.detector.window_seconds
              << " portscan_unique_port_threshold=" << options.detector.unique_port_threshold
              << " portscan_minimum_attempts=" << options.detector.minimum_attempts;
    if (options.synthetic)
        std::cout << " input_packet_count=" << options.input.packet_count
                  << " input_unique_ports=" << options.input.unique_ports;
    if (options.live) std::cout << " duration_seconds=" << options.duration_seconds;
    std::cout << '\n'
              << "counts packets_received=" << metrics.packets_received
              << " packets_parsed=" << metrics.packets_parsed
              << " packets_malformed=" << metrics.packets_malformed
              << " packets_rejected=" << metrics.packets_rejected
              << " packets_dropped=" << metrics.packets_dropped
              << " flows_created=" << metrics.flows_created
              << " flows_expired=" << metrics.flows_expired
              << " flows_flushed=" << metrics.flows_flushed
              << " flows_active=" << metrics.flows_active
              << " detections_fired=" << metrics.detections_fired
              << " events_emitted=" << metrics.events_emitted
              << " sink_failures=" << metrics.sink_failures << '\n'
              << "rates wall_seconds=" << wall_seconds
              << " engine_runtime_seconds=" << metrics.runtime_seconds
              << " packets_per_second=" << per_second(metrics.packets_received, wall_seconds)
              << " flows_per_second=" << per_second(metrics.flows_created, wall_seconds)
              << " events_per_second=" << per_second(metrics.events_emitted, wall_seconds)
              << " parsed_packets_per_second=" << per_second(metrics.packets_parsed, wall_seconds)
              << " parse_rate=" << (metrics.packets_received == 0 ? 0.0 :
                   static_cast<double>(metrics.packets_parsed) / static_cast<double>(metrics.packets_received)) << '\n';
    if (have_usage)
        std::cout << "resources cpu_user_seconds=" << cpu_seconds(after.ru_utime) - cpu_seconds(before.ru_utime)
                   << " cpu_system_seconds=" << cpu_seconds(after.ru_stime) - cpu_seconds(before.ru_stime)
                   << " cpu_utilization_percent=" << 100.0 *
                       ((cpu_seconds(after.ru_utime) - cpu_seconds(before.ru_utime)) +
                        (cpu_seconds(after.ru_stime) - cpu_seconds(before.ru_stime))) / wall_seconds
                   << " max_rss_kib=" << after.ru_maxrss << " max_rss_scope=process-high-water"
                   << " resident_rss_kib=" << resident_rss_kib() << " resident_rss_scope=post-flush-snapshot\n";
    else std::cout << "resources cpu_user_seconds=N/A cpu_system_seconds=N/A max_rss_kib=N/A\n";
    std::cout << "latency scope=capture-to-engine-observer transport_latency=not-isolated samples=" << latency.samples
              << " unavailable=" << latency.unavailable;
    if (latency.samples != 0)
        std::cout << " mean_ms=" << latency.total_seconds * 1000.0 / static_cast<double>(latency.samples)
                  << " min_ms=" << latency.minimum_seconds * 1000.0
                  << " max_ms=" << latency.maximum_seconds * 1000.0;
    else std::cout << " mean_ms=N/A min_ms=N/A max_ms=N/A reason="
                   << (options.pcap ? "offline-replay-timestamps" : "no-valid-event-timestamps");
    std::cout << '\n';
}

int run(const Options& options) {
    std::unique_ptr<capture::CaptureSource> capture;
    if (options.live) capture = std::make_unique<capture::LiveCaptureSource>(options.live_config);
    else if (options.synthetic) capture = std::make_unique<capture::SyntheticCaptureSource>(options.input);
    else capture = std::make_unique<capture::PcapReplaySource>(capture::PcapReplayConfig{options.pcap_path, false});
    auto registry = std::make_unique<detection::DetectorRegistry>();
    registry->add(std::make_unique<detection::PortScanDetector>(options.detector));
    auto pipeline = std::make_unique<pipeline::PipelineImpl>(std::move(registry), Duration{60.0});
    auto sink = std::make_unique<transport::FileEventSink>("/dev/null");
    runtime::EngineImpl engine(std::move(capture), std::move(pipeline), std::move(sink));
    Latency latency;
    engine.on_event([&](events::SecurityEvent event) { latency.observe(event, options.synthetic || options.live); });
    engine.on_started([] { std::cout << "capture_ready=true\n" << std::flush; });
    SignalStopper signals(engine);
    std::mutex duration_mutex;
    std::condition_variable_any duration_wake;
    std::jthread duration_stop;
    if (options.live) duration_stop = std::jthread([&](std::stop_token stop) {
        std::unique_lock lock(duration_mutex);
        duration_wake.wait_for(lock, stop, std::chrono::duration<double>(options.duration_seconds), [] { return false; });
        if (!stop.stop_requested()) engine.stop();
    });
    rusage before{};
    rusage after{};
    const bool have_before = getrusage(RUSAGE_SELF, &before) == 0;
    const auto start = std::chrono::steady_clock::now();
    bool failed = false;
    try {
        signals.before_run();
        engine.run();
    } catch (...) {
        engine.stop();
        failed = true;
        std::cerr << "error: benchmark capture or engine runtime failed\n";
    }
    const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    const bool have_after = getrusage(RUSAGE_SELF, &after) == 0;
    const auto metrics = engine.metrics();
    failed = failed || metrics.sink_failures != 0;
    report(options, metrics, elapsed, before, after, have_before && have_after, latency, failed);
    return failed ? 1 : 0;
}
} // namespace

int main(int argc, char** argv) {
    try {
        const auto options = parse_options(argc, argv);
        if (options.help) {
            usage();
            return 0;
        }
        return run(options);
    } catch (const OptionError& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 2;
    } catch (...) {
        std::cerr << "error: benchmark initialization failed\n";
        return 1;
    }
}
