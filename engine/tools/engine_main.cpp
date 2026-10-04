#include "intriqo/capture/capture.hpp"
#include "intriqo/detection/detector_registry.hpp"
#include "intriqo/detection/port_scan_detector.hpp"
#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/runtime/engine_impl.hpp"
#include "intriqo/transport/event_sink.hpp"
#include "intriqo/transport/queued_event_sink.hpp"
#include "runtime_reporting.hpp"

#include <atomic>
#include <charconv>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {
using namespace intriqo;

class OptionError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

enum class Mode { none, live, pcap, synthetic };
constexpr std::size_t maximum_event_queue_capacity = 1000000;

struct Options {
    Mode mode{Mode::none};
    std::string source;
    capture::LiveCaptureConfig live;
    capture::SyntheticCaptureConfig synthetic;
    detection::PortScanConfig detector;
    double flow_idle_timeout{60.0};
    std::size_t max_active_flows{100000};
    std::string sink{"file"};
    std::size_t event_queue_capacity{0};
    std::string output{"intriqo-events.jsonl"};
    std::string control_plane_url;
    std::string log_level{"info"};
    bool output_set{false};
    bool url_set{false};
    bool live_option_set{false};
    bool synthetic_option_set{false};
    bool help{false};
};

void usage() {
    std::cout << R"(Usage: intriqo-engine (--interface IFACE | --pcap FILE | --synthetic) [options]

Capture (exactly one mode):
  --interface IFACE                  Capture Ethernet packets from an interface
  --pcap FILE                        Replay a PCAP file through the full engine
  --synthetic                        Generate reproducible Ethernet/IPv4/TCP SYNs
  --filter EXPR                      Live capture BPF filter
  --snaplen BYTES                     Live capture limit (1..16777216; default 65535)
  --no-promiscuous                    Disable live promiscuous capture
  --capture-buffer-bytes BYTES         Kernel capture buffer request (default 16777216)
  --capture-timeout-ms MS              Buffered capture timeout (default 100; positive)
  --capture-immediate                  Disable capture batching (default buffered)
  --synthetic-packets COUNT           Positive packet count (default 10)
  --synthetic-unique-ports COUNT       Destination ports 1..COUNT (1..65535; default 10)

Detection:
  --portscan-window SECONDS           Finite positive window (default 10)
  --portscan-unique-port-threshold N   Distinct ports required (1..65535; default 10)
  --portscan-minimum-attempts N        Positive minimum attempts (default 10)
  --flow-idle-timeout SECONDS           Flow idle expiry (default 60)
  --max-active-flows N                 Active flow bound (default 100000)
  --max-tracked-sources N              Portscan source bound (default 4096)
  --max-tracked-observations N         Counted flow ID bound (default 100000)

Output:
  --sink file|http                    Event sink (default file)
  --event-queue-capacity N             Pending event bound (0..1000000; default 0)
  --output PATH                       File sink destination (default intriqo-events.jsonl)
  --control-plane-url URL             Override INTRIQO_CONTROL_PLANE_URL for HTTP
  --log-level error|info|debug         Diagnostic level (default info)
  --help                             Show this help

The built-in HTTP sink supports http:// hostname/IPv4 URLs, without TLS.
HTTP authentication uses INTRIQO_CONTROL_PLANE_TOKEN only, never CLI arguments.
INTRIQO_EVENT_QUEUE_CAPACITY defaults to 0 (synchronous delivery); positive values
enable queued delivery. --event-queue-capacity overrides the environment value.
INTRIQO_CONTROL_PLANE_ENDPOINT defaults to /api/v1/events and is appended to the
base URL. URLs and tokens are never logged. Startup/shutdown summaries are on
stdout; diagnostics are on stderr. SIGINT/SIGTERM stop capture and flush flows.
Aliases: --synthetic-packet-count and --portscan-window-seconds.
)";
}

std::size_t positive_integer(std::string_view text, std::string_view flag,
                             std::size_t maximum = std::numeric_limits<std::size_t>::max()) {
    std::size_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value == 0 || value > maximum)
        throw OptionError(std::string(flag) + " requires a positive integer in range");
    return value;
}

std::size_t non_negative_integer(std::string_view text, std::string_view flag,
                                 std::size_t maximum) {
    std::size_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value > maximum)
        throw OptionError(std::string(flag) + " requires a non-negative integer in range 0.." +
                          std::to_string(maximum));
    return value;
}

double positive_seconds(std::string_view text, std::string_view flag) {
    double value = 0.0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || !std::isfinite(value) || value <= 0.0)
        throw OptionError(std::string(flag) + " requires finite positive seconds");
    return value;
}

Options parse_options(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--help") {
            options.help = true;
            return options;
        }
    }
    auto env_value = [](const char* name) { const auto* value = std::getenv(name); return value ? std::string_view(value) : std::string_view{}; };
    auto event_queue_capacity = env_value("INTRIQO_EVENT_QUEUE_CAPACITY");
    std::string_view event_queue_capacity_source = "INTRIQO_EVENT_QUEUE_CAPACITY";
    if (const auto value = env_value("INTRIQO_FLOW_IDLE_TIMEOUT_SECONDS"); !value.empty())
        options.flow_idle_timeout = positive_seconds(value, "INTRIQO_FLOW_IDLE_TIMEOUT_SECONDS");
    if (const auto value = env_value("INTRIQO_MAX_ACTIVE_FLOWS"); !value.empty())
        options.max_active_flows = positive_integer(value, "INTRIQO_MAX_ACTIVE_FLOWS");
    if (const auto value = env_value("INTRIQO_PORTSCAN_MAX_SOURCES"); !value.empty())
        options.detector.max_tracked_sources = positive_integer(value, "INTRIQO_PORTSCAN_MAX_SOURCES");
    if (const auto value = env_value("INTRIQO_PORTSCAN_MAX_OBSERVATIONS"); !value.empty())
        options.detector.max_tracked_observations = positive_integer(value, "INTRIQO_PORTSCAN_MAX_OBSERVATIONS");
    auto select_mode = [&](Mode mode) {
        if (options.mode != Mode::none)
            throw OptionError("select exactly one of --interface, --pcap, or --synthetic");
        options.mode = mode;
    };
    for (int i = 1; i < argc; ++i) {
        const std::string_view flag(argv[i]);
        auto value = [&]() -> std::string_view {
            if (i + 1 >= argc || std::string_view(argv[i + 1]).starts_with("--"))
                throw OptionError("option requires a value (use --help for supported options)");
            const std::string_view result(argv[++i]);
            if (result.empty()) throw OptionError("option values must not be empty");
            return result;
        };
        if (flag == "--interface") {
            select_mode(Mode::live);
            options.source = value();
            options.live.interface_name = options.source;
        } else if (flag == "--pcap") {
            select_mode(Mode::pcap);
            options.source = value();
        } else if (flag == "--synthetic") {
            select_mode(Mode::synthetic);
        } else if (flag == "--filter") {
            options.live.bpf_filter = value();
            options.live_option_set = true;
        } else if (flag == "--snaplen") {
            options.live.snaplen = static_cast<int>(positive_integer(value(), flag,
                16777216));
            options.live_option_set = true;
        } else if (flag == "--no-promiscuous") {
            options.live.promiscuous = false;
            options.live_option_set = true;
        } else if (flag == "--capture-buffer-bytes") {
            options.live.buffer_size = static_cast<int>(positive_integer(value(), flag,
                static_cast<std::size_t>(std::numeric_limits<int>::max())));
            options.live_option_set = true;
        } else if (flag == "--capture-timeout-ms") {
            options.live.timeout = std::chrono::milliseconds(positive_integer(value(), flag, 60000));
            options.live_option_set = true;
        } else if (flag == "--capture-immediate") {
            options.live.immediate = true;
            options.live_option_set = true;
        } else if (flag == "--flow-idle-timeout") {
            options.flow_idle_timeout = positive_seconds(value(), flag);
        } else if (flag == "--max-active-flows") {
            options.max_active_flows = positive_integer(value(), flag);
        } else if (flag == "--max-tracked-sources") {
            options.detector.max_tracked_sources = positive_integer(value(), flag);
        } else if (flag == "--max-tracked-observations") {
            options.detector.max_tracked_observations = positive_integer(value(), flag);
        } else if (flag == "--synthetic-packets" || flag == "--synthetic-packet-count") {
            options.synthetic.packet_count = positive_integer(value(), flag);
            options.synthetic_option_set = true;
        } else if (flag == "--synthetic-unique-ports") {
            options.synthetic.unique_ports = positive_integer(value(), flag, 65535);
            options.synthetic_option_set = true;
        } else if (flag == "--portscan-window" || flag == "--portscan-window-seconds") {
            options.detector.window_seconds = positive_seconds(value(), flag);
        } else if (flag == "--portscan-unique-port-threshold") {
            options.detector.unique_port_threshold = positive_integer(value(), flag, 65535);
        } else if (flag == "--portscan-minimum-attempts") {
            options.detector.minimum_attempts = positive_integer(value(), flag);
        } else if (flag == "--sink") {
            options.sink = value();
            if (options.sink != "file" && options.sink != "http")
                throw OptionError("--sink must be file or http");
        } else if (flag == "--event-queue-capacity") {
            event_queue_capacity = value();
            event_queue_capacity_source = flag;
        } else if (flag == "--output") {
            options.output = value();
            options.output_set = true;
        } else if (flag == "--control-plane-url") {
            options.control_plane_url = value();
            options.url_set = true;
        } else if (flag == "--log-level") {
            options.log_level = value();
            if (options.log_level != "error" && options.log_level != "info" && options.log_level != "debug")
                throw OptionError("--log-level must be error, info, or debug");
        } else {
            // Do not echo unknown arguments: they may be accidentally supplied credentials.
            throw OptionError("unknown option (use --help for supported options)");
        }
    }
    if (!event_queue_capacity.empty())
        options.event_queue_capacity = non_negative_integer(event_queue_capacity,
            event_queue_capacity_source, maximum_event_queue_capacity);
    if (options.mode == Mode::none)
        throw OptionError("select exactly one of --interface, --pcap, or --synthetic");
    if (options.live_option_set && options.mode != Mode::live)
        throw OptionError("live capture options require --interface");
    if (options.synthetic_option_set && options.mode != Mode::synthetic)
        throw OptionError("synthetic options require --synthetic");
    if (options.output_set && options.sink != "file")
        throw OptionError("--output requires --sink file");
    if (options.url_set && options.sink != "http")
        throw OptionError("--control-plane-url requires --sink http");
    return options;
}

const char* mode_name(Mode mode) {
    switch (mode) {
    case Mode::live: return "live";
    case Mode::pcap: return "pcap";
    case Mode::synthetic: return "synthetic";
    default: return "none";
    }
}

std::string safe_label(std::string_view text) {
    // Source/file labels can themselves look like URLs; omit those entirely.
    if (text.find("://") != std::string_view::npos) return "<redacted-url>";
    std::string result;
    for (const char c : text.substr(0, 240)) {
        const auto byte = static_cast<unsigned char>(c);
        result += byte >= 32 && byte <= 126 ? c : '?';
    }
    if (text.size() > 240) result += "...";
    return result;
}

std::string environment(const char* name) {
    const char* value = std::getenv(name);
    return value ? value : "";
}

std::string event_url(const Options& options) {
    std::string base = options.url_set ? options.control_plane_url : environment("INTRIQO_CONTROL_PLANE_URL");
    if (base.empty())
        throw OptionError("HTTP sink requires --control-plane-url or INTRIQO_CONTROL_PLANE_URL");
    // The current built-in HTTP sink implements plain HTTP, not TLS.
    if (!base.starts_with("http://"))
        throw OptionError("the built-in HTTP sink requires an http URL (TLS is not supported)");
    const auto authority_begin = std::size_t{7};
    const auto authority_end = base.find_first_of("/?#", authority_begin);
    const auto authority = base.substr(authority_begin, authority_end - authority_begin);
    if (authority.empty() || authority.find('@') != std::string::npos ||
        base.find_first_of("\r\n\t ") != std::string::npos || base.find_first_of("?#") != std::string::npos)
        throw OptionError("control-plane URL requires a host and must not contain credentials, whitespace, query, or fragment");
    const auto port_separator = authority.find(':');
    if (port_separator != std::string::npos) {
        if (port_separator == 0 || authority.find(':', port_separator + 1) != std::string::npos)
            throw OptionError("the built-in HTTP sink requires a hostname or IPv4 host with an optional port");
        positive_integer(std::string_view(authority).substr(port_separator + 1), "control-plane URL port", 65535);
    }
    std::string endpoint = environment("INTRIQO_CONTROL_PLANE_ENDPOINT");
    if (endpoint.empty()) endpoint = "/api/v1/events";
    if (!endpoint.starts_with('/') || endpoint.starts_with("//") ||
        endpoint.find_first_of("\r\n\t ") != std::string::npos || endpoint.find('#') != std::string::npos)
        throw OptionError("INTRIQO_CONTROL_PLANE_ENDPOINT must be an absolute HTTP path");
    while (base.ends_with('/')) base.pop_back();
    return base + endpoint;
}

// Lock-free atomics are signal-safe and also avoid a cross-thread data race
// when the kernel delivers a signal to a thread other than the watcher.
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

void startup(const Options& options, const std::vector<std::string>& names) {
    std::cout << "startup status=starting mode=" << mode_name(options.mode)
              << " source=" << std::quoted(safe_label(options.mode == Mode::synthetic ? "generated-tcp-syn" : options.source))
              << " detectors=";
    for (std::size_t i = 0; i < names.size(); ++i) {
        if (i) std::cout << ',';
        std::cout << safe_label(names[i]);
    }
    std::cout << " sink=" << options.sink
              << " event_queue_capacity=" << options.event_queue_capacity
              << " delivery_mode=" << (options.event_queue_capacity == 0 ? "synchronous" : "queued");
    if (options.sink == "file") std::cout << " output=" << std::quoted(safe_label(options.output));
    else std::cout << " destination=<configured>";
    std::cout << " log_level=" << options.log_level
              << " portscan_window_seconds=" << options.detector.window_seconds
              << " portscan_unique_port_threshold=" << options.detector.unique_port_threshold
              << " portscan_minimum_attempts=" << options.detector.minimum_attempts
              << " flow_idle_timeout_seconds=" << options.flow_idle_timeout
              << " max_active_flows=" << options.max_active_flows
              << " max_tracked_sources=" << options.detector.max_tracked_sources
              << " max_tracked_observations=" << options.detector.max_tracked_observations;
    if (options.mode == Mode::live)
        std::cout << " snaplen=" << options.live.snaplen
                  << " capture_buffer_bytes=" << options.live.buffer_size
                  << " capture_timeout_ms=" << options.live.timeout.count()
                  << " capture_immediate=" << (options.live.immediate ? "true" : "false")
                  << " promiscuous=" << (options.live.promiscuous ? "true" : "false")
                  << " filter=" << (options.live.bpf_filter.empty() ? "disabled" : "enabled");
    if (options.mode == Mode::synthetic)
        std::cout << " synthetic_packets=" << options.synthetic.packet_count
                  << " synthetic_unique_ports=" << options.synthetic.unique_ports;
    std::cout << '\n' << std::flush;
}

void shutdown(const metrics::EngineMetrics& metrics, bool failed) {
    std::cout << "shutdown status=" << (failed ? "error" : stop_requested.load(std::memory_order_relaxed) ? "interrupted" : "complete")
              << " packets_received=" << metrics.packets_received
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
              << " sink_failures=" << metrics.sink_failures
              << " runtime_seconds=" << metrics.runtime_seconds;
    tools::detailed_counters(std::cout, metrics);
    std::cout << '\n';
}

int run(const Options& options) {
    std::unique_ptr<capture::CaptureSource> capture;
    if (options.mode == Mode::live) capture = std::make_unique<capture::LiveCaptureSource>(options.live);
    else if (options.mode == Mode::pcap)
        capture = std::make_unique<capture::PcapReplaySource>(capture::PcapReplayConfig{options.source, false});
    else capture = std::make_unique<capture::SyntheticCaptureSource>(options.synthetic);

    auto registry = std::make_unique<detection::DetectorRegistry>();
    registry->add(std::make_unique<detection::PortScanDetector>(options.detector));
    const auto names = registry->names();
    auto pipeline = std::make_unique<pipeline::PipelineImpl>(std::move(registry), Duration{options.flow_idle_timeout}, options.max_active_flows);
    std::unique_ptr<transport::SecurityEventSink> sink;
    if (options.sink == "file") sink = std::make_unique<transport::FileEventSink>(options.output);
    else sink = std::make_unique<transport::HttpEventSink>(transport::HttpEventSink::Config{
        event_url(options), 3, environment("INTRIQO_CONTROL_PLANE_TOKEN")});
    if (options.event_queue_capacity != 0)
        sink = std::make_unique<transport::QueuedEventSink>(std::move(sink), options.event_queue_capacity);

    runtime::EngineImpl engine(std::move(capture), std::move(pipeline), std::move(sink));
    engine.on_started([] { std::cout << "startup status=running capture_ready=true\n" << std::flush; });
    SignalStopper signals(engine);
    startup(options, names);
    if (options.log_level == "debug")
        std::cerr << "debug: full capture/parser/pipeline/detector/sink runtime; signal watcher polling every 20 ms\n";
    bool failed = false;
    try {
        signals.before_run();
        engine.run();
    } catch (const std::exception& error) {
        engine.stop();
        failed = true;
        std::string message = error.what();
        const auto token = environment("INTRIQO_CONTROL_PLANE_TOKEN");
        if (!token.empty()) {
            for (auto at = message.find(token); at != std::string::npos; at = message.find(token, at + 10))
                message.replace(at, token.size(), "<redacted>");
        }
        message = std::regex_replace(message, std::regex(R"(https?://[^\s'\"]+)"), "<redacted-url>");
        std::cerr << "error: " << safe_label(message) << '\n';
    } catch (...) {
        engine.stop();
        failed = true;
        std::cerr << "error: unknown capture or engine runtime failure\n";
    }
    const auto metrics = engine.metrics();
    if (metrics.sink_failures != 0) {
        failed = true;
        std::cerr << "error: one or more security events could not be delivered\n";
    }
    shutdown(metrics, failed);
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
        std::cerr << "error: engine initialization failed\n";
        return 1;
    }
}
