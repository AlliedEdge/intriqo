#include "intriqo/capture/capture.hpp"
#include "intriqo/detection/detector_registry.hpp"
#include "intriqo/detection/port_scan_detector.hpp"
#include "intriqo/pipeline/pipeline_impl.hpp"
#include "intriqo/runtime/engine_impl.hpp"
#include "intriqo/transport/event_sink.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <csignal>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/resource.h>
#include <thread>
#include <unistd.h>

// Ordinary, checksummed fixture bytes only. This tool never injects packets or
// opens a network socket. The only retained packets/events are two correctness
// events; long-run samples are written as JSONL immediately.
namespace {
using namespace intriqo;
using Steady = std::chrono::steady_clock;
static_assert(std::atomic<bool>::is_always_lock_free);
std::atomic<bool> interrupted{false};
extern "C" void request_stop(int) { interrupted.store(true, std::memory_order_relaxed); }

struct Options {
    double duration{3.0};
    double rate{10000.0}; // 0 means unpaced
    double idle_timeout{60.0};
    double window{10.0};
    std::size_t max_flows{100000};
    std::size_t max_sources{4096};
    std::size_t max_observations{100000};
    std::size_t sources{0}; // auto: twice source capacity plus one
    std::size_t ports{4096};
    std::size_t sample_ms{1000};
    std::string output;
    bool correctness_only{false};
    bool help{false};
};

void usage() {
    std::cout << R"(Usage: intriqo-state-soak [options]
  --duration-seconds SECONDS      Finite wall duration, >0..3600 (default 3)
  --rate PPS                      Target offered fixture rate; 0 = unpaced (10000)
  --max-active-flows COUNT         Flow capacity (100000)
  --max-tracked-sources COUNT      Detector source capacity (4096)
  --max-tracked-observations COUNT Detector observation capacity (100000)
  --flow-idle-timeout SECONDS      Positive logical idle timeout (60)
  --portscan-window SECONDS        Positive logical detection window (10)
  --sources COUNT                 Varied fixture sources (default 2*capacity+1)
  --ports COUNT                   Varied destination ports, 10..65535 (4096)
  --sample-interval-ms MS          Streaming sample interval, 20..60000 (1000)
  --output FILE                   Exclusive new JSONL file (default stdout)
  --correctness-only              Run just the bounded two-window scan check
  --help

Exercises raw Ethernet/IPv4/TCP -> Engine parser -> Pipeline -> Registry -> real
PortScanDetector -> FileEventSink. Every four packets repeat one flow. Sources,
ports and source ports churn deterministically; logical time jumps between
capacity-sized epochs to exercise expiry even in a short CI run. Logical fixture
time is separate from measured steady-clock duration; packet latency is N/A.
RSS/CPU/metrics samples stream to JSONL. Peaks include exact state high-water
counters and sampled RSS; sampled RSS is not evidence of a long-run plateau.
Duration supports short CI runs and 300/1800/3600 seconds. SIGINT/SIGTERM reports
a partial result. No packet storage, network injection, or retained sample array.
)";
}

std::size_t integer(std::string_view text, std::string_view flag,
                    std::size_t maximum = 10000000) {
    std::size_t result{};
    const auto [end, error] = std::from_chars(text.data(), text.data()+text.size(), result);
    if (error != std::errc{} || end != text.data()+text.size() || result == 0 || result > maximum)
        throw std::invalid_argument(std::string(flag)+" requires a positive integer in range");
    return result;
}

double number(std::string_view text, std::string_view flag, bool allow_zero = false) {
    double result{};
    const auto [end, error] = std::from_chars(text.data(), text.data()+text.size(), result);
    if (error != std::errc{} || end != text.data()+text.size() || !std::isfinite(result) ||
        result < 0 || (!allow_zero && result == 0) || result > 1000000000.0)
        throw std::invalid_argument(std::string(flag)+" requires finite nonnegative/positive seconds or rate");
    return result;
}

Options parse_options(int argc, char** argv) {
    Options o;
    for (int i=1; i<argc; ++i) {
        const std::string_view flag(argv[i]);
        auto value = [&]() -> std::string_view {
            if (++i >= argc || std::string_view(argv[i]).starts_with("--"))
                throw std::invalid_argument(std::string(flag)+" requires a value");
            return argv[i];
        };
        if (flag == "--help") o.help = true;
        else if (flag == "--correctness-only") o.correctness_only = true;
        else if (flag == "--duration-seconds") o.duration = number(value(), flag);
        else if (flag == "--rate") o.rate = number(value(), flag, true);
        else if (flag == "--flow-idle-timeout") o.idle_timeout = number(value(), flag);
        else if (flag == "--portscan-window") o.window = number(value(), flag);
        else if (flag == "--max-active-flows") o.max_flows = integer(value(), flag);
        else if (flag == "--max-tracked-sources") o.max_sources = integer(value(), flag, 8388607);
        else if (flag == "--max-tracked-observations") o.max_observations = integer(value(), flag);
        else if (flag == "--sources") o.sources = integer(value(), flag, 16777215);
        else if (flag == "--ports") o.ports = integer(value(), flag, 65535);
        else if (flag == "--sample-interval-ms") o.sample_ms = integer(value(), flag, 60000);
        else if (flag == "--output") o.output = value();
        else throw std::invalid_argument("unknown option: "+std::string(flag));
    }
    if (o.duration > 3600) throw std::invalid_argument("duration must be <=3600 seconds");
    if (o.sample_ms < 20 || o.ports < 10) throw std::invalid_argument("sample interval >=20ms and ports >=10 required");
    if (o.sources == 0) o.sources = 2*o.max_sources+1;
    return o;
}

class JsonlOutput {
public:
    explicit JsonlOutput(const std::string& path) {
        if (path.empty()) { file_ = stdout; return; }
        const int fd = ::open(path.c_str(), O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0644);
        if (fd < 0) throw std::runtime_error("cannot create output; existing files are never overwritten");
        file_ = ::fdopen(fd, "w");
        if (!file_) { ::close(fd); throw std::runtime_error("cannot open JSONL output stream"); }
        owned_ = true;
    }
    ~JsonlOutput() { if (owned_) std::fclose(file_); }
    void write(const std::string& line) {
        if (std::fwrite(line.data(), 1, line.size(), file_) != line.size() ||
            std::fputc('\n', file_) == EOF || std::fflush(file_) != 0)
            throw std::runtime_error("JSONL output failed");
    }
private:
    FILE* file_{nullptr};
    bool owned_{false};
};

std::uint16_t checksum(std::span<const std::byte> bytes, std::uint32_t sum=0) {
    for (std::size_t i=0; i<bytes.size(); i+=2) {
        sum += std::to_integer<unsigned char>(bytes[i]) << 8;
        if (i+1<bytes.size()) sum += std::to_integer<unsigned char>(bytes[i+1]);
    }
    while (sum >> 16) sum = (sum & 65535)+(sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}

std::array<std::byte,54> tcp_fixture(std::uint32_t source, std::uint16_t source_port,
                                    std::uint16_t destination_port, std::uint64_t index,
                                    unsigned flags) {
    std::array<std::byte,54> b{};
    auto put16 = [&](std::size_t at, std::uint16_t n) {
        b[at]=std::byte(n >> 8); b[at+1]=std::byte(n & 255);
    };
    b[0]=std::byte{2}; b[5]=std::byte{2}; b[6]=std::byte{2}; b[11]=std::byte{1};
    put16(12, 0x0800); b[14]=std::byte{0x45}; put16(16,40);
    put16(18,static_cast<std::uint16_t>(index)); put16(20,0x4000);
    b[22]=std::byte{64}; b[23]=std::byte{6};
    b[26]=std::byte{10}; b[27]=std::byte((source >> 16)&255);
    b[28]=std::byte((source >> 8)&255); b[29]=std::byte(source&255);
    b[30]=std::byte{198}; b[31]=std::byte{51}; b[32]=std::byte{100}; b[33]=std::byte{20};
    put16(34,source_port); put16(36,destination_port);
    for (int i=0; i<4; ++i) b[38+i]=std::byte((index >> (24-8*i))&255);
    b[46]=std::byte{0x50}; b[47]=std::byte(flags); put16(48,64240);
    put16(24,checksum(std::span<const std::byte>(b).subspan(14,20)));
    // Pseudo-header contains addresses, protocol and the TCP length (20).
    std::uint32_t pseudo=6+20;
    for (std::size_t i=26; i<34; i+=2)
        pseudo += (std::to_integer<unsigned char>(b[i])<<8)+std::to_integer<unsigned char>(b[i+1]);
    put16(50,checksum(std::span<const std::byte>(b).subspan(34,20),pseudo));
    return b;
}

class FixtureSource final : public capture::CaptureSource {
public:
    explicit FixtureSource(Options options, bool correctness=false)
        : options_(std::move(options)), correctness_(correctness) {
        if (options_.sources==0) options_.sources=2*options_.max_sources+1;
    }
    void set_callback(capture::PacketCallback cb) override { callback_=std::move(cb); }
    void set_ready_callback(std::function<void()> cb) override { ready_=std::move(cb); }
    void start() override {
        if (started_) throw std::logic_error("fixture source is single-use");
        started_=true;
        if (!callback_) throw std::logic_error("fixture callback missing");
        if (ready_) ready_();
        const auto begin=Steady::now();
        const auto deadline=begin+std::chrono::duration_cast<Steady::duration>(Duration{options_.duration});
        const auto epoch_flows=std::max<std::uint64_t>({options_.max_flows*2ULL,
            options_.max_observations*2ULL, options_.sources*16ULL, 128ULL});
        const double epoch_seconds=2*std::max(options_.idle_timeout,options_.window)+1;
        // Keep a capacity epoch inside active windows, then jump beyond both
        // timeouts. This stresses admission/eviction even with slow wall pacing.
        const double logical_rate=std::max(options_.rate > 0 ? options_.rate : 10000,
            static_cast<double>(epoch_flows)*8/std::min(options_.window,options_.idle_timeout));
        const TimePoint base{std::chrono::seconds{1700000000}};
        for (std::uint64_t i=0; !stopped_.load(std::memory_order_relaxed) &&
             !interrupted.load(std::memory_order_relaxed); ++i) {
            if (correctness_ ? i>=100 : Steady::now()>=deadline) break;
            const std::uint64_t flow=i/4;
            const auto epoch=flow/epoch_flows;
            const auto epoch_flow=flow%epoch_flows;
            // Alternate an admitted-source epoch (observation pressure) and a
            // high-cardinality epoch (source rejection pressure). Merely using
            // too many sources would mask observation capacity behind rejects.
            const auto source_pool=epoch%2==0 ? std::min(options_.sources,options_.max_sources) : options_.sources;
            std::uint32_t source=static_cast<std::uint32_t>(1+epoch_flow%source_pool);
            std::uint16_t port=static_cast<std::uint16_t>(1+(epoch_flow/source_pool)%options_.ports);
            std::uint16_t sport=static_cast<std::uint16_t>(49152+(epoch_flow/(source_pool*options_.ports))%16384);
            double logical_seconds=static_cast<double>(i)/logical_rate+
                static_cast<double>(flow/epoch_flows)*epoch_seconds;
            if (correctness_) {
                source=1; sport=49152; port=static_cast<std::uint16_t>(1+i%10);
                logical_seconds=static_cast<double>(i/50)*20+static_cast<double>(i%50)*0.001;
            } else if (options_.rate > 0) {
                const auto due=begin+std::chrono::duration_cast<Steady::duration>(Duration{static_cast<double>(i)/options_.rate});
                const auto wake_at=std::min(due,deadline);
                while (wake_at > Steady::now() && !stopped_.load(std::memory_order_relaxed) &&
                       !interrupted.load(std::memory_order_relaxed))
                    std::this_thread::sleep_until(std::min(wake_at,Steady::now()+std::chrono::milliseconds{20}));
                if (due >= deadline) break;
                if (stopped_.load(std::memory_order_relaxed) || Steady::now()>=deadline) break;
            }
            const unsigned flags=correctness_ || i%4<2 ? 2 : i%4==2 ? 16 : 24;
            const auto bytes=tcp_fixture(source,sport,port,i,flags);
            if (logical_seconds>=Duration(TimePoint::max()-base).count())
                throw std::runtime_error("fixture logical time exhausted representable timestamp range");
            const auto timestamp=correctness_
                ? base+std::chrono::seconds{static_cast<long>(i/50*20)}+std::chrono::milliseconds{static_cast<long>(i%50)}
                : base+std::chrono::duration_cast<Clock::duration>(Duration{logical_seconds});
            delivered_.fetch_add(1,std::memory_order_relaxed);
            callback_({timestamp,std::span<const std::byte>(bytes),1,54,54});
            last_logical_seconds_.store(logical_seconds,std::memory_order_relaxed);
        }
    }
    void stop() noexcept override { stopped_.store(true,std::memory_order_relaxed); }
    std::string description() const override { return "bounded-varied-checksummed-TCP-fixtures"; }
    capture::CaptureStatistics statistics() const noexcept override {
        capture::CaptureStatistics s;
        s.packets_received=delivered_.load(std::memory_order_relaxed);
        s.packets_captured=s.packets_received;
        s.statistics_available=true;
        return s;
    }
    double logical_seconds() const { return last_logical_seconds_.load(std::memory_order_relaxed); }
private:
    Options options_;
    bool correctness_{false};
    bool started_{false};
    capture::PacketCallback callback_;
    std::function<void()> ready_;
    std::atomic<bool> stopped_{false};
    std::atomic<std::uint64_t> delivered_{0};
    std::atomic<double> last_logical_seconds_{0};
};

void metrics_json(std::ostream& out, const metrics::EngineMetrics& m) {
    out << "{\"packets_received\":" << m.packets_received
        << ",\"packets_seen\":" << m.packets_seen << ",\"packets_captured\":" << m.packets_captured
        << ",\"packets_parsed\":" << m.packets_parsed << ",\"packets_processed\":" << m.packets_processed
        << ",\"packets_rejected\":" << m.packets_rejected << ",\"packets_malformed\":" << m.packets_malformed
        << ",\"packets_unsupported\":" << m.packets_unsupported << ",\"packets_truncated\":" << m.packets_truncated
        << ",\"capture_drops\":" << m.capture_drops << ",\"interface_drops\":" << m.interface_drops
        << ",\"capture_errors\":" << m.capture_errors << ",\"capture_statistics_available\":"
        << (m.capture_statistics_available ? "true" : "false")
        << ",\"flows_created\":" << m.flows_created << ",\"flows_active\":" << m.flows_active
        << ",\"flows_expired\":" << m.flows_expired << ",\"flows_flushed\":" << m.flows_flushed
        << ",\"flows_evicted\":" << m.flows_evicted << ",\"peak_active_flows\":" << m.peak_active_flows
        << ",\"detections_fired\":" << m.detections_fired << ",\"events_emitted\":" << m.events_emitted
        << ",\"sink_failures\":" << m.sink_failures
        << ",\"detector_observations\":" << m.detector_observations
        << ",\"detector_state_sources\":" << m.detector_state_sources
        << ",\"detector_state_observations\":" << m.detector_state_observations
        << ",\"detector_peak_sources\":" << m.detector_peak_sources
        << ",\"detector_peak_observations\":" << m.detector_peak_observations
        << ",\"detector_expired_sources\":" << m.detector_expired_sources
        << ",\"detector_state_rejections\":" << m.detector_state_rejections
        << ",\"detector_errors\":" << m.detector_errors
        << ",\"processing_seconds\":" << m.processing_seconds
        << ",\"event_sink_seconds\":" << m.event_sink_seconds
        << ",\"processing_packets_per_second\":" << m.processing_packets_per_second
        << ",\"runtime_seconds\":" << m.runtime_seconds << '}';
}

class TemporaryEvents {
public:
    TemporaryEvents() {
        std::string pattern=(::access("/tmp/opencode",W_OK)==0 ? "/tmp/opencode/" : "/tmp/");
        pattern += "intriqo-soak-events-XXXXXX";
        std::array<char,128> name{};
        std::copy(pattern.begin(),pattern.end(),name.begin());
        const int fd=::mkstemp(name.data());
        if (fd<0) throw std::runtime_error("cannot create bounded correctness event file");
        ::close(fd); path=name.data();
    }
    ~TemporaryEvents() { ::unlink(path.c_str()); }
    std::string path;
};

bool uuid_v4(std::string_view id) {
    if (id.size()!=36 || id[14]!='4' || std::string_view("89ab").find(id[19])==std::string_view::npos) return false;
    for (std::size_t i=0; i<id.size(); ++i) {
        if (i==8 || i==13 || i==18 || i==23) { if (id[i]!='-') return false; }
        else if (std::string_view("0123456789abcdef").find(id[i])==std::string_view::npos) return false;
    }
    return true;
}

bool correctness(JsonlOutput& output) {
    TemporaryEvents file;
    Options o;
    auto registry=std::make_unique<detection::DetectorRegistry>();
    registry->add(std::make_unique<detection::PortScanDetector>(detection::PortScanConfig{}));
    auto pipeline=std::make_unique<pipeline::PipelineImpl>(std::move(registry),Duration{1.0},100);
    runtime::EngineImpl engine(std::make_unique<FixtureSource>(o,true),std::move(pipeline),
        std::make_unique<transport::FileEventSink>(file.path));
    std::array<events::SecurityEvent,2> events;
    std::size_t observed=0;
    engine.on_event([&](events::SecurityEvent e) { if (observed<events.size()) events[observed]=std::move(e); ++observed; });
    engine.run();
    const auto m=engine.metrics();
    bool valid=observed==2 && m.packets_seen==100 && m.packets_processed==100 &&
        m.packets_rejected==0 && m.flows_created==20 && m.detections_fired==2 &&
        m.events_emitted==2 && m.sink_failures==0;
    std::ifstream input(file.path);
    std::array<std::string,2> json;
    for (std::size_t i=0; i<2; ++i) {
        const auto expected=TimePoint{std::chrono::seconds{1700000000}}+
            std::chrono::seconds{static_cast<long>(i*20)}+std::chrono::milliseconds{9};
        std::getline(input,json[i]);
        const auto& e=events[i];
        valid=valid && uuid_v4(e.event_id) && e.timestamp==expected &&
            e.event_type==events::EventType::PORT_SCAN && e.source_address.to_string()=="10.0.0.1" &&
            e.destination_address.to_string()=="198.51.100.20" && json[i]==e.to_json() &&
            json[i].find("\"unique_destination_ports\":10")!=std::string::npos &&
            json[i].find("\"connection_attempts\":10")!=std::string::npos;
    }
    std::string extra;
    valid=valid && events[0].event_id!=events[1].event_id && !std::getline(input,extra);
    std::ostringstream out;
    out << "{\"schema_version\":2,\"type\":\"correctness\",\"passed\":" << (valid ? "true" : "false")
        << ",\"expected_events\":2,\"observed_events\":" << observed
        << ",\"scenario\":\"two-expired-windows-ten-ports-five-repetitions-one-event-per-window\""
        << ",\"uuid_v4_unique_timestamp_and_file_serialization_checked\":" << (valid ? "true" : "false")
        << ",\"events\":[";
    // Include only serializer-produced bounded events; Python independently
    // parses this JSON and validates the contract, not just string equality.
    for (std::size_t i=0; i<std::min(observed,events.size()); ++i) {
        if (i) out << ',';
        out << events[i].to_json();
    }
    out << "],\"metrics\":"; metrics_json(out,m); out << '}';
    output.write(out.str());
    return valid;
}

struct Resources {
    long rss_kib{-1};
    long high_water_kib{-1};
    double user_seconds{0};
    double system_seconds{0};
};

Resources resources() {
    Resources r;
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status,line)) {
        if (!line.starts_with("VmRSS:") && !line.starts_with("VmHWM:")) continue;
        const auto start=line.find_first_of("0123456789");
        if (start!=std::string::npos) {
            auto& destination=line.starts_with("VmRSS:") ? r.rss_kib : r.high_water_kib;
            std::from_chars(line.data()+start,line.data()+line.size(),destination);
        }
    }
    rusage usage{};
    if (::getrusage(RUSAGE_SELF,&usage)==0) {
        // /proc VmHWM is post-exec process memory. ru_maxrss can preserve the
        // launching parent's pre-exec fork high-water and is not interchangeable.
        r.user_seconds=usage.ru_utime.tv_sec+usage.ru_utime.tv_usec/1000000.0;
        r.system_seconds=usage.ru_stime.tv_sec+usage.ru_stime.tv_usec/1000000.0;
    }
    return r;
}

int run(const Options& o) {
    JsonlOutput output(o.output);
    if (!correctness(output)) return 1;
    if (o.correctness_only) return 0;
    auto registry=std::make_unique<detection::DetectorRegistry>();
    detection::PortScanConfig config;
    config.window_seconds=o.window; config.max_tracked_sources=o.max_sources;
    config.max_tracked_observations=o.max_observations;
    registry->add(std::make_unique<detection::PortScanDetector>(config));
    auto source=std::make_unique<FixtureSource>(o);
    const auto* source_ptr=source.get();
    auto pipeline=std::make_unique<pipeline::PipelineImpl>(std::move(registry),Duration{o.idle_timeout},o.max_flows);
    runtime::EngineImpl engine(std::move(source),std::move(pipeline),std::make_unique<transport::FileEventSink>("/dev/null"));
    const auto initial=resources();
    const auto start=Steady::now();
    long peak_rss=initial.rss_kib;
    std::uint64_t samples=0;
    std::mutex mutex;
    std::condition_variable wake;
    bool done=false;
    std::exception_ptr sample_error;
    auto sample = [&](std::string_view phase) {
        const auto r=resources();
        peak_rss=std::max(peak_rss,r.rss_kib);
        const double elapsed=std::chrono::duration<double>(Steady::now()-start).count();
        std::ostringstream out; out << std::setprecision(10)
            << "{\"schema_version\":2,\"type\":\"sample\",\"phase\":\"" << phase
            << "\",\"elapsed_seconds\":" << elapsed << ",\"rss_kib\":" << r.rss_kib
            << ",\"process_high_water_rss_kib\":" << r.high_water_kib
            << ",\"cpu_user_seconds\":" << r.user_seconds-initial.user_seconds
            << ",\"cpu_system_seconds\":" << r.system_seconds-initial.system_seconds
            << ",\"logical_fixture_seconds\":" << source_ptr->logical_seconds()
            << ",\"metrics\":"; metrics_json(out,engine.metrics()); out << '}';
        output.write(out.str()); ++samples;
    };
    sample("initial");
    std::thread sampler([&] {
        try {
            std::unique_lock lock(mutex);
            while (!wake.wait_for(lock,std::chrono::milliseconds{o.sample_ms},[&] { return done; })) {
                lock.unlock(); sample("periodic"); lock.lock();
            }
        } catch (...) { sample_error=std::current_exception(); engine.stop(); }
    });
    std::exception_ptr failure;
    try { engine.run(); } catch (...) { failure=std::current_exception(); }
    { std::lock_guard lock(mutex); done=true; }
    wake.notify_one(); sampler.join();
    if (sample_error) std::rethrow_exception(sample_error);
    sample("final-post-flush");
    const auto final=resources();
    const auto m=engine.metrics();
    const double elapsed=std::chrono::duration<double>(Steady::now()-start).count();
    const bool bounded=m.peak_active_flows<=o.max_flows && m.detector_peak_sources<=o.max_sources &&
        m.detector_peak_observations<=o.max_observations;
    const bool counters=m.packets_seen==m.packets_captured && m.packets_captured==m.packets_parsed &&
        m.packets_parsed==m.packets_processed && m.packets_rejected==0 && m.capture_errors==0 &&
        m.sink_failures==0 && m.detector_errors==0 && m.flows_active==0 &&
        m.detector_state_sources==0 && m.detector_state_observations==0 &&
        m.events_emitted==m.detections_fired &&
        m.flows_created==m.flows_expired+m.flows_evicted+m.flows_flushed;
    std::ostringstream out; out << std::setprecision(10)
        << "{\"schema_version\":2,\"type\":\"summary\",\"status\":\""
        << (failure || !bounded || !counters ? "failed" : interrupted.load() ? "interrupted" : "complete")
        << "\",\"duration_seconds\":" << o.duration << ",\"elapsed_seconds\":" << elapsed
        << ",\"target_offered_packets_per_second\":" << o.rate
        << ",\"achieved_offered_packets_per_second\":" << (elapsed>0 ? m.packets_seen/elapsed : 0)
        << ",\"offered_packets\":" << m.packets_seen
        << ",\"initial_rss_kib\":" << initial.rss_kib << ",\"peak_sampled_rss_kib\":" << peak_rss
        << ",\"final_rss_kib\":" << final.rss_kib << ",\"process_high_water_rss_kib\":" << final.high_water_kib
        << ",\"cpu_user_seconds\":" << final.user_seconds-initial.user_seconds
        << ",\"cpu_system_seconds\":" << final.system_seconds-initial.system_seconds
        << ",\"cpu_utilization_percent\":" << (elapsed>0 ? 100*((final.user_seconds-initial.user_seconds)+
            (final.system_seconds-initial.system_seconds))/elapsed : 0)
        << ",\"sample_count\":" << samples << ",\"samples_retained_in_memory\":0"
        << ",\"max_active_flows\":" << o.max_flows << ",\"max_tracked_sources\":" << o.max_sources
        << ",\"max_tracked_observations\":" << o.max_observations << ",\"fixture_sources\":" << o.sources
        << ",\"fixture_destination_ports\":" << o.ports << ",\"flow_idle_timeout_seconds\":" << o.idle_timeout
        << ",\"fixture_epoch_policy\":\"alternating-admitted-sources-and-high-cardinality-with-timeout-jumps\""
        << ",\"portscan_window_seconds\":" << o.window << ",\"logical_fixture_seconds\":" << source_ptr->logical_seconds()
        << ",\"state_capacity_bounds_passed\":" << (bounded ? "true" : "false")
        << ",\"counter_invariants_passed\":" << (counters ? "true" : "false")
        << ",\"flow_capacity_exercised\":" << (m.flows_evicted>0 ? "true" : "false")
        << ",\"source_capacity_reached\":" << (m.detector_peak_sources==o.max_sources ? "true" : "false")
        << ",\"observation_capacity_reached\":" << (m.detector_peak_observations==o.max_observations ? "true" : "false")
        << ",\"packet_latency_p99_ms\":null,\"packet_latency_reason\":\"logical-fixture-time-not-wall-packet-timing\""
        << ",\"rss_scope\":\"initial-after-correctness-final-post-flush-sampled-peak-not-plateau-proof\""
        << ",\"metrics\":"; metrics_json(out,m); out << '}'; output.write(out.str());
    if (failure) {
        try { std::rethrow_exception(failure); }
        catch (const std::exception& error) { std::cerr << "error: soak engine: " << error.what() << '\n'; }
        catch (...) { std::cerr << "error: soak engine failed\n"; }
    }
    return failure || !bounded || !counters ? 1 : interrupted.load() ? 130 : 0;
}
} // namespace

int main(int argc, char** argv) {
    try {
        const auto options=parse_options(argc,argv);
        if (options.help) { usage(); return 0; }
        struct sigaction action{};
        action.sa_handler=request_stop; sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT,&action,nullptr)!=0 || sigaction(SIGTERM,&action,nullptr)!=0)
            throw std::runtime_error("could not install stop handlers");
        return run(options);
    } catch (const std::invalid_argument& error) {
        std::cerr << "error: " << error.what() << '\n'; return 2;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n'; return 1;
    }
}
