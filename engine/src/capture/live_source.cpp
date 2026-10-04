#include "intriqo/capture/capture.hpp"
#include "capture_internal.hpp"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
#include <exception>
#include <memory>
#include <stdexcept>
#include <utility>

#if defined(INTRIQO_HAS_PCAP) && defined(__linux__)
#include <pcap/pcap.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#endif

namespace intriqo::capture {

struct LiveCaptureSource::State : detail::CaptureState {
#if defined(INTRIQO_HAS_PCAP) && defined(__linux__)
    const int wake_fd;

    State() : wake_fd(::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) {
        if (wake_fd < 0) {
            throw std::runtime_error(std::string("Live capture: cannot create shutdown eventfd: ")
                                     + std::strerror(errno));
        }
    }
    ~State() { ::close(wake_fd); }
#endif
};

LiveCaptureSource::LiveCaptureSource(LiveCaptureConfig config)
    : config_(std::move(config)), state_(std::make_unique<State>()) {}

LiveCaptureSource::~LiveCaptureSource() = default;

void LiveCaptureSource::set_callback(PacketCallback cb) { state_->set_callback(std::move(cb)); }
void LiveCaptureSource::set_ready_callback(std::function<void()> cb) { state_->set_ready_callback(std::move(cb)); }
void LiveCaptureSource::set_idle_callback(std::function<void(TimePoint)> cb) { state_->set_idle_callback(std::move(cb)); }
std::string LiveCaptureSource::description() const { return "live:" + config_.interface_name; }
CaptureStatistics LiveCaptureSource::statistics() const noexcept { return state_->statistics(); }

void LiveCaptureSource::stop() noexcept {
    state_->stop();
#if defined(INTRIQO_HAS_PCAP) && defined(__linux__)
    // stop() never touches the pcap handle. Its owner is exclusively start(),
    // and this eventfd remains valid for the entire lifetime of the source.
    const std::uint64_t value = 1;
    while (::write(state_->wake_fd, &value, sizeof(value)) < 0 && errno == EINTR) {}
#endif
}

void LiveCaptureSource::start() {
    const auto callback = state_->begin();
    if (!callback) return;

#if !defined(__linux__)
    state_->record_error();
    throw std::runtime_error("Live capture is supported only on Linux");
#elif !defined(INTRIQO_HAS_PCAP)
    state_->record_error();
    throw std::runtime_error("Live capture is unavailable: Intriqo was built without libpcap "
                             "(INTRIQO_HAS_PCAP)");
#else
    const auto fail = [this](const std::string& reason) {
        state_->record_error();
        return std::runtime_error("Live capture '" + config_.interface_name + "': " + reason);
    };
    if (config_.interface_name.empty()) throw fail("interface_name must not be empty");
    if (config_.snaplen <= 0
        || static_cast<std::uint32_t>(config_.snaplen) > detail::max_packet_length) {
        throw fail("snaplen must be between 1 and 16777216 bytes");
    }
    if (config_.timeout.count() < 0 || config_.timeout.count() > INT_MAX) {
        throw fail("timeout must be between 0 and INT_MAX milliseconds");
    }
    if (config_.timeout.count() == 0 && !config_.immediate) {
        throw fail("buffered capture requires a positive packet buffer timeout");
    }
    if (config_.buffer_size <= 0) throw fail("capture buffer_size must be positive");
    if (state_->stopped.load()) return;

    char error_buffer[PCAP_ERRBUF_SIZE]{};
    std::unique_ptr<pcap_t, decltype(&pcap_close)> handle(
        pcap_create(config_.interface_name.c_str(), error_buffer), &pcap_close);
    if (!handle) throw fail(std::string("pcap_create failed: ") + error_buffer);

    const auto check = [&](int result, const char* operation) {
        if (result < 0) {
            const char* error = pcap_geterr(handle.get());
            throw fail(std::string(operation) + " failed: "
                       + (error && *error ? error : pcap_statustostr(result)));
        }
    };
    check(pcap_set_snaplen(handle.get(), config_.snaplen), "pcap_set_snaplen");
    check(pcap_set_buffer_size(handle.get(), config_.buffer_size), "pcap_set_buffer_size");
    check(pcap_set_promisc(handle.get(), config_.promiscuous ? 1 : 0), "pcap_set_promisc");
    check(pcap_set_timeout(handle.get(), static_cast<int>(config_.timeout.count())), "pcap_set_timeout");
    check(pcap_set_immediate_mode(handle.get(), config_.immediate ? 1 : 0), "pcap_set_immediate_mode");

    bool nanoseconds = false;
#ifdef PCAP_TSTAMP_PRECISION_NANO
    const int precision_result = pcap_set_tstamp_precision(handle.get(), PCAP_TSTAMP_PRECISION_NANO);
    if (precision_result == 0) nanoseconds = true;
    else if (precision_result != PCAP_ERROR_TSTAMP_PRECISION_NOTSUP) {
        check(precision_result, "pcap_set_tstamp_precision");
    }
#endif
    // Positive activate results are libpcap warnings; the handle is usable.
    check(pcap_activate(handle.get()), "pcap_activate");
    if (state_->stopped.load()) return;

    const int datalink = pcap_datalink(handle.get());
    if (datalink < 0) throw fail(std::string("pcap_datalink failed: ") + pcap_geterr(handle.get()));
    try {
        detail::validate_link_type(static_cast<std::size_t>(datalink));
    } catch (const std::exception& error) {
        throw fail(error.what());
    }

    if (!config_.bpf_filter.empty()) {
        struct Filter {
            bpf_program program{};
            bool compiled{false};
            ~Filter() { if (compiled) pcap_freecode(&program); }
        } filter;
        check(pcap_compile(handle.get(), &filter.program, config_.bpf_filter.c_str(), 1,
                           PCAP_NETMASK_UNKNOWN), "pcap_compile (BPF filter)");
        filter.compiled = true;
        check(pcap_setfilter(handle.get(), &filter.program), "pcap_setfilter");
    }
    if (pcap_setnonblock(handle.get(), 1, error_buffer) < 0) {
        throw fail(std::string("pcap_setnonblock failed: ") + error_buffer);
    }

    pcap_stat previous_counters{};
    CaptureStatistics totals{};
    auto last_statistics = std::chrono::steady_clock::time_point{};
    const auto refresh_statistics = [&](bool force = false) {
        const auto now = std::chrono::steady_clock::now();
        if (!force && now - last_statistics < std::chrono::milliseconds(100)) return;
        last_statistics = now;
        pcap_stat counters{};
        if (pcap_stats(handle.get(), &counters) < 0) {
            // Statistics are optional on some capture devices. Report their
            // availability independently of packet-read success.
            state_->record_statistics_error();
            return;
        }
        // Extend libpcap's unsigned 32-bit counters. ps_ifdrop is published as
        // reported; a zero does not imply hardware drop counters are supported.
        totals.packets_received += static_cast<std::uint32_t>(counters.ps_recv - previous_counters.ps_recv);
        totals.packets_dropped += static_cast<std::uint32_t>(counters.ps_drop - previous_counters.ps_drop);
        totals.interface_dropped += static_cast<std::uint32_t>(counters.ps_ifdrop - previous_counters.ps_ifdrop);
        previous_counters = counters;
        state_->publish_kernel_statistics(totals);
    };

    struct DispatchContext {
        detail::CaptureState& state;
        pcap_t* handle;
        const PacketCallback& callback;
        const LiveCaptureConfig& config;
        int datalink;
        bool nanoseconds;
        std::vector<std::byte> storage;
        std::exception_ptr failure;

        void deliver(const pcap_pkthdr* header, const unsigned char* data) noexcept {
            if (state.stopped.load() || failure) {
                pcap_breakloop(handle);
                return;
            }
            packet::PacketView packet;
            try {
                const auto invalid = [this](const char* reason) {
                    return std::runtime_error("Live capture '" + config.interface_name + "': " + reason);
                };
                if (!header || (header->caplen != 0 && !data)) {
                    throw invalid("pcap_dispatch returned an invalid packet");
                }
                if (header->caplen > static_cast<std::uint32_t>(config.snaplen)
                    || header->caplen > header->len || header->len > detail::max_packet_length) {
                    throw invalid("invalid captured/original packet lengths");
                }
                const auto seconds = header->ts.tv_sec;
                const auto fraction = header->ts.tv_usec;
                if (seconds < 0 || fraction < 0
                    || fraction >= (nanoseconds ? 1'000'000'000L : 1'000'000L)
                    || seconds > std::chrono::duration_cast<std::chrono::seconds>(
                        Clock::duration::max()).count() - 1) {
                    throw invalid("packet timestamp is out of range");
                }
                const auto subsecond = nanoseconds ? std::chrono::nanoseconds(fraction)
                    : std::chrono::nanoseconds(std::chrono::microseconds(fraction));
                const auto timestamp = TimePoint{std::chrono::duration_cast<Clock::duration>(
                    std::chrono::seconds(seconds) + subsecond)};
                const auto normalized = detail::normalize(
                    {reinterpret_cast<const std::byte*>(data), header->caplen},
                    static_cast<std::size_t>(datalink), storage);
                packet = {timestamp, normalized.bytes, normalized.link_type, header->len, header->caplen};
            } catch (...) {
                state.record_error();
                failure = std::current_exception();
                pcap_breakloop(handle);
                return;
            }
            if (state.stopped.load()) {
                pcap_breakloop(handle);
                return;
            }
            state.record_delivery(false);
            try {
                callback(packet);
            } catch (...) {
                // Never unwind C/libpcap frames, and do not label user callback
                // exceptions as capture failures.
                failure = std::current_exception();
                pcap_breakloop(handle);
                return;
            }
            if (state.stopped.load()) pcap_breakloop(handle);
        }
    } context{*state_, handle.get(), callback, config_, datalink, nanoseconds, {}, {}};
    const auto trampoline = [](unsigned char* user, const pcap_pkthdr* header,
                               const unsigned char* data) noexcept {
        reinterpret_cast<DispatchContext*>(user)->deliver(header, data);
    };

    const int capture_fd = pcap_get_selectable_fd(handle.get());
    const int retry_ms = static_cast<int>(std::clamp<std::int64_t>(
        config_.timeout.count() == 0 ? 100 : config_.timeout.count(), 1, 100));
    const auto poll_timeout = [&] {
        int timeout = retry_ms;
#ifdef PCAP_AVAILABLE_1_9
        // Some devices require a periodic read even with a selectable fd.
        // Re-query: libpcap permits this required timeout to change.
        if (const auto* required = pcap_get_required_select_timeout(handle.get())) {
            if (required->tv_sec == 0 && required->tv_usec >= 0) {
                const auto milliseconds = required->tv_usec / 1000 + (required->tv_usec % 1000 != 0);
                timeout = static_cast<int>(std::clamp<decltype(milliseconds)>(milliseconds, 1, timeout));
            }
        }
#endif
        return timeout;
    };
    bool idle_backoff = false;
    bool buffered_packets = false;
    refresh_statistics(true);
    try {
        state_->ready();
        while (!state_->stopped.load()) {
            pollfd descriptors[2]{{state_->wake_fd, POLLIN, 0}, {capture_fd, POLLIN, 0}};
            // A spuriously readable descriptor backs off on the eventfd only.
            const nfds_t count = capture_fd >= 0 && !idle_backoff ? 2 : 1;
            const bool waited = !buffered_packets;
            // Drain libpcap's internal buffer without waiting for fd readiness,
            // including short batches: only a zero dispatch proves it is empty.
            const int ready = waited ? ::poll(descriptors, count, poll_timeout()) : 0;
            if (ready < 0) {
                if (errno == EINTR) continue;
                throw fail(std::string("poll failed: ") + std::strerror(errno));
            }
            if (state_->stopped.load()) break;
            if (descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                throw fail("shutdown descriptor became invalid");
            }
            if (count == 2 && (descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL))) {
                throw fail("capture descriptor reported an error or hangup");
            }

            // Bounded, nonblocking batches amortize libpcap entry overhead; the
            // trampoline can interrupt even a full batch on stop or failure.
            const int delivered = pcap_dispatch(handle.get(), 256, trampoline,
                reinterpret_cast<unsigned char*>(&context));
            if (context.failure) std::rethrow_exception(context.failure);
            if (delivered == PCAP_ERROR_BREAK) {
                if (state_->stopped.load()) break;
                throw fail("pcap_dispatch ended unexpectedly");
            }
            check(delivered, "pcap_dispatch");
            buffered_packets = delivered > 0;
            idle_backoff = delivered == 0 && capture_fd >= 0 && (idle_backoff || ready > 0);
            refresh_statistics();
            if (waited && ready == 0 && delivered == 0) state_->idle();
        }
        refresh_statistics(true);
    } catch (...) {
        const auto error = std::current_exception();
        refresh_statistics(true);
        std::rethrow_exception(error);
    }
#endif
}

} // namespace intriqo::capture
