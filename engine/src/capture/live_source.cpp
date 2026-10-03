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
    throw std::runtime_error("Live capture is supported only on Linux");
#elif !defined(INTRIQO_HAS_PCAP)
    throw std::runtime_error("Live capture is unavailable: Intriqo was built without libpcap "
                             "(INTRIQO_HAS_PCAP)");
#else
    const auto fail = [this](const std::string& reason) {
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
    check(pcap_set_immediate_mode(handle.get(), 1), "pcap_set_immediate_mode");

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
    state_->ready();
    CaptureStatistics totals{};
    const auto refresh_statistics = [&] {
        pcap_stat counters{};
        check(pcap_stats(handle.get(), &counters), "pcap_stats");
        // libpcap uses unsigned 32-bit counters; extend wraps to the public
        // 64-bit totals while this single capture handle remains active.
        totals.packets_received += static_cast<std::uint32_t>(counters.ps_recv - previous_counters.ps_recv);
        totals.packets_dropped += static_cast<std::uint32_t>(counters.ps_drop - previous_counters.ps_drop);
        totals.interface_dropped += static_cast<std::uint32_t>(counters.ps_ifdrop - previous_counters.ps_ifdrop);
        previous_counters = counters;
        state_->received.store(totals.packets_received);
        state_->dropped.store(totals.packets_dropped);
        state_->interface_dropped.store(totals.interface_dropped);
    };

    const int capture_fd = pcap_get_selectable_fd(handle.get());
    // Some devices have no selectable descriptor. Polling only the shutdown
    // eventfd gives a bounded, interruptible retry instead of spinning.
    const int retry_ms = static_cast<int>(std::clamp<std::int64_t>(
        config_.timeout.count() == 0 ? 100 : config_.timeout.count(), 1, 100));
    std::vector<std::byte> normalized_storage;
    bool idle_backoff = false;
    bool buffered_packets = false;
    try {
        while (!state_->stopped.load()) {
            pollfd descriptors[2]{{state_->wake_fd, POLLIN, 0}, {capture_fd, POLLIN, 0}};
            // An unexpectedly readable fd with no packets must not cause a
            // busy loop. Wait solely on the shutdown fd until a retry makes
            // progress, then return to selectable capture polling.
            const nfds_t count = capture_fd >= 0 && !idle_backoff ? 2 : 1;
            // A full batch may leave packets inside libpcap even when its fd is
            // no longer readable. Drain those before waiting for new traffic.
            const int ready = buffered_packets ? 0 : ::poll(descriptors, count, retry_ms);
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

            bool delivered = false;
            unsigned int batch = 0;
            // Limit each drain so shutdown and counters remain responsive even
            // on a continuously busy interface. Every pcap read is nonblocking.
            for (; batch < 64 && !state_->stopped.load(); ++batch) {
                pcap_pkthdr* header = nullptr;
                const unsigned char* data = nullptr;
                const int result = pcap_next_ex(handle.get(), &header, &data);
                if (result == 0) break;
                if (result == -2) throw fail("capture ended unexpectedly");
                check(result, "pcap_next_ex");
                if (result != 1 || !header || (header->caplen != 0 && !data)) {
                    throw fail("pcap_next_ex returned an invalid packet");
                }
                if (header->caplen > static_cast<std::uint32_t>(config_.snaplen)
                    || header->caplen > header->len || header->len > detail::max_packet_length) {
                    throw fail("invalid captured/original packet lengths");
                }
                const auto seconds = header->ts.tv_sec;
                const auto fraction = header->ts.tv_usec; // nanoseconds when that precision was selected
                if (seconds < 0 || fraction < 0
                    || fraction >= (nanoseconds ? 1'000'000'000L : 1'000'000L)
                    || seconds > std::chrono::duration_cast<std::chrono::seconds>(
                        Clock::duration::max()).count() - 1) {
                    throw fail("packet timestamp is out of range");
                }
                const auto subsecond = nanoseconds ? std::chrono::nanoseconds(fraction)
                    : std::chrono::nanoseconds(std::chrono::microseconds(fraction));
                const auto timestamp = TimePoint{std::chrono::duration_cast<Clock::duration>(
                    std::chrono::seconds(seconds) + subsecond)};
                const auto normalized = detail::normalize(
                    {reinterpret_cast<const std::byte*>(data), header->caplen},
                    static_cast<std::size_t>(datalink), normalized_storage);
                if (state_->stopped.load()) break;
                callback({timestamp, normalized.bytes, normalized.link_type, header->len, header->caplen});
                delivered = true;
            }
            refresh_statistics();
            buffered_packets = batch == 64;
            idle_backoff = !delivered && capture_fd >= 0 && (idle_backoff || ready > 0);
        }
        refresh_statistics();
    } catch (...) {
        const auto error = std::current_exception();
        try { refresh_statistics(); } catch (...) {} // preserve the original read/callback error
        handle.reset();
        std::rethrow_exception(error);
    }
#endif
}

} // namespace intriqo::capture
