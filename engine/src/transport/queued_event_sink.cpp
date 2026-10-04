#include "intriqo/transport/queued_event_sink.hpp"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace intriqo::transport {
namespace {

enum class FailureOrigin {
    none, not_ready, closed, overflow, copy, prepare, worker_start, worker, submit, flush
};

bool underlying_failure(FailureOrigin origin) noexcept {
    return origin == FailureOrigin::prepare || origin == FailureOrigin::worker_start ||
           origin == FailureOrigin::worker || origin == FailureOrigin::submit ||
           origin == FailureOrigin::flush;
}

const char* failure_message(FailureOrigin origin) noexcept {
    switch (origin) {
    case FailureOrigin::none: return "";
    case FailureOrigin::not_ready: return "queued event sink is not prepared";
    case FailureOrigin::closed: return "queued event sink admission is closed";
    case FailureOrigin::overflow: return "queued event sink capacity exceeded";
    case FailureOrigin::copy: return "queued event sink event copy failed";
    case FailureOrigin::prepare: return "queued event sink underlying preparation failed";
    case FailureOrigin::worker_start: return "queued event sink worker startup failed";
    case FailureOrigin::worker: return "queued event sink worker wait failed";
    case FailureOrigin::submit: return "queued event sink underlying submission failed";
    case FailureOrigin::flush: return "queued event sink underlying flush failed";
    }
    return "queued event sink failed";
}

// Error details are bounded and single-line. Known credential labels are
// redacted together with the remainder, rather than echoing bearer/header data.
std::string sanitized_detail(std::string_view detail) {
    constexpr std::size_t max_length = 512;
    std::string result(detail.substr(0, max_length));
    std::string lower;
    lower.reserve(result.size());
    for (char& character : result) {
        const auto byte = static_cast<unsigned char>(character);
        if (byte < 0x20 || byte == 0x7f) character = ' ';
        lower.push_back(character >= 'A' && character <= 'Z'
            ? static_cast<char>(character + ('a' - 'A')) : character);
    }
    auto sensitive = std::string::npos;
    for (const auto label : {"authorization", "bearer", "token", "password",
                             "secret", "api_key", "api-key", "apikey"}) {
        sensitive = std::min(sensitive, lower.find(label));
    }
    if (sensitive != std::string::npos) {
        result.resize(sensitive);
        result += "[redacted]";
    } else if (detail.size() > max_length) {
        result += "...";
    }
    return result;
}

double seconds_since(std::chrono::steady_clock::time_point started) noexcept {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
}

} // namespace

struct QueuedEventSink::State {
    State(std::unique_ptr<SecurityEventSink> underlying, std::size_t max_pending)
        : sink(std::move(underlying)), capacity(max_pending) {
        if (!sink) throw std::invalid_argument("queued event sink requires an underlying sink");
        if (capacity == 0) throw std::invalid_argument("queued event sink capacity must be positive");
        // Preallocate a ring of empty slots. Only event copies allocate on admission.
        pending.resize(capacity);
    }

    void fail_locked(FailureOrigin origin) noexcept {
        ++statistics.event_sink_failures;
        // Preserve the first underlying failure even if later submissions fail
        // because admission has closed. A transport error takes precedence over
        // an earlier local rejection/overflow.
        if (failure == FailureOrigin::none ||
            (underlying_failure(origin) && !underlying_failure(failure))) {
            failure = origin;
            detail.clear();
        }
    }

    void capture_error(FailureOrigin origin) noexcept {
        try {
            auto message = sanitized_detail(sink->error());
            std::lock_guard lock(mutex);
            if (failure == origin && detail.empty()) detail = std::move(message);
        } catch (...) {
            // error() and allocation can throw; the allocation-free origin and
            // failure counter have already been recorded.
        }
    }

    void work() noexcept {
        static_assert(std::is_nothrow_move_constructible_v<events::SecurityEvent>);
        for (;;) {
            std::optional<events::SecurityEvent> event;
            {
                std::unique_lock lock(mutex);
                try {
                    changed.wait(lock, [this] { return depth != 0 || admission_closed; });
                } catch (...) {
                    // Close admission but still drain already admitted events.
                    fail_locked(FailureOrigin::worker);
                    sink_failed = true;
                    admission_closed = true;
                }
                if (depth == 0) return;
                event.emplace(std::move(*pending[head]));
                pending[head].reset();
                head = (head + 1) % capacity;
                --depth;
                statistics.queue_depth = depth;
            }

            // No queue mutex is held during underlying I/O or error retrieval.
            const auto started = std::chrono::steady_clock::now();
            const bool acknowledged = sink->submit(*event);
            const double elapsed = seconds_since(started);
            {
                std::lock_guard lock(mutex);
                statistics.event_sink_seconds += elapsed;
                if (acknowledged) {
                    ++statistics.events_emitted;
                } else {
                    fail_locked(FailureOrigin::submit);
                    sink_failed = true;
                }
            }
            if (!acknowledged) capture_error(FailureOrigin::submit);
        }
    }

    std::unique_ptr<SecurityEventSink> sink;
    const std::size_t capacity;
    std::vector<std::optional<events::SecurityEvent>> pending;
    std::size_t head{0};
    std::size_t tail{0};
    std::size_t depth{0};
    mutable std::mutex mutex;
    std::condition_variable changed;
    std::thread worker;
    bool prepare_attempted{false};
    bool preparing{false};
    bool prepared{false};
    bool sink_failed{false};
    bool admission_closed{false};
    bool flushing{false};
    bool finished{false};
    EventDeliveryStatistics statistics;
    FailureOrigin failure{FailureOrigin::none};
    std::string detail;
};

QueuedEventSink::QueuedEventSink(std::unique_ptr<SecurityEventSink> sink, std::size_t capacity)
    : state_(std::make_unique<State>(std::move(sink), capacity)) {}

QueuedEventSink::~QueuedEventSink() { (void)flush(); }

bool QueuedEventSink::prepare() noexcept {
    auto& state = *state_;
    {
        std::unique_lock lock(state.mutex);
        state.changed.wait(lock, [&state] { return !state.preparing; });
        if (state.admission_closed) return false;
        if (state.prepare_attempted) return state.prepared && !state.sink_failed;
        state.prepare_attempted = true;
        state.preparing = true;
    }

    const bool prepared = state.sink->prepare();
    bool worker_started = false;
    if (prepared) {
        try {
            state.worker = std::thread([state_ptr = &state] { state_ptr->work(); });
            worker_started = true;
        } catch (...) {
            std::lock_guard lock(state.mutex);
            state.fail_locked(FailureOrigin::worker_start);
            state.sink_failed = true;
        }
    } else {
        {
            std::lock_guard lock(state.mutex);
            state.fail_locked(FailureOrigin::prepare);
            state.sink_failed = true;
        }
        state.capture_error(FailureOrigin::prepare);
    }

    bool result;
    {
        std::lock_guard lock(state.mutex);
        state.prepared = prepared && worker_started;
        state.preparing = false;
        result = state.prepared && !state.admission_closed;
    }
    state.changed.notify_all();
    return result;
}

bool QueuedEventSink::submit(const events::SecurityEvent& event) noexcept {
    auto& state = *state_;
    {
        std::lock_guard lock(state.mutex);
        if (state.sink_failed) {
            state.fail_locked(state.failure);
            return false;
        }
        if (state.admission_closed) {
            state.fail_locked(FailureOrigin::closed);
            return false;
        }
        if (!state.prepared) {
            state.fail_locked(FailureOrigin::not_ready);
            return false;
        }
        if (state.depth == state.capacity) {
            state.fail_locked(FailureOrigin::overflow);
            ++state.statistics.queue_overflows;
            return false;
        }
        try {
            state.pending[state.tail].emplace(event);
        } catch (...) {
            state.fail_locked(FailureOrigin::copy);
            return false;
        }
        state.tail = (state.tail + 1) % state.capacity;
        ++state.depth;
        state.statistics.queue_depth = state.depth;
        state.statistics.queue_peak_depth = std::max(state.statistics.queue_peak_depth,
                                                    state.statistics.queue_depth);
    }
    state.changed.notify_one();
    return true;
}

bool QueuedEventSink::flush() noexcept {
    auto& state = *state_;
    {
        std::unique_lock lock(state.mutex);
        state.admission_closed = true;
        state.changed.notify_all();
        if (state.flushing) {
            state.changed.wait(lock, [&state] { return state.finished; });
            return state.statistics.event_sink_failures == 0;
        }
        if (state.finished) return state.statistics.event_sink_failures == 0;
        state.flushing = true;
        state.changed.wait(lock, [&state] { return !state.preparing; });
    }

    // Exactly one flusher owns the join and the final underlying flush. Other
    // callers wait on changed, which releases the mutex while the worker drains.
    if (state.worker.joinable()) state.worker.join();
    const auto started = std::chrono::steady_clock::now();
    const bool flushed = state.sink->flush();
    const double elapsed = seconds_since(started);
    {
        std::lock_guard lock(state.mutex);
        state.statistics.event_sink_seconds += elapsed;
        if (!flushed) {
            state.fail_locked(FailureOrigin::flush);
            state.sink_failed = true;
        }
    }
    if (!flushed) state.capture_error(FailureOrigin::flush);

    bool result;
    {
        std::lock_guard lock(state.mutex);
        state.finished = true;
        state.flushing = false;
        result = state.statistics.event_sink_failures == 0;
    }
    state.changed.notify_all();
    return result;
}

std::string QueuedEventSink::error() const {
    std::lock_guard lock(state_->mutex);
    std::string message = failure_message(state_->failure);
    if (!state_->detail.empty()) message += ": " + state_->detail;
    return message;
}

std::optional<EventDeliveryStatistics> QueuedEventSink::delivery_statistics() const noexcept {
    std::lock_guard lock(state_->mutex);
    return state_->statistics;
}

} // namespace intriqo::transport
