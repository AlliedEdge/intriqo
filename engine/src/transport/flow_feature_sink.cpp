#include "intriqo/transport/flow_feature_sink.hpp"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <linux/magic.h>
#include <mutex>
#include <stdexcept>
#include <string_view>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <thread>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>
#include <variant>

namespace intriqo::transport {
namespace {

constexpr std::size_t maximum_instance_id_bytes = 36;

double seconds_since(std::chrono::steady_clock::time_point start) noexcept {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
}

class Descriptor {
public:
    explicit Descriptor(int fd = -1) noexcept : fd_(fd) {}
    ~Descriptor() { if (fd_ >= 0) (void)::close(fd_); }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    int get() const noexcept { return fd_; }
    int release() noexcept { return std::exchange(fd_, -1); }
    void reset(int fd) noexcept {
        if (fd_ >= 0) (void)::close(fd_);
        fd_ = fd;
    }
private:
    int fd_;
};

bool local_filesystem(int fd) noexcept {
    struct statfs information{};
    if (::fstatfs(fd, &information) != 0) return false;
    // Fail closed for unknown and userspace filesystems: a FUSE regular file can
    // represent a remote endpoint. The supported native local Linux filesystems
    // below include the usual disk, memory, and container overlay filesystems.
    switch (information.f_type) {
    case EXT4_SUPER_MAGIC:
    case XFS_SUPER_MAGIC:
    case BTRFS_SUPER_MAGIC:
    case TMPFS_MAGIC:
    case RAMFS_MAGIC:
    case OVERLAYFS_SUPER_MAGIC:
    case F2FS_SUPER_MAGIC:
    case 0x3153464a: // JFS (not defined in all linux/magic.h versions).
    case NILFS_SUPER_MAGIC:
    case REISERFS_SUPER_MAGIC:
    case MSDOS_SUPER_MAGIC:
    case EXFAT_SUPER_MAGIC:
    case 0x2fc12fc1: // ZFS (not defined in all linux/magic.h versions).
    case 0x5346544e: // Native NTFS.
    case 0x7366746e: // Native NTFS3.
        return true;
    default:
        return false;
    }
}

int open_local_file(std::string_view path) {
    constexpr int directory_flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
    Descriptor directory(::open(path.front() == '/' ? "/" : ".", directory_flags));
    if (directory.get() < 0) return -1;
    if (path.front() == '/') path.remove_prefix(1);
    // Walk parents using pinned directory descriptors. O_NOFOLLOW on only the
    // final component would still follow a symlink in a parent directory.
    for (auto separator = path.find('/'); separator != std::string_view::npos;
         separator = path.find('/')) {
        const auto component = path.substr(0, separator);
        path.remove_prefix(separator + 1);
        if (component.empty() || component == ".") continue;
        const std::string name(component);
        const int next = ::openat(directory.get(), name.c_str(), directory_flags);
        if (next < 0) return -1;
        directory.reset(next);
    }
    if (path.empty()) return -1;
    const std::string name(path);
    Descriptor file(::openat(directory.get(), name.c_str(),
        O_WRONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_CREAT | O_APPEND, 0600));
    if (file.get() < 0) return -1;
    struct stat information{};
    if (::fstat(file.get(), &information) != 0 || !S_ISREG(information.st_mode) ||
        !local_filesystem(file.get())) return -1;
    return file.release();
}

} // namespace

struct FileFlowFeatureSink::State {
    using Record = std::variant<features::FlowFeatureRecord, features::FlowFeatureRecordV2>;
    State(std::string destination, std::size_t max_pending, bool version2)
        : path(std::move(destination)), capacity(max_pending) {
        if (path.empty() || path.find('\0') != std::string::npos) {
            throw std::invalid_argument("flow feature sink path is invalid");
        }
        if (capacity == 0 || capacity > maximum_flow_feature_sink_capacity) {
            throw std::invalid_argument("flow feature sink capacity is invalid");
        }
        pending.resize(capacity);
        auto initialize = [version2](Record& record) {
            if (version2) record = features::FlowFeatureRecordV2{};
            std::visit([](auto& r) { r.engine_instance_id.reserve(maximum_instance_id_bytes); }, record);
        };
        for (auto& record : pending) initialize(record);
        initialize(in_flight);
    }

    void fail_locked() noexcept {
        if (!failed) {
            failed = true;
            ++counters.write_failures;
        }
        counters.records_dropped += depth;
        depth = 0;
        head = tail = 0;
        counters.queue_depth = 0;
        admission_closed = true;
    }

    bool write_line(int fd, std::string_view line, WriteHook hook, void* context) noexcept {
        std::size_t written = 0;
        while (written < line.size()) {
            const auto remaining = line.size() - written;
            const auto count = hook
                ? hook(fd, line.data() + written, remaining, context)
                : static_cast<std::ptrdiff_t>(::write(fd, line.data() + written, remaining));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0 || static_cast<std::size_t>(count) > remaining) return false;
            written += static_cast<std::size_t>(count);
        }
        return true;
    }

    void work() noexcept {
        static_assert(std::is_nothrow_swappable_v<Record>);
        int fd = -1;
        try { fd = open_local_file(path); } catch (...) { /* Generic failure only. */ }
        {
            std::lock_guard lock(mutex);
            if (fd < 0) fail_locked();
            initialized = true;
        }
        changed.notify_all();
        if (fd < 0) return;

        for (;;) {
            WriteHook hook;
            void* context;
            {
                std::unique_lock lock(mutex);
                try {
                    changed.wait(lock, [this] { return depth != 0 || admission_closed; });
                } catch (...) {
                    fail_locked();
                }
                if (depth == 0) break;
                // Swapping preserves the reserved string storage in both the
                // worker record and ring slot; admission never allocates a UUID.
                std::swap(in_flight, pending[head]);
                head = (head + 1) % capacity;
                --depth;
                counters.queue_depth = depth;
                hook = write_hook;
                context = write_context;
            }

            std::string line;
            const auto serialization_started = std::chrono::steady_clock::now();
            bool valid = false;
            try {
                line = std::visit([](const auto& r) { return r.to_json(); }, in_flight);
                // The contract bounds the JSON body; JSONL adds one LF byte.
                if (!line.empty() && line.size() <= features::maximum_flow_feature_record_bytes) {
                    line.push_back('\n');
                    valid = true;
                }
            } catch (...) { /* Bad records do not disable subsequent good data. */ }
            const double serialization_elapsed = seconds_since(serialization_started);
            if (!valid) {
                std::lock_guard lock(mutex);
                counters.serialization_seconds += serialization_elapsed;
                ++counters.validation_failures;
                ++counters.records_dropped;
                continue;
            }

            // No queue mutex spans serialization, the test hook, or any syscall.
            // Regular-file writes may block despite O_NONBLOCK; do not claim a
            // hard deadline for flush()/destruction or detach this worker.
            const auto write_started = std::chrono::steady_clock::now();
            const bool complete = write_line(fd, line, hook, context);
            const double write_elapsed = seconds_since(write_started);
            {
                std::lock_guard lock(mutex);
                counters.serialization_seconds += serialization_elapsed;
                counters.write_seconds += write_elapsed;
                if (complete) {
                    ++counters.records_written;
                } else {
                    ++counters.records_dropped; // The in-flight record, once.
                    fail_locked();             // All pending records, once.
                }
            }
            if (!complete) break;
        }

        // Linux close releases the descriptor even on EINTR; retrying could
        // close an unrelated reused descriptor. A close error is recorded once.
        if (::close(fd) != 0) {
            std::lock_guard lock(mutex);
            fail_locked();
        }
    }

    const std::string path;
    const std::size_t capacity;
    template<class R>
    bool enqueue(const R& record) noexcept {
        {
            std::lock_guard lock(mutex);
            ++counters.records_submitted;
            if (admission_closed) {
                ++counters.records_dropped;
                return false;
            }
            if (depth == capacity) {
                ++counters.records_dropped;
                ++counters.queue_overflows;
                return false;
            }
            // The selected schema stays fixed for this file. Assignment into an
            // existing alternative preserves reserved UUID storage on admission.
            if (!std::holds_alternative<R>(pending[tail])
                || record.engine_instance_id.size() > maximum_instance_id_bytes) {
                ++counters.records_dropped;
                ++counters.validation_failures;
                return false;
            }
            try { std::get<R>(pending[tail]) = record; }
            catch (...) {
                ++counters.records_dropped;
                ++counters.validation_failures;
                return false;
            }
            tail = (tail + 1) % capacity;
            ++depth;
            counters.queue_depth = depth;
            counters.queue_peak_depth = std::max(counters.queue_peak_depth, depth);
        }
        changed.notify_one();
        return true;
    }

    std::vector<Record> pending;
    Record in_flight;
    std::size_t head{0}, tail{0}, depth{0};
    mutable std::mutex mutex;
    std::condition_variable changed;
    std::thread worker;
    bool initialized{false};
    bool admission_closed{false};
    bool failed{false};
    bool flushing{false};
    bool finished{false};
    FlowFeatureSinkStatistics counters;
    WriteHook write_hook{nullptr};
    void* write_context{nullptr};
};

FileFlowFeatureSink::FileFlowFeatureSink(std::string path, std::size_t capacity, bool version2)
    : state_(std::make_unique<State>(std::move(path), capacity, version2)) {
    auto& state = *state_;
    try {
        state.worker = std::thread([pointer = &state] { pointer->work(); });
    } catch (...) {
        std::lock_guard lock(state.mutex);
        state.fail_locked();
        state.initialized = true;
    }
    // Only setup waits for open/validation. Capture-time submit never waits for
    // file I/O, and startup failure is represented by a usable disabled sink.
    std::unique_lock lock(state.mutex);
    state.changed.wait(lock, [&state] { return state.initialized; });
}

FileFlowFeatureSink::~FileFlowFeatureSink() { (void)flush(); }

bool FileFlowFeatureSink::submit(const features::FlowFeatureRecord& record) noexcept {
    return state_->enqueue(record);
}

bool FileFlowFeatureSink::submit_v2(const features::FlowFeatureRecordV2& record) noexcept {
    return state_->enqueue(record);
}

bool FileFlowFeatureSink::flush() noexcept {
    auto& state = *state_;
    {
        std::unique_lock lock(state.mutex);
        state.admission_closed = true;
        state.changed.notify_all();
        if (state.flushing) {
            state.changed.wait(lock, [&state] { return state.finished; });
        }
        if (state.finished) return !state.failed && state.counters.records_dropped == 0;
        state.flushing = true;
    }
    // A single caller owns the join. Others wait without holding the queue lock.
    // The worker owns closing the persistent file descriptor after draining.
    if (state.worker.joinable()) state.worker.join();
    bool success;
    {
        std::lock_guard lock(state.mutex);
        state.finished = true;
        state.flushing = false;
        success = !state.failed && state.counters.records_dropped == 0;
    }
    state.changed.notify_all();
    return success;
}

FlowFeatureSinkStatistics FileFlowFeatureSink::statistics() const noexcept {
    std::lock_guard lock(state_->mutex);
    return state_->counters;
}

bool FileFlowFeatureSink::set_write_hook_for_testing(WriteHook hook, void* context) noexcept {
    std::lock_guard lock(state_->mutex);
    if (state_->counters.records_submitted != 0 || state_->admission_closed) return false;
    state_->write_hook = hook;
    state_->write_context = context;
    return true;
}

} // namespace intriqo::transport
