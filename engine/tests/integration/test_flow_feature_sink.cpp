#include <gtest/gtest.h>
#include "intriqo/transport/flow_feature_sink.hpp"
#include <algorithm>
#include <atomic>
#include <barrier>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <future>
#include <iterator>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <sys/stat.h>
#include <fcntl.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace intriqo::transport::detail {
struct FileFlowFeatureSinkTestAccess {
    using Hook = std::ptrdiff_t (*)(int, const char*, std::size_t, void*) noexcept;
    static bool install(FileFlowFeatureSink& sink, Hook hook, void* context) noexcept {
        return sink.set_write_hook_for_testing(hook, context);
    }
};
} // namespace intriqo::transport::detail

using namespace intriqo;

namespace {
constexpr auto wait_limit = std::chrono::seconds(5);
constexpr auto instance_id = "00112233-4455-4677-8899-aabbccddeeff";
using Sink = transport::FileFlowFeatureSink;
using TestAccess = transport::detail::FileFlowFeatureSinkTestAccess;

struct TemporaryDirectory {
    std::filesystem::path path;
    TemporaryDirectory() {
        auto root = std::filesystem::temp_directory_path();
        if (std::filesystem::is_directory("/tmp/opencode")) root = "/tmp/opencode";
        auto pattern = (root / "intriqo-flow-sink-XXXXXX").string();
        const auto created = ::mkdtemp(pattern.data());
        if (!created) throw std::runtime_error("cannot create sink test directory");
        path = created;
    }
    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
    std::string file(const char* name = "features.jsonl") const { return (path / name).string(); }
};

features::FlowFeatureRecord record(FlowId id,
        features::FlowExportReason reason = features::FlowExportReason::shutdown_flush) {
    flow::NetworkFlow value{};
    value.flow_id = id;
    value.key = {IPv4Address{{10, 0, 0, 1}}, IPv4Address{{10, 0, 0, 2}},
                 12345, 443, Protocol::TCP};
    value.first_seen = TimePoint{std::chrono::seconds{1700000000}};
    value.last_seen = value.first_seen + std::chrono::seconds{1};
    value.packet_count = 2;
    value.byte_count = 80;
    value.fwd_packet_count = value.rev_packet_count = 1;
    value.fwd_byte_count = value.rev_byte_count = 40;
    return features::FlowFeatureRecord::from_flow(value, instance_id, reason);
}

std::string contents(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

struct WriteGate {
    std::mutex mutex;
    std::condition_variable changed;
    bool entered{false}, released{false};
    bool fail{false};
    unsigned calls{0};

    static std::ptrdiff_t write(int fd, const char* bytes, std::size_t count,
                               void* context) noexcept {
        auto& gate = *static_cast<WriteGate*>(context);
        std::unique_lock lock(gate.mutex);
        ++gate.calls;
        gate.entered = true;
        gate.changed.notify_all();
        // A finite guard prevents an assertion failure from hanging the suite.
        // Test ordering depends on explicit entered/released signals, not time.
        if (!gate.changed.wait_for(lock, wait_limit, [&gate] { return gate.released; })) {
            errno = EIO;
            return -1;
        }
        if (gate.fail) { errno = EIO; return -1; }
        lock.unlock();
        return static_cast<std::ptrdiff_t>(::write(fd, bytes, count));
    }
    bool wait_entered() {
        std::unique_lock lock(mutex);
        return changed.wait_for(lock, wait_limit, [this] { return entered; });
    }
    void release() {
        std::lock_guard lock(mutex);
        released = true;
        changed.notify_all();
    }
};

struct ReleaseOnExit {
    WriteGate& gate;
    ~ReleaseOnExit() { gate.release(); }
};

struct ScriptedWrite {
    bool fail_after_partial{false};
    unsigned calls{0};
    static std::ptrdiff_t write(int fd, const char* bytes, std::size_t count,
                               void* context) noexcept {
        auto& script = *static_cast<ScriptedWrite*>(context);
        ++script.calls;
        if (script.calls == 1) { errno = EINTR; return -1; }
        if (script.calls == 2) {
            return static_cast<std::ptrdiff_t>(::write(fd, bytes, std::min(count, std::size_t{7})));
        }
        if (script.fail_after_partial) { errno = EIO; return -1; }
        return static_cast<std::ptrdiff_t>(::write(fd, bytes, count));
    }
};

void expect_accounted(const transport::FlowFeatureSinkStatistics& statistics) {
    EXPECT_EQ(statistics.records_submitted, statistics.records_written + statistics.records_dropped);
    EXPECT_EQ(statistics.queue_depth, 0U);
}
} // namespace

TEST(FlowFeatureSink, WritesActualOrderedJsonlAndCreatesPrivateFile) {
    TemporaryDirectory directory;
    auto sink = std::make_shared<Sink>(directory.file(), 8);
    const auto first = record(1, features::FlowExportReason::idle_expired);
    const auto second = record(2, features::FlowExportReason::capacity_evicted);
    const auto third = record(3);
    ASSERT_TRUE(sink->submit(first));
    ASSERT_TRUE(sink->submit(second));
    ASSERT_TRUE(sink->submit(third));
    ASSERT_TRUE(sink->flush());
    EXPECT_EQ(contents(directory.file()), first.to_json() + '\n' + second.to_json() + '\n'
                                           + third.to_json() + '\n');
    struct stat information{};
    ASSERT_EQ(::stat(directory.file().c_str(), &information), 0);
    EXPECT_EQ(information.st_mode & 0777, 0600U);
    const auto statistics = sink->statistics();
    expect_accounted(statistics);
    EXPECT_EQ(statistics.records_submitted, 3U);
    EXPECT_EQ(statistics.records_written, 3U);
    EXPECT_EQ(statistics.validation_failures, 0U);
    EXPECT_EQ(statistics.write_failures, 0U);
    EXPECT_GT(statistics.serialization_seconds, 0.0);
    EXPECT_GT(statistics.write_seconds, 0.0);
    EXPECT_TRUE(sink->flush());
    EXPECT_EQ(sink->statistics().records_written, 3U);
}

TEST(FlowFeatureSink, AppendsAndKeepsOnePersistentDescriptor) {
    TemporaryDirectory directory;
    const auto first = record(1);
    { std::ofstream output(directory.file()); output << first.to_json() << '\n'; }
    ASSERT_EQ(::chmod(directory.file().c_str(), 0640), 0);
    Sink sink(directory.file(), 2);
    const auto renamed = directory.file("renamed.jsonl");
    std::filesystem::rename(directory.file(), renamed);
    const auto second = record(2);
    ASSERT_TRUE(sink.submit(second));
    ASSERT_TRUE(sink.flush());
    EXPECT_FALSE(std::filesystem::exists(directory.file()));
    EXPECT_EQ(contents(renamed), first.to_json() + '\n' + second.to_json() + '\n');
    struct stat information{};
    ASSERT_EQ(::stat(renamed.c_str(), &information), 0);
    EXPECT_EQ(information.st_mode & 0777, 0640U);
}

TEST(FlowFeatureSink, DestructionDrainsAdmittedRecordsBeforeReturning) {
    TemporaryDirectory directory;
    const auto first = record(1), second = record(2);
    {
        Sink sink(directory.file(), 2);
        ASSERT_TRUE(sink.submit(first));
        ASSERT_TRUE(sink.submit(second));
    }
    EXPECT_EQ(contents(directory.file()), first.to_json() + '\n' + second.to_json() + '\n');
}

TEST(FlowFeatureSink, InvalidConfigurationThrowsWithoutStartingDelivery) {
    TemporaryDirectory directory;
    EXPECT_THROW(Sink(directory.file(), 0), std::invalid_argument);
    EXPECT_THROW(Sink(directory.file(), transport::maximum_flow_feature_sink_capacity + 1),
                 std::invalid_argument);
    EXPECT_THROW(Sink("", 1), std::invalid_argument);
    EXPECT_THROW(Sink(std::string("abc\0def", 7), 1), std::invalid_argument);
    EXPECT_EQ(transport::maximum_flow_feature_sink_capacity, 65536U);
    EXPECT_FALSE(std::filesystem::exists(directory.file()));
}

TEST(FlowFeatureSink, RejectsMissingParentsSymlinksFifoDirectoriesAndDevices) {
    TemporaryDirectory directory;
    const auto target = directory.file("target.jsonl");
    { std::ofstream output(target); output << "unchanged"; }
    const auto link = directory.file("link.jsonl");
    std::filesystem::create_symlink(target, link);
    const auto parent_link = directory.file("parent-link");
    std::filesystem::create_directory_symlink(directory.path, parent_link);
    const auto fifo = directory.file("fifo");
    ASSERT_EQ(::mkfifo(fifo.c_str(), 0600), 0);
    // With a reader present, open succeeds; fstat must still reject the FIFO.
    const int reader = ::open(fifo.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
    ASSERT_GE(reader, 0);
    for (const auto& path : {directory.file("missing/output.jsonl"), link,
                             parent_link + "/target.jsonl", fifo,
                             directory.path.string(), std::string("/dev/null")}) {
        SCOPED_TRACE(path);
        Sink sink(path, 2);
        EXPECT_EQ(sink.statistics().write_failures, 1U);
        EXPECT_FALSE(sink.submit(record(1)));
        EXPECT_FALSE(sink.submit(record(2)));
        EXPECT_FALSE(sink.flush());
        EXPECT_FALSE(sink.flush());
        const auto statistics = sink.statistics();
        expect_accounted(statistics);
        EXPECT_EQ(statistics.records_submitted, 2U);
        EXPECT_EQ(statistics.records_dropped, 2U);
        EXPECT_EQ(statistics.records_written, 0U);
        EXPECT_EQ(statistics.write_failures, 1U);
        EXPECT_EQ(statistics.queue_overflows, 0U);
        EXPECT_EQ(statistics.validation_failures, 0U);
    }
    char byte;
    EXPECT_EQ(::read(reader, &byte, 1), -1);
    EXPECT_EQ(errno, EAGAIN);
    (void)::close(reader);
    EXPECT_EQ(contents(target), "unchanged");
}

TEST(FlowFeatureSink, BoundedDropNewestAndConcurrentSnapshotsAndFlush) {
    TemporaryDirectory directory;
    WriteGate gate;
    Sink sink(directory.file(), 2);
    ReleaseOnExit cleanup{gate};
    ASSERT_TRUE(TestAccess::install(sink, &WriteGate::write, &gate));
    const auto first = record(1), second = record(2), third = record(3);
    ASSERT_TRUE(sink.submit(first));
    ASSERT_TRUE(gate.wait_entered());
    EXPECT_EQ(sink.statistics().records_written, 0U); // Admission is not delivery.
    ASSERT_TRUE(sink.submit(second));
    ASSERT_TRUE(sink.submit(third));
    EXPECT_FALSE(sink.submit(record(4)));
    auto statistics = sink.statistics();
    EXPECT_EQ(statistics.records_submitted, 4U);
    EXPECT_EQ(statistics.records_dropped, 1U);
    EXPECT_EQ(statistics.queue_depth, 2U);
    EXPECT_EQ(statistics.queue_peak_depth, 2U);
    EXPECT_EQ(statistics.queue_overflows, 1U);
    EXPECT_EQ(statistics.write_failures, 0U);
    // Snapshot progress while the worker is stalled proves the queue lock is
    // not held across file writing or the hook.
    auto snapshots = std::async(std::launch::async, [&sink] {
        for (unsigned i = 0; i < 2000; ++i) {
            if (sink.statistics().queue_depth != 2) return false;
        }
        return true;
    });
    ASSERT_EQ(snapshots.wait_for(wait_limit), std::future_status::ready);
    EXPECT_TRUE(snapshots.get());
    auto first_flush = std::async(std::launch::async, [&sink] { return sink.flush(); });
    auto second_flush = std::async(std::launch::async, [&sink] { return sink.flush(); });
    EXPECT_EQ(first_flush.wait_for(std::chrono::seconds{0}), std::future_status::timeout);
    EXPECT_EQ(second_flush.wait_for(std::chrono::seconds{0}), std::future_status::timeout);
    EXPECT_EQ(contents(directory.file()), "");
    gate.release();
    ASSERT_EQ(first_flush.wait_for(wait_limit), std::future_status::ready);
    ASSERT_EQ(second_flush.wait_for(wait_limit), std::future_status::ready);
    EXPECT_FALSE(first_flush.get()); // The one overflow is visible, not recounted.
    EXPECT_FALSE(second_flush.get());
    statistics = sink.statistics();
    expect_accounted(statistics);
    EXPECT_EQ(statistics.records_written, 3U);
    EXPECT_EQ(statistics.records_dropped, 1U);
    EXPECT_EQ(statistics.queue_peak_depth, 2U);
    EXPECT_EQ(contents(directory.file()), first.to_json() + '\n' + second.to_json() + '\n'
                                           + third.to_json() + '\n');
    EXPECT_FALSE(sink.submit(record(5)));
    EXPECT_FALSE(sink.flush());
    statistics = sink.statistics();
    expect_accounted(statistics);
    EXPECT_EQ(statistics.records_submitted, 5U);
    EXPECT_EQ(statistics.records_dropped, 2U);
    EXPECT_EQ(statistics.queue_overflows, 1U);
    EXPECT_EQ(statistics.write_failures, 0U);
}

TEST(FlowFeatureSink, FailedWriteDropsInFlightPendingAndFutureWithoutRetryOrRecount) {
    TemporaryDirectory directory;
    WriteGate gate;
    gate.fail = true;
    Sink sink(directory.file(), 2);
    ReleaseOnExit cleanup{gate};
    ASSERT_TRUE(TestAccess::install(sink, &WriteGate::write, &gate));
    ASSERT_TRUE(sink.submit(record(1)));
    ASSERT_TRUE(gate.wait_entered());
    ASSERT_TRUE(sink.submit(record(2)));
    ASSERT_TRUE(sink.submit(record(3)));
    EXPECT_FALSE(sink.submit(record(4)));
    gate.release();
    EXPECT_FALSE(sink.flush());
    auto statistics = sink.statistics();
    expect_accounted(statistics);
    EXPECT_EQ(statistics.records_submitted, 4U);
    EXPECT_EQ(statistics.records_dropped, 4U);
    EXPECT_EQ(statistics.records_written, 0U);
    EXPECT_EQ(statistics.write_failures, 1U);
    EXPECT_EQ(statistics.queue_overflows, 1U);
    EXPECT_EQ(gate.calls, 1U);
    EXPECT_FALSE(sink.submit(record(5)));
    EXPECT_FALSE(sink.flush());
    EXPECT_FALSE(sink.flush());
    statistics = sink.statistics();
    expect_accounted(statistics);
    EXPECT_EQ(statistics.records_dropped, 5U);
    EXPECT_EQ(statistics.write_failures, 1U);
    EXPECT_EQ(statistics.validation_failures, 0U);
    EXPECT_EQ(gate.calls, 1U);
    EXPECT_EQ(contents(directory.file()), "");
}

TEST(FlowFeatureSink, HandlesEintrAndPartialWritesAndDoesNotRetryAfterFatalFailure) {
    TemporaryDirectory directory;
    const auto value = record(1);
    for (bool fail_after_partial : {false, true}) {
        ScriptedWrite script;
        script.fail_after_partial = fail_after_partial;
        const auto path = directory.file(fail_after_partial ? "partial.jsonl" : "complete.jsonl");
        Sink sink(path, 2);
        ASSERT_TRUE(TestAccess::install(sink, &ScriptedWrite::write, &script));
        ASSERT_TRUE(sink.submit(value));
        EXPECT_EQ(sink.flush(), !fail_after_partial);
        EXPECT_EQ(script.calls, 3U);
        const auto statistics = sink.statistics();
        expect_accounted(statistics);
        EXPECT_EQ(statistics.records_written, fail_after_partial ? 0U : 1U);
        EXPECT_EQ(statistics.records_dropped, fail_after_partial ? 1U : 0U);
        EXPECT_EQ(statistics.write_failures, fail_after_partial ? 1U : 0U);
        EXPECT_EQ(contents(path), fail_after_partial ? value.to_json().substr(0, 7)
                                                    : value.to_json() + '\n');
        EXPECT_EQ(sink.flush(), !fail_after_partial);
        EXPECT_EQ(script.calls, 3U);
    }
}

TEST(FlowFeatureSink, InvalidRecordsAreBoundedAndDoNotDisableRemainingGoodData) {
    TemporaryDirectory directory;
    Sink sink(directory.file(), 8);
    const auto first = record(1), last = record(5);
    auto bad_uuid = record(2);
    bad_uuid.engine_instance_id = "invalid";
    auto bad_number = record(3);
    bad_number.features.bytes_per_second = std::numeric_limits<double>::infinity();
    auto oversized = record(4);
    oversized.engine_instance_id.assign(features::maximum_flow_feature_record_bytes + 1, 'a');
    ASSERT_TRUE(sink.submit(first));
    ASSERT_TRUE(sink.submit(bad_uuid));
    ASSERT_TRUE(sink.submit(bad_number));
    EXPECT_FALSE(sink.submit(oversized));
    ASSERT_TRUE(sink.submit(last));
    EXPECT_FALSE(sink.flush());
    const auto statistics = sink.statistics();
    expect_accounted(statistics);
    EXPECT_EQ(statistics.records_submitted, 5U);
    EXPECT_EQ(statistics.records_written, 2U);
    EXPECT_EQ(statistics.records_dropped, 3U);
    EXPECT_EQ(statistics.validation_failures, 3U);
    EXPECT_EQ(statistics.write_failures, 0U);
    EXPECT_EQ(statistics.queue_overflows, 0U);
    EXPECT_EQ(contents(directory.file()), first.to_json() + '\n' + last.to_json() + '\n');
}

TEST(FlowFeatureSink, ConcurrentAdmissionSnapshotsAndClosingAccountForEveryAttempt) {
    TemporaryDirectory directory;
    Sink sink(directory.file(), 16);
    std::barrier begin(4);
    std::atomic<bool> snapshot_ok{true};
    auto submit = [&sink, &begin](FlowId offset) {
        const auto value = record(offset);
        begin.arrive_and_wait();
        for (unsigned i = 0; i < 1000; ++i) (void)sink.submit(value);
    };
    std::thread first(submit, 1);
    std::thread second(submit, 2);
    std::thread snapshots([&] {
        begin.arrive_and_wait();
        for (unsigned i = 0; i < 2000; ++i) {
            const auto statistics = sink.statistics();
            if (statistics.queue_depth > 16 || statistics.queue_peak_depth > 16 ||
                statistics.records_written + statistics.records_dropped > statistics.records_submitted) {
                snapshot_ok = false;
            }
        }
    });
    begin.arrive_and_wait();
    (void)sink.flush();
    first.join();
    second.join();
    snapshots.join();
    EXPECT_TRUE(snapshot_ok.load());
    const auto statistics = sink.statistics();
    expect_accounted(statistics);
    EXPECT_EQ(statistics.records_submitted, 2000U);
    EXPECT_EQ(statistics.write_failures, 0U);
    EXPECT_EQ(statistics.validation_failures, 0U);
    std::ifstream input(directory.file());
    std::string line;
    std::uint64_t lines = 0;
    const auto first_json = record(1).to_json(), second_json = record(2).to_json();
    while (std::getline(input, line)) {
        EXPECT_TRUE(line == first_json || line == second_json);
        EXPECT_LT(line.size(), features::maximum_flow_feature_record_bytes);
        ++lines;
    }
    EXPECT_EQ(lines, statistics.records_written);
}
