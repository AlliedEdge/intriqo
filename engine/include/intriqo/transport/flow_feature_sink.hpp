#pragma once

#include "intriqo/features/flow_feature_record.hpp"
#include "intriqo/features/flow_feature_record_v2.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace intriqo::transport {

inline constexpr std::size_t maximum_flow_feature_sink_capacity = 65536;
inline constexpr std::size_t default_flow_feature_sink_capacity = 4096;

struct FlowFeatureSinkStatistics {
    std::uint64_t records_submitted{0}; ///< Every submit attempt, including rejection.
    std::uint64_t records_written{0};   ///< Complete JSONL lines accepted by the kernel.
    std::uint64_t records_dropped{0};    ///< Each lost/rejected record counted exactly once.
    std::uint64_t queue_overflows{0};    ///< Drop-newest admission failures.
    std::uint64_t write_failures{0};     ///< Fatal startup, file, or worker failure (once).
    std::uint64_t validation_failures{0}; ///< Record copy/validation/serialization failures.
    std::uint64_t queue_depth{0};       ///< Pending records, excluding at most one in flight.
    std::uint64_t queue_peak_depth{0};
    double serialization_seconds{0.0}; ///< Worker serialization, including rejected records.
    double write_seconds{0.0};         ///< Worker record writes; excludes drain/join waiting.
};

class FlowFeatureSink {
public:
    virtual ~FlowFeatureSink() = default;
    virtual bool submit(const features::FlowFeatureRecord& record) noexcept = 0;
    virtual bool submit_v2(const features::FlowFeatureRecordV2&) noexcept { return false; }
    virtual bool flush() noexcept { return true; }
    [[nodiscard]] virtual FlowFeatureSinkStatistics statistics() const noexcept { return {}; }
};

namespace detail { struct FileFlowFeatureSinkTestAccess; }

/// Single-use, drop-newest asynchronous local JSONL sink. submit() acknowledges
/// bounded admission only, never delivery. A preallocated ring holds capacity
/// records plus at most one worker record; copying a UUID does not allocate.
/// Serialization/validation and all file operations run on the worker, without
/// holding the queue mutex. A fatal file/worker failure disables writing and
/// counts pending and subsequent records as dropped; it never escapes to capture.
/// Only regular files on recognized local Linux filesystems are accepted. No
/// path component may be a symlink. New files use mode 0600; existing files retain
/// their permissions. Complete writes mean kernel acceptance, not fsync durability.
/// A failed partial write may leave a trailing incomplete line and is not retried.
class FileFlowFeatureSink final : public FlowFeatureSink {
public:
    /// Throws invalid_argument for empty/NUL paths or capacity outside [1, 65536].
    /// Allocation failures may throw. Other startup failures disable the sink and
    /// are visible as write_failures, allowing the caller to continue capture.
    explicit FileFlowFeatureSink(std::string path,
                                std::size_t capacity = default_flow_feature_sink_capacity,
                                bool version2 = false);
    ~FileFlowFeatureSink() override;

    bool submit(const features::FlowFeatureRecord& record) noexcept override;
    bool submit_v2(const features::FlowFeatureRecordV2& record) noexcept override;
    /// Close admission, drain or count every loss, join, and close the descriptor.
    /// Thread-safe and idempotent; true means no recorded loss or fatal failure.
    /// Regular-file I/O (even with O_NONBLOCK) can stall indefinitely: this call
    /// has no hard shutdown deadline and never detaches a still-running worker.
    bool flush() noexcept override;
    [[nodiscard]] FlowFeatureSinkStatistics statistics() const noexcept override;

private:
    struct State;
    std::unique_ptr<State> state_;

    // Narrow syscall seam for deterministic stall/partial-write/failure tests.
    // Installable only before the first submit; not part of the public sink API.
    using WriteHook = std::ptrdiff_t (*)(int, const char*, std::size_t, void*) noexcept;
    bool set_write_hook_for_testing(WriteHook hook, void* context) noexcept;
    friend struct detail::FileFlowFeatureSinkTestAccess;
};

} // namespace intriqo::transport
