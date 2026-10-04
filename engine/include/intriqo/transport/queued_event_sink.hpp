#pragma once

#include "intriqo/transport/event_sink.hpp"
#include <cstddef>
#include <memory>

namespace intriqo::transport {

/// Single-use, bounded delivery wrapper. At most capacity events are pending,
/// plus one event being submitted by the worker. The bound is in events, not bytes.
/// Successful submit() means admission; delivery_statistics() reports actual
/// acknowledgments. Rejected submissions and underlying failures are not retried.
/// prepare(), submit(), flush(), error(), and snapshots may run concurrently.
/// The underlying sink must not call back into this wrapper. Destruction drains
/// and joins, so shutdown is bounded by the underlying sink's operation timeouts.
class QueuedEventSink final : public SecurityEventSink {
public:
    /// Throws std::invalid_argument for a null sink or zero capacity.
    QueuedEventSink(std::unique_ptr<SecurityEventSink> sink, std::size_t capacity);
    ~QueuedEventSink() override;

    bool prepare() noexcept override;
    bool submit(const events::SecurityEvent& event) noexcept override;
    /// Close admission, drain every admitted event once, join, and flush the sink.
    /// Repeated calls do not repeat work; false indicates any recorded failure.
    bool flush() noexcept override;
    [[nodiscard]] std::string error() const override;
    [[nodiscard]] std::optional<EventDeliveryStatistics>
    delivery_statistics() const noexcept override;

private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace intriqo::transport
