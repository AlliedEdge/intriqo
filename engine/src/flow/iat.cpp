#include "intriqo/flow/iat.hpp"
#include <cmath>
#include <stdexcept>

namespace intriqo::flow {

void FlowIAT::observe(TimePoint timestamp, bool first_packet) noexcept {
    if (!enabled) return;
    if (first_packet) {
        previous = timestamp;
        return;
    }
    ++gap_count;
    if (timestamp < previous) valid = false;
    if (valid) {
        // Widen integral clock ticks BEFORE subtraction: epoch magnitude must
        // not swallow nanosecond-sized gaps or overflow a signed duration.
        const auto gap = static_cast<long double>(timestamp.time_since_epoch().count())
                       - static_cast<long double>(previous.time_since_epoch().count());
        const auto delta = gap - mean_ticks;
        mean_ticks += delta / static_cast<long double>(gap_count);
        m2_ticks += delta * (gap - mean_ticks);
        if (!std::isfinite(mean_ticks) || !std::isfinite(m2_ticks)) valid = false;
    }
    previous = timestamp;
}

double FlowIAT::std_seconds() const {
    if (!enabled || !valid || !std::isfinite(mean_ticks) || !std::isfinite(m2_ticks)
        || mean_ticks < 0 || m2_ticks < 0)
        throw std::invalid_argument("v2 IAT measurement unavailable or invalid");
    if (gap_count < 2) return 0.0;
    const auto ticks = std::sqrt(m2_ticks / static_cast<long double>(gap_count));
    const auto seconds = ticks * static_cast<long double>(Clock::period::num)
                              / static_cast<long double>(Clock::period::den);
    const auto result = static_cast<double>(seconds);
    if (!std::isfinite(result)) throw std::invalid_argument("v2 IAT is nonfinite");
    return result;
}

} // namespace intriqo::flow
