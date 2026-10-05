#pragma once

#include "intriqo/common/types.hpp"

namespace intriqo::flow {

/// Opt-in v2 measurement, never consulted by flow retirement or detectors.
/// Capture/file order must be nondecreasing within each flow. A late packet
/// invalidates the entire timing measurement; no sorting or gap clipping occurs.
struct FlowIAT {
    bool enabled{false};
    bool valid{true};
    TimePoint previous{};
    std::uint64_t gap_count{0};
    long double mean_ticks{0.0L};
    long double m2_ticks{0.0L};

    void observe(TimePoint timestamp, bool first_packet) noexcept;
    /// Population std; zero for no gaps or one gap. Throws for invalid state.
    [[nodiscard]] double std_seconds() const;
};

} // namespace intriqo::flow
