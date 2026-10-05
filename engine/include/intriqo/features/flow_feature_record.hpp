#pragma once

#include "intriqo/features/features.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace intriqo::features {

enum class FlowExportReason {
    idle_expired,
    capacity_evicted,
    shutdown_flush,
};

inline constexpr std::size_t maximum_flow_feature_record_bytes = 8192;

/// A versioned snapshot of supported measurements at flow retirement.
/// Directions retain the first-observed tuple; byte counts include IPv4 headers.
struct FlowFeatureRecord {
    static constexpr std::string_view schema_version = "flow_features.v1";

    std::string engine_instance_id;
    FlowId flow_id{0};
    TimePoint first_seen{};
    TimePoint timestamp{};
    flow::FlowKey network{};
    FlowExportReason export_reason{FlowExportReason::shutdown_flush};
    FlowFeatures features{};
    std::uint64_t fwd_packet_count{0};
    std::uint64_t rev_packet_count{0};
    std::uint64_t fwd_byte_count{0};
    std::uint64_t rev_byte_count{0};

    /// Throws std::invalid_argument for metadata or measurements outside v1.
    [[nodiscard]] static FlowFeatureRecord from_flow(
        const flow::NetworkFlow& flow, std::string_view engine_instance_id,
        FlowExportReason export_reason);

    /// Deterministic JSON without a trailing newline; validates mutable fields.
    /// The legacy FlowFeatures::connection_attempts member is never exported.
    [[nodiscard]] std::string to_json() const;
};

/// Generate a canonical lowercase version-4 UUID for one engine lifetime.
[[nodiscard]] std::string make_engine_instance_id();

} // namespace intriqo::features
