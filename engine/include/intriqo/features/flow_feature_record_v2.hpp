#pragma once

#include "intriqo/features/flow_feature_record.hpp"

namespace intriqo::features {

struct FlowFeaturesV2 {
    double duration_seconds{0.0};
    std::uint64_t packet_count{0};
    double packets_per_second{0.0};
    double minor_direction_packet_fraction{0.0};
    double mean_ipv4_packet_bytes{0.0};
    double ipv4_direction_byte_imbalance{0.0};
    double syn_packet_fraction{0.0};
    double fin_packet_fraction{0.0};
    double flow_iat_std_seconds{0.0};
};

/// An explicit v2 snapshot. Inherited native counters/metadata are retained as
/// measurement evidence, not additional model inputs. V1 serialization is frozen.
struct FlowFeatureRecordV2 : FlowFeatureRecord {
    static constexpr std::string_view schema_version = "flow_features.v2";
    static constexpr std::string_view iat_policy = "capture_order_nondecreasing_population.v1";
    FlowFeaturesV2 values{};
    std::uint64_t iat_gap_count{0};

    [[nodiscard]] static FlowFeatureRecordV2 from_flow(
        const flow::NetworkFlow&, std::string_view engine_instance_id, FlowExportReason);
    [[nodiscard]] std::string to_json() const;
};

} // namespace intriqo::features
