#include "intriqo/features/flow_feature_record_v2.hpp"
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <limits>
#include <locale>
#include <sstream>
#include <stdexcept>

namespace intriqo::features {
namespace {

double fraction(std::uint64_t part, std::uint64_t total) {
    return total ? static_cast<double>(part) / static_cast<double>(total) : 0.0;
}

FlowFeaturesV2 project(const FlowFeatureRecord& r, double std_seconds) {
    const auto& f = r.features;
    // Subtract the smaller unsigned counter from the larger before conversion.
    const auto difference = std::max(r.fwd_byte_count, r.rev_byte_count)
                          - std::min(r.fwd_byte_count, r.rev_byte_count);
    return {f.duration_seconds, f.packet_count,
        f.duration_seconds > 0 ? static_cast<double>(f.packet_count) / f.duration_seconds : 0.0,
        fraction(std::min(r.fwd_packet_count, r.rev_packet_count), f.packet_count),
        fraction(f.byte_count, f.packet_count), fraction(difference, f.byte_count),
        fraction(f.syn_count, f.packet_count), fraction(f.fin_count, f.packet_count),
        std_seconds};
}

void checked(double actual, double expected) {
    if (!std::isfinite(actual) || actual < 0 || actual != expected)
        throw std::invalid_argument("invalid v2 feature measurement");
}

} // namespace

FlowFeatureRecordV2 FlowFeatureRecordV2::from_flow(
    const flow::NetworkFlow& f, std::string_view instance_id, FlowExportReason reason) {
    FlowFeatureRecordV2 r;
    static_cast<FlowFeatureRecord&>(r) = FlowFeatureRecord::from_flow(f, instance_id, reason);
    r.iat_gap_count = f.iat.gap_count;
    r.values = project(r, f.iat.std_seconds());
    (void)r.to_json();
    return r;
}

std::string FlowFeatureRecordV2::to_json() const {
    // Reuse the exact frozen validator/metadata spelling, not its wire version.
    const auto native = FlowFeatureRecord::to_json();
    flow::NetworkFlow lifespan{};
    lifespan.first_seen = first_seen;
    lifespan.last_seen = timestamp;
    checked(features.duration_seconds, lifespan.duration_seconds());
    const auto expected = project(*this, values.flow_iat_std_seconds);
    if (values.packet_count != features.packet_count
        || iat_gap_count != (features.packet_count ? features.packet_count - 1 : 0))
        throw std::invalid_argument("v2 packet/timing counts disagree");
    checked(values.duration_seconds, expected.duration_seconds);
    checked(values.packets_per_second, expected.packets_per_second);
    checked(values.minor_direction_packet_fraction, expected.minor_direction_packet_fraction);
    checked(values.mean_ipv4_packet_bytes, expected.mean_ipv4_packet_bytes);
    checked(values.ipv4_direction_byte_imbalance, expected.ipv4_direction_byte_imbalance);
    checked(values.syn_packet_fraction, expected.syn_packet_fraction);
    checked(values.fin_packet_fraction, expected.fin_packet_fraction);
    checked(values.flow_iat_std_seconds, expected.flow_iat_std_seconds);
    checked(features.packets_per_second, expected.packets_per_second);
    checked(features.bytes_per_packet, expected.mean_ipv4_packet_bytes);
    checked(features.bytes_per_second,
            features.duration_seconds > 0 ? static_cast<double>(features.byte_count) / features.duration_seconds : 0.0);
    if ((iat_gap_count < 2 && values.flow_iat_std_seconds != 0)
        || values.flow_iat_std_seconds > values.duration_seconds)
        throw std::invalid_argument("v2 timing statistic outside native lifespan");

    const auto split = native.find(",\"features\":");
    auto prefix = native.substr(0, split);
    prefix.replace(prefix.find("flow_features.v1"), std::string_view("flow_features.v1").size(), schema_version);
    // Native features are audit evidence; the nine-dimensional projection is
    // serialized separately. A sink chooses one schema explicitly for its file.
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << std::setprecision(std::numeric_limits<double>::max_digits10)
        << prefix << ",\"measurements\":" << native.substr(split + 12, native.size() - split - 13)
        << ",\"timing\":{\"policy\":\"" << iat_policy << "\",\"gap_count\":" << iat_gap_count
        << "},\"features\":{\"duration_seconds\":" << values.duration_seconds
        << ",\"packet_count\":" << values.packet_count
        << ",\"packets_per_second\":" << values.packets_per_second
        << ",\"minor_direction_packet_fraction\":" << values.minor_direction_packet_fraction
        << ",\"mean_ipv4_packet_bytes\":" << values.mean_ipv4_packet_bytes
        << ",\"ipv4_direction_byte_imbalance\":" << values.ipv4_direction_byte_imbalance
        << ",\"syn_packet_fraction\":" << values.syn_packet_fraction
        << ",\"fin_packet_fraction\":" << values.fin_packet_fraction
        << ",\"flow_iat_std_seconds\":" << values.flow_iat_std_seconds << "}}";
    auto result = out.str();
    if (result.size() > maximum_flow_feature_record_bytes)
        throw std::length_error("v2 feature record exceeds size limit");
    return result;
}

} // namespace intriqo::features
