#include "intriqo/features/flow_feature_record.hpp"
#include <array>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <limits>
#include <locale>
#include <random>
#include <sstream>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace intriqo::features {
namespace {

[[noreturn]] void invalid(const char* message) {
    throw std::invalid_argument(message);
}

bool canonical_uuid(std::string_view value) noexcept {
    if (value.size() != 36) return false;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return false;
        } else if (!((value[i] >= '0' && value[i] <= '9')
                     || (value[i] >= 'a' && value[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

std::string_view export_reason_name(FlowExportReason reason) {
    switch (reason) {
    case FlowExportReason::idle_expired: return "idle_expired";
    case FlowExportReason::capacity_evicted: return "capacity_evicted";
    case FlowExportReason::shutdown_flush: return "shutdown_flush";
    }
    invalid("invalid flow export reason");
}

std::string_view checked_protocol_name(Protocol protocol) {
    switch (protocol) {
    case Protocol::TCP: return "TCP";
    case Protocol::UDP: return "UDP";
    case Protocol::ICMP: return "ICMP";
    case Protocol::OTHER: return "OTHER";
    }
    invalid("invalid flow network protocol");
}

std::string escaped(std::string_view value) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size());
    for (char character : value) {
        const auto byte = static_cast<unsigned char>(character);
        switch (byte) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (byte < 0x20) {
                result += "\\u00";
                result += hex[byte >> 4];
                result += hex[byte & 0x0f];
            } else {
                result += character;
            }
        }
    }
    return result;
}

std::string format_timestamp(TimePoint timestamp, bool render = true) {
    using Period = Clock::duration::period;
    using Rep = Clock::duration::rep;
    static_assert(std::is_integral_v<Rep> && std::is_signed_v<Rep>
                  && sizeof(Rep) <= sizeof(std::int64_t));
    static_assert(Period::num == 1 && 1'000'000'000 % Period::den == 0,
                  "system_clock must use integral, nanosecond-exact ticks");

    // Do not subtract time_points, or floor by converting whole seconds back
    // to clock ticks: both can overflow at TimePoint::min(). Split ticks first.
    const auto ticks = static_cast<std::int64_t>(timestamp.time_since_epoch().count());
    constexpr std::int64_t ticks_per_second = Period::den;
    auto seconds = ticks / ticks_per_second;
    auto fraction = ticks % ticks_per_second;
    if (fraction < 0) {
        --seconds;
        fraction += ticks_per_second;
    }
    const auto nanoseconds = fraction * (1'000'000'000 / ticks_per_second);
    auto day_count = seconds / 86400;
    auto second_of_day = seconds % 86400;
    if (second_of_day < 0) {
        --day_count;
        second_of_day += 86400;
    }

    using namespace std::chrono;
    constexpr auto first_day = sys_days{year{1} / January / 1}.time_since_epoch().count();
    constexpr auto last_day = sys_days{year{9999} / December / 31}.time_since_epoch().count();
    if (day_count < first_day || day_count > last_day)
        invalid("flow timestamp is outside the RFC3339 year range 0001..9999");
    const year_month_day date{sys_days{days{day_count}}};
    if (!date.ok()) invalid("invalid flow timestamp");

    // Construction validates the native timestamp range without allocating or
    // formatting text. Rendering belongs exclusively to the sink's serializer.
    if (!render) return {};

    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << std::setfill('0') << std::setw(4) << static_cast<int>(date.year())
        << '-' << std::setw(2) << static_cast<unsigned>(date.month())
        << '-' << std::setw(2) << static_cast<unsigned>(date.day())
        << 'T' << std::setw(2) << second_of_day / 3600
        << ':' << std::setw(2) << (second_of_day % 3600) / 60
        << ':' << std::setw(2) << second_of_day % 60
        << '.' << std::setw(9) << nanoseconds << 'Z';
    return out.str();
}

std::pair<std::string, std::string> validate(const FlowFeatureRecord& record, bool render = true) {
    if (!canonical_uuid(record.engine_instance_id))
        invalid("engine instance ID must be a canonical lowercase UUID");
    if (record.flow_id == 0) invalid("flow ID must be nonzero");
    (void)export_reason_name(record.export_reason);
    (void)checked_protocol_name(record.network.protocol);
    if (record.timestamp < record.first_seen)
        invalid("flow timestamps must not be reversed");

    const auto& f = record.features;
    for (double metric : {f.duration_seconds, f.bytes_per_packet,
                          f.packets_per_second, f.bytes_per_second}) {
        if (!std::isfinite(metric) || metric < 0.0)
            invalid("flow metrics must be finite and nonnegative");
    }
    // Subtraction after the bound check avoids uint64 addition wrapping.
    if (record.fwd_packet_count > f.packet_count
        || record.rev_packet_count != f.packet_count - record.fwd_packet_count
        || record.fwd_byte_count > f.byte_count
        || record.rev_byte_count != f.byte_count - record.fwd_byte_count)
        invalid("directional flow counters must equal the totals");
    if ((record.fwd_packet_count == 0 && record.fwd_byte_count != 0)
        || (record.rev_packet_count == 0 && record.rev_byte_count != 0))
        invalid("an empty flow direction cannot contain bytes");
    for (std::uint32_t counter : {f.syn_count, f.fin_count, f.rst_count,
                                 f.initial_syn_count, f.syn_ack_count, f.ack_count}) {
        if (counter > f.packet_count) invalid("TCP counters exceed the packet count");
    }
    if (static_cast<std::uint64_t>(f.initial_syn_count) + f.syn_ack_count > f.syn_count
        || static_cast<std::uint64_t>(f.syn_count) + f.ack_count > f.packet_count)
        invalid("TCP counter subsets exceed their totals");
    if (f.tcp_handshake_started
        && (f.initial_syn_count == 0 || record.fwd_packet_count == 0))
        invalid("a started handshake requires an initial forward SYN");
    if (f.tcp_syn_ack_seen
        && (!f.tcp_handshake_started || f.syn_ack_count == 0
            || record.rev_packet_count == 0))
        invalid("SYN-ACK evidence requires a started handshake and reverse packet");
    if (f.tcp_handshake_completed
        && (!f.tcp_syn_ack_seen || f.ack_count == 0 || record.fwd_packet_count < 2))
        invalid("a completed handshake requires SYN-ACK and forward ACK evidence");
    if (record.network.protocol != Protocol::TCP
        && (f.syn_count != 0 || f.fin_count != 0 || f.rst_count != 0
            || f.initial_syn_count != 0 || f.syn_ack_count != 0 || f.ack_count != 0
            || f.tcp_handshake_started || f.tcp_syn_ack_seen || f.tcp_handshake_completed))
        invalid("non-TCP flows cannot contain TCP counters or handshake evidence");

    return {format_timestamp(record.first_seen, render), format_timestamp(record.timestamp, render)};
}

} // namespace

FlowFeatureRecord FlowFeatureRecord::from_flow(
    const flow::NetworkFlow& flow, std::string_view instance_id, FlowExportReason reason) {
    FlowFeatureRecord record;
    record.engine_instance_id = instance_id;
    record.flow_id = flow.flow_id;
    record.first_seen = flow.first_seen;
    record.timestamp = flow.last_seen;
    record.network = flow.key;
    record.export_reason = reason;
    record.fwd_packet_count = flow.fwd_packet_count;
    record.rev_packet_count = flow.rev_packet_count;
    record.fwd_byte_count = flow.fwd_byte_count;
    record.rev_byte_count = flow.rev_byte_count;

    const auto extracted = FlowFeatures::from_flow(flow);
    auto& f = record.features;
    f.packet_count = extracted.packet_count;
    f.byte_count = extracted.byte_count;
    f.duration_seconds = extracted.duration_seconds;
    f.bytes_per_packet = extracted.bytes_per_packet;
    f.packets_per_second = extracted.packets_per_second;
    f.bytes_per_second = extracted.bytes_per_second;
    f.syn_count = extracted.syn_count;
    f.fin_count = extracted.fin_count;
    f.rst_count = extracted.rst_count;
    f.initial_syn_count = extracted.initial_syn_count;
    f.syn_ack_count = extracted.syn_ack_count;
    f.ack_count = extracted.ack_count;
    f.tcp_handshake_started = extracted.tcp_handshake_started;
    f.tcp_syn_ack_seen = extracted.tcp_syn_ack_seen;
    f.tcp_handshake_completed = extracted.tcp_handshake_completed;
    (void)validate(record, false);
    return record;
}

std::string FlowFeatureRecord::to_json() const {
    const auto [first, last] = validate(*this);
    const auto& f = features;
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << std::setprecision(std::numeric_limits<double>::max_digits10)
        << "{\"schema_version\":\"" << escaped(schema_version)
        << "\",\"metadata\":{\"engine_instance_id\":\"" << escaped(engine_instance_id)
        << "\",\"flow_id\":\"" << flow_id
        << "\",\"first_seen\":\"" << escaped(first)
        << "\",\"timestamp\":\"" << escaped(last)
        << "\",\"export_reason\":\"" << escaped(export_reason_name(export_reason))
        << "\",\"network\":{\"src_ip\":\"" << escaped(network.src_ip.to_string())
        << "\",\"dst_ip\":\"" << escaped(network.dst_ip.to_string())
        << "\",\"src_port\":" << network.src_port
        << ",\"dst_port\":" << network.dst_port
        << ",\"protocol\":\"" << escaped(checked_protocol_name(network.protocol))
        << "\"}},\"features\":{\"packet_count\":" << f.packet_count
        << ",\"byte_count\":" << f.byte_count
        << ",\"duration_seconds\":" << f.duration_seconds
        << ",\"bytes_per_packet\":" << f.bytes_per_packet
        << ",\"packets_per_second\":" << f.packets_per_second
        << ",\"bytes_per_second\":" << f.bytes_per_second
        << ",\"fwd_packet_count\":" << fwd_packet_count
        << ",\"rev_packet_count\":" << rev_packet_count
        << ",\"fwd_byte_count\":" << fwd_byte_count
        << ",\"rev_byte_count\":" << rev_byte_count
        << ",\"syn_count\":" << f.syn_count
        << ",\"fin_count\":" << f.fin_count
        << ",\"rst_count\":" << f.rst_count
        << ",\"initial_syn_count\":" << f.initial_syn_count
        << ",\"syn_ack_count\":" << f.syn_ack_count
        << ",\"ack_count\":" << f.ack_count
        << ",\"tcp_handshake_started\":" << (f.tcp_handshake_started ? "true" : "false")
        << ",\"tcp_syn_ack_seen\":" << (f.tcp_syn_ack_seen ? "true" : "false")
        << ",\"tcp_handshake_completed\":" << (f.tcp_handshake_completed ? "true" : "false")
        << "}}";
    auto result = out.str();
    if (result.size() > maximum_flow_feature_record_bytes)
        throw std::length_error("flow feature record exceeds the v1 size limit");
    return result;
}

std::string make_engine_instance_id() {
    std::random_device random;
    std::array<unsigned char, 16> bytes{};
    for (auto& byte : bytes) byte = static_cast<unsigned char>(random());
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0f) | 0x40);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3f) | 0x80);

    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(36);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) result += '-';
        result += hex[bytes[i] >> 4];
        result += hex[bytes[i] & 0x0f];
    }
    return result;
}

} // namespace intriqo::features
