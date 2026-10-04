/// Deterministic unit tests for the planned SYN-flood detector.

#include <gtest/gtest.h>

#include "intriqo/detection/syn_flood_detector.hpp"

#include <atomic>
#include <barrier>
#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <thread>
#include <variant>
#include <vector>

using namespace intriqo;

namespace {

const IPv4Address kSource{{10, 0, 0, 1}};
const IPv4Address kOtherSource{{10, 0, 0, 2}};
const IPv4Address kDestination{{192, 0, 2, 10}};
const IPv4Address kOtherDestination{{192, 0, 2, 11}};

// A fixed epoch keeps event timestamps and all event-time decisions stable.
TimePoint at_ms(std::int64_t offset_ms) {
    return TimePoint{std::chrono::milliseconds{1'700'000'000'000LL + offset_ms}};
}

template <typename Config>
void set_minimum_attempts(Config& config, std::size_t value) {
    if constexpr (requires { config.minimum_syn_attempts; }) {
        config.minimum_syn_attempts = value;
    } else {
        config.minimum_attempts = value;
    }
}

template <typename Config>
void set_minimum_rate(Config& config, double value) {
    if constexpr (requires { config.minimum_syn_rate; }) {
        config.minimum_syn_rate = value;
    } else {
        config.minimum_rate_per_second = value;
    }
}

template <typename Config>
void set_incomplete_ratio(Config& config, double value) {
    if constexpr (requires { config.minimum_incomplete_ratio; }) {
        config.minimum_incomplete_ratio = value;
    } else {
        config.incomplete_ratio_threshold = value;
    }
}

template <typename Config>
void set_max_sources(Config& config, std::size_t value) {
    if constexpr (requires { config.max_tracked_sources; }) {
        config.max_tracked_sources = value;
    } else {
        config.max_tracked_buckets = value;
    }
}

detection::SynFloodConfig test_config() {
    detection::SynFloodConfig config;
    config.window_seconds = 10.0;
    set_minimum_attempts(config, 4);
    set_minimum_rate(config, 2.0);
    set_incomplete_ratio(config, 0.75);
    config.minimum_incomplete_handshakes = 3;
    config.severity = events::Severity::HIGH;
    config.cooldown_seconds = 5.0;
    set_max_sources(config, 16);
    config.max_tracked_flows = 64;
    config.minimum_observation_seconds = 0.1;
    return config;
}

flow::NetworkFlow make_flow(FlowId id,
                            std::int64_t offset_ms,
                            Protocol protocol = Protocol::TCP,
                            IPv4Address source = kSource,
                            IPv4Address destination = kDestination,
                            bool completed = false) {
    flow::NetworkFlow flow;
    flow.flow_id = id;
    flow.key = flow::FlowKey{
        source,
        destination,
        static_cast<Port>(40'000u + static_cast<unsigned>(id % 1'000u)),
        static_cast<Port>(443),
        protocol};
    flow.first_seen = at_ms(offset_ms);
    flow.last_seen = at_ms(offset_ms);
    flow.packet_count = completed ? 3u : 2u;
    // A completed handshake has the initial SYN plus a SYN-ACK; a half-open
    // attempt has only the initial SYN.  ACK is tracked separately.
    flow.syn_count = completed ? 2u : 1u;
    flow.initial_syn_count = 1u;
    flow.syn_ack_count = completed ? 1u : 0u;
    flow.ack_count = completed ? 1u : 0u;
    flow.tcp_handshake_started = true;
    flow.tcp_syn_ack_seen = completed;
    flow.tcp_handshake_completed = completed;
    return flow;
}

std::vector<events::SecurityEvent> evaluate_incomplete(
    detection::SynFloodDetector& detector,
    FlowId id,
    std::int64_t offset_ms,
    IPv4Address source = kSource,
    IPv4Address destination = kDestination) {
    return detector.evaluate(make_flow(id, offset_ms, Protocol::TCP, source, destination), {});
}

const events::MetadataValue* detail(const events::SecurityEvent& event, const std::string& key) {
    const auto found = event.details.find(key);
    return found == event.details.end() ? nullptr : &found->second;
}

void expect_no_event(detection::SynFloodDetector& detector,
                     FlowId id,
                     std::int64_t offset_ms,
                     IPv4Address source = kSource,
                     IPv4Address destination = kDestination) {
    EXPECT_TRUE(evaluate_incomplete(detector, id, offset_ms, source, destination).empty());
}

} // namespace

TEST(SynFloodDetector, ReportsExpectedName) {
    detection::SynFloodDetector detector(test_config());

    EXPECT_EQ(detector.name(), "syn_flood");
}

TEST(SynFloodDetector, NormalCompletedTcpHandshakeDoesNotTrigger) {
    auto config = test_config();
    set_minimum_rate(config, 0.1);
    detection::SynFloodDetector detector(config);

    for (FlowId id = 1; id <= 4; ++id) {
        auto completed = make_flow(id, static_cast<std::int64_t>((id - 1) * 1'000),
                                   Protocol::TCP, kSource, kDestination, true);
        EXPECT_TRUE(detector.evaluate(completed, {}).empty());
    }

    const auto statistics = detector.statistics();
    EXPECT_EQ(statistics.observations, 4u);
    EXPECT_EQ(statistics.detections, 0u);
    EXPECT_EQ(statistics.state_sources, 1u);
    EXPECT_EQ(statistics.state_observations, 4u);
    EXPECT_EQ(statistics.peak_sources, 1u);
    EXPECT_EQ(statistics.peak_observations, 4u);
    EXPECT_EQ(statistics.errors, 0u);
}

TEST(SynFloodDetector, SmallBurstStaysBelowThreshold) {
    detection::SynFloodDetector detector(test_config());

    expect_no_event(detector, 1, 0);
    expect_no_event(detector, 2, 200);
    expect_no_event(detector, 3, 400);

    const auto statistics = detector.statistics();
    EXPECT_EQ(statistics.observations, 3u);
    EXPECT_EQ(statistics.detections, 0u);
    EXPECT_EQ(statistics.state_sources, 1u);
    EXPECT_EQ(statistics.state_observations, 3u);
}

TEST(SynFloodDetector, SustainedHighRateIncompleteAttemptsTrigger) {
    auto config = test_config();
    set_minimum_rate(config, 2.0);
    set_incomplete_ratio(config, 0.75);
    config.minimum_incomplete_handshakes = 3;
    detection::SynFloodDetector detector(config);

    expect_no_event(detector, 1, 0);
    expect_no_event(detector, 2, 200);
    expect_no_event(detector, 3, 400);
    const auto generated = evaluate_incomplete(detector, 4, 600);

    ASSERT_EQ(generated.size(), 1u);
    EXPECT_EQ(generated.front().event_type, events::EventType::SYN_FLOOD);
    EXPECT_EQ(detector.statistics().detections, 1u);
}

TEST(SynFloodDetector, HighIncompleteRatioTriggers) {
    auto config = test_config();
    set_minimum_rate(config, 0.1);
    set_incomplete_ratio(config, 0.75);
    config.minimum_incomplete_handshakes = 3;
    detection::SynFloodDetector detector(config);

    expect_no_event(detector, 1, 0);
    expect_no_event(detector, 2, 3'000);
    expect_no_event(detector, 3, 6'000);
    const auto generated = evaluate_incomplete(detector, 4, 9'000);

    ASSERT_EQ(generated.size(), 1u);
    EXPECT_EQ(generated.front().event_type, events::EventType::SYN_FLOOD);
}

TEST(SynFloodDetector, CompletedHandshakesLowerSuspicion) {
    auto config = test_config();
    set_minimum_rate(config, 0.1);
    set_incomplete_ratio(config, 0.75);
    config.minimum_incomplete_handshakes = 3;
    detection::SynFloodDetector detector(config);

    for (FlowId id = 1; id <= 3; ++id) {
        auto completed = make_flow(id, static_cast<std::int64_t>((id - 1) * 3'000),
                                   Protocol::TCP, kSource, kDestination, true);
        EXPECT_TRUE(detector.evaluate(completed, {}).empty());
    }
    expect_no_event(detector, 4, 9'000);
    EXPECT_EQ(detector.statistics().detections, 0u);

    // The same attempt volume with no completed handshakes is suspicious.
    detection::SynFloodDetector comparison(config);
    expect_no_event(comparison, 101, 0, kOtherSource, kDestination);
    expect_no_event(comparison, 102, 3'000, kOtherSource, kDestination);
    expect_no_event(comparison, 103, 6'000, kOtherSource, kDestination);
    ASSERT_EQ(evaluate_incomplete(comparison, 104, 9'000, kOtherSource, kDestination).size(), 1u);
}

TEST(SynFloodDetector, IsolatesSourcesAndDestinations) {
    auto config = test_config();
    set_minimum_attempts(config, 3);
    set_minimum_rate(config, 0.1);
    config.cooldown_seconds = 0.001;
    detection::SynFloodDetector detector(config);

    // Two observations in each bucket must not combine across either key.
    expect_no_event(detector, 1, 0, kSource, kDestination);
    expect_no_event(detector, 2, 100, kSource, kDestination);
    expect_no_event(detector, 3, 0, kOtherSource, kDestination);
    expect_no_event(detector, 4, 100, kOtherSource, kDestination);
    expect_no_event(detector, 5, 0, kSource, kOtherDestination);
    expect_no_event(detector, 6, 100, kSource, kOtherDestination);
    EXPECT_EQ(detector.statistics().detections, 0u);

    ASSERT_EQ(evaluate_incomplete(detector, 7, 200, kSource, kDestination).size(), 1u);
    ASSERT_EQ(evaluate_incomplete(detector, 8, 200, kOtherSource, kDestination).size(), 1u);
    ASSERT_EQ(evaluate_incomplete(detector, 9, 200, kSource, kOtherDestination).size(), 1u);
}

TEST(SynFloodDetector, ExpireRemovesOldBucketAndStartsFreshWindow) {
    auto config = test_config();
    config.window_seconds = 5.0;
    set_minimum_rate(config, 0.1);
    detection::SynFloodDetector detector(config);

    expect_no_event(detector, 1, 0);
    expect_no_event(detector, 2, 1'000);
    ASSERT_EQ(detector.statistics().state_sources, 1u);

    detector.expire(at_ms(6'001));
    auto after_expire = detector.statistics();
    EXPECT_EQ(after_expire.state_sources, 0u);
    EXPECT_EQ(after_expire.expired_sources, 1u);

    expect_no_event(detector, 3, 6'002);
    const auto after_new_window = detector.statistics();
    EXPECT_EQ(after_new_window.state_sources, 1u);
    EXPECT_EQ(after_new_window.state_observations, 3u);
    EXPECT_EQ(after_new_window.state_rejections, 0u);
}

TEST(SynFloodDetector, ExpiresRetainedFlowIdentityWhenCallerNeverRetiresIt) {
    auto config = test_config();
    config.window_seconds = 1.0;
    config.state_expiration_seconds = 1.0;
    detection::SynFloodDetector detector(config);

    expect_no_event(detector, 1, 0);
    detector.expire(at_ms(2'001));
    const auto statistics = detector.statistics();
    EXPECT_EQ(statistics.state_observations, 0u);
    EXPECT_EQ(statistics.expired_observations, 1u);
}

TEST(SynFloodDetector, AFlowStartingWithSynAckIsNotCountedAsAnInitialAttempt) {
    detection::SynFloodDetector detector(test_config());
    auto response = make_flow(1, 0);
    response.initial_syn_count = 0;
    response.syn_count = 1;
    response.syn_ack_count = 1;
    response.ack_count = 0;
    response.tcp_handshake_started = false;
    response.tcp_syn_ack_seen = false;
    response.tcp_handshake_completed = false;

    EXPECT_TRUE(detector.evaluate(response, {}).empty());
    EXPECT_EQ(detector.statistics().observations, 0u);
}

TEST(SynFloodDetector, RejectsNewSourceWhenSourceBucketCapacityIsFull) {
    auto config = test_config();
    set_max_sources(config, 1);
    config.max_tracked_flows = 8;
    detection::SynFloodDetector detector(config);

    expect_no_event(detector, 1, 0, kSource, kDestination);
    expect_no_event(detector, 2, 0, kOtherSource, kDestination);

    const auto statistics = detector.statistics();
    EXPECT_EQ(statistics.observations, 1u);
    EXPECT_EQ(statistics.state_sources, 1u);
    EXPECT_EQ(statistics.state_observations, 1u);
    EXPECT_EQ(statistics.peak_sources, 1u);
    EXPECT_EQ(statistics.state_rejections, 1u);
}

TEST(SynFloodDetector, RejectsFlowsWhenFlowCapacityIsFull) {
    auto config = test_config();
    set_max_sources(config, 4);
    config.max_tracked_flows = 2;
    detection::SynFloodDetector detector(config);

    expect_no_event(detector, 1, 0);
    expect_no_event(detector, 2, 100);
    expect_no_event(detector, 3, 200);

    const auto statistics = detector.statistics();
    EXPECT_EQ(statistics.observations, 2u);
    EXPECT_EQ(statistics.state_observations, 2u);
    EXPECT_EQ(statistics.peak_observations, 2u);
    EXPECT_EQ(statistics.state_rejections, 1u);
}

TEST(SynFloodDetector, SuppressesDuplicatesDuringCooldownAndAllowsLaterEvidence) {
    auto config = test_config();
    config.window_seconds = 1.0;
    set_minimum_attempts(config, 3);
    set_minimum_rate(config, 0.1);
    config.cooldown_seconds = 5.0;
    detection::SynFloodDetector detector(config);

    expect_no_event(detector, 1, 0);
    expect_no_event(detector, 2, 100);
    ASSERT_EQ(evaluate_incomplete(detector, 3, 200).size(), 1u);

    // The same flow is deduplicated, and a new flow in this emitted bucket is quiet.
    EXPECT_TRUE(evaluate_incomplete(detector, 3, 1'000).empty());
    EXPECT_TRUE(evaluate_incomplete(detector, 4, 1'000).empty());
    EXPECT_EQ(detector.statistics().detections, 1u);

    // A fresh bucket is also suppressed while the prior alert is cooling down.
    detector.expire(at_ms(1'201));
    expect_no_event(detector, 5, 2'000);
    expect_no_event(detector, 6, 2'100);
    EXPECT_TRUE(evaluate_incomplete(detector, 7, 2'200).empty());
    EXPECT_EQ(detector.statistics().detections, 1u);

    // After cooldown and another bucket boundary, the same evidence is emitted.
    detector.expire(at_ms(6'001));
    expect_no_event(detector, 8, 7'000);
    expect_no_event(detector, 9, 7'100);
    ASSERT_EQ(evaluate_incomplete(detector, 10, 7'200).size(), 1u);
    EXPECT_EQ(detector.statistics().detections, 2u);
}

TEST(SynFloodDetector, IgnoresMalformedDefaultAndNonTcpInputSafely) {
    detection::SynFloodDetector detector(test_config());

    flow::NetworkFlow default_flow;
    std::vector<events::SecurityEvent> default_result;
    EXPECT_NO_THROW(default_result = detector.evaluate(default_flow, {}));
    EXPECT_TRUE(default_result.empty());

    auto udp = make_flow(1, 0, Protocol::UDP);
    auto other = make_flow(2, 0, Protocol::OTHER);
    auto no_destination_port = make_flow(3, 0);
    no_destination_port.key.dst_port = 0;
    auto same_endpoint = make_flow(4, 0, Protocol::TCP, kSource, kSource);

    EXPECT_TRUE(detector.evaluate(udp, {}).empty());
    EXPECT_TRUE(detector.evaluate(other, {}).empty());
    EXPECT_TRUE(detector.evaluate(no_destination_port, {}).empty());
    EXPECT_TRUE(detector.evaluate(same_endpoint, {}).empty());

    const auto statistics = detector.statistics();
    EXPECT_EQ(statistics.detections, 0u);
    EXPECT_EQ(statistics.errors, 0u);
}

TEST(SynFloodDetector, EventEvidenceJsonAndStatisticsAreDeterministic) {
    auto config = test_config();
    set_minimum_rate(config, 0.1);
    detection::SynFloodDetector detector(config);

    expect_no_event(detector, 1, 0);
    expect_no_event(detector, 2, 100);
    expect_no_event(detector, 3, 200);
    const auto generated = evaluate_incomplete(detector, 4, 300);

    ASSERT_EQ(generated.size(), 1u);
    const auto& event = generated.front();
    EXPECT_EQ(event.event_type, events::EventType::SYN_FLOOD);
    EXPECT_EQ(event.severity, events::Severity::HIGH);
    EXPECT_EQ(event.source_address, kSource);
    EXPECT_EQ(event.destination_address, kDestination);
    EXPECT_EQ(event.timestamp, at_ms(300));
    EXPECT_EQ(event.event_id.size(), 36u);

    // Evidence is structured, rather than inferred from the human description.
    ASSERT_NE(detail(event, "connection_attempts"), nullptr);
    ASSERT_NE(detail(event, "incomplete_handshakes"), nullptr);
    ASSERT_NE(detail(event, "incomplete_ratio"), nullptr);
    ASSERT_NE(detail(event, "rate_per_second"), nullptr);
    ASSERT_NE(detail(event, "window_seconds"), nullptr);
    ASSERT_NE(detail(event, "detector"), nullptr);
    const auto* attempts = std::get_if<std::int64_t>(detail(event, "connection_attempts"));
    ASSERT_NE(attempts, nullptr);
    EXPECT_EQ(*attempts, 4);
    const auto* incomplete = std::get_if<std::int64_t>(detail(event, "incomplete_handshakes"));
    ASSERT_NE(incomplete, nullptr);
    EXPECT_EQ(*incomplete, 4);
    const auto* syn_acks = std::get_if<std::int64_t>(detail(event, "syn_ack_count"));
    ASSERT_NE(syn_acks, nullptr);
    EXPECT_EQ(*syn_acks, 0);
    const auto* acks = std::get_if<std::int64_t>(detail(event, "completed_handshakes"));
    ASSERT_NE(acks, nullptr);
    EXPECT_EQ(*acks, 0);

    const auto json = event.to_json();
    EXPECT_NE(json.find("\"event_id\""), std::string::npos);
    EXPECT_NE(json.find("\"event_type\":\"SYN_FLOOD\""), std::string::npos);
    EXPECT_NE(json.find("\"severity\":\"HIGH\""), std::string::npos);
    EXPECT_NE(json.find("\"source_address\":\"10.0.0.1\""), std::string::npos);
    EXPECT_NE(json.find("\"destination_address\":\"192.0.2.10\""), std::string::npos);
    EXPECT_NE(json.find("\"connection_attempts\""), std::string::npos);
    EXPECT_NE(json.find("\"syn_ack_count\""), std::string::npos);
    EXPECT_NE(json.find("\"completed_handshakes\""), std::string::npos);
    EXPECT_NE(json.find("\"incomplete_handshakes\""), std::string::npos);
    EXPECT_NE(json.find("\"incomplete_ratio\""), std::string::npos);

    const auto statistics = detector.statistics();
    EXPECT_EQ(statistics.observations, 4u);
    EXPECT_EQ(statistics.detections, 1u);
    EXPECT_EQ(statistics.state_sources, 1u);
    EXPECT_EQ(statistics.state_observations, 4u);
    EXPECT_EQ(statistics.peak_sources, 1u);
    EXPECT_EQ(statistics.peak_observations, 4u);
    EXPECT_EQ(statistics.state_rejections, 0u);
    EXPECT_EQ(statistics.syn_observations, 4u);
    EXPECT_EQ(statistics.syn_ack_observations, 0u);
    EXPECT_EQ(statistics.ack_completions, 0u);
    EXPECT_EQ(statistics.incomplete_handshakes, 4u);
    EXPECT_EQ(statistics.errors, 0u);
}

TEST(SynFloodDetector, ResetClearsLiveStateButRetainsCounters) {
    auto config = test_config();
    set_minimum_rate(config, 0.1);
    detection::SynFloodDetector detector(config);

    expect_no_event(detector, 1, 0);
    const auto before_reset = detector.statistics();
    EXPECT_EQ(before_reset.observations, 1u);
    EXPECT_EQ(before_reset.state_sources, 1u);
    EXPECT_EQ(before_reset.state_observations, 1u);

    detector.reset();
    const auto after_reset = detector.statistics();
    EXPECT_EQ(after_reset.observations, 1u);
    EXPECT_EQ(after_reset.state_sources, 0u);
    EXPECT_EQ(after_reset.state_observations, 0u);
    EXPECT_EQ(after_reset.peak_sources, 1u);
    EXPECT_EQ(after_reset.peak_observations, 1u);

    // Reset releases both the old bucket and its flow identity.
    expect_no_event(detector, 1, 0);
    EXPECT_EQ(detector.statistics().observations, 2u);
}

TEST(SynFloodDetector, RetireFlowReleasesDeduplicationIdentity) {
    auto config = test_config();
    set_minimum_rate(config, 0.1);
    detection::SynFloodDetector detector(config);

    expect_no_event(detector, 7, 0);
    EXPECT_TRUE(evaluate_incomplete(detector, 7, 100).empty());
    EXPECT_EQ(detector.statistics().observations, 1u);

    detector.retire_flow(7);
    EXPECT_TRUE(evaluate_incomplete(detector, 7, 200).empty());
    const auto statistics = detector.statistics();
    EXPECT_EQ(statistics.observations, 2u);
    EXPECT_EQ(statistics.state_observations, 1u);
    EXPECT_EQ(statistics.state_rejections, 0u);
}

TEST(SynFloodDetector, ConcurrentEvaluateStatisticsAndRetireAreSafe) {
    auto config = test_config();
    set_minimum_attempts(config, 1'000);
    set_minimum_rate(config, 1'000.0);
    config.minimum_incomplete_handshakes = 1'000;
    set_max_sources(config, 4);
    config.max_tracked_flows = 128;
    detection::SynFloodDetector detector(config);

    constexpr int kRounds = 32;
    constexpr FlowId kSecondWorkerBase = 1'000;
    std::barrier round_start(4);
    std::atomic<bool> failed{false};

    auto evaluate_worker = [&](FlowId base, IPv4Address source) {
        for (int round = 0; round < kRounds; ++round) {
            round_start.arrive_and_wait();
            try {
                if (!detector.evaluate(
                         make_flow(base + static_cast<FlowId>(round), round * 10,
                                   Protocol::TCP, source, kDestination),
                         {})
                         .empty()) {
                    failed.store(true, std::memory_order_relaxed);
                }
            } catch (...) {
                failed.store(true, std::memory_order_relaxed);
            }
            round_start.arrive_and_wait();
        }
    };

    std::thread first_evaluator(evaluate_worker, FlowId{1}, kSource);
    std::thread second_evaluator(evaluate_worker, kSecondWorkerBase, kOtherSource);
    std::thread statistics_reader([&] {
        for (int round = 0; round < kRounds; ++round) {
            round_start.arrive_and_wait();
            try {
                const auto statistics = detector.statistics();
                if (statistics.state_sources > 4u
                    || statistics.state_observations > config.max_tracked_flows
                    || statistics.errors != 0u) {
                    failed.store(true, std::memory_order_relaxed);
                }
            } catch (...) {
                failed.store(true, std::memory_order_relaxed);
            }
            round_start.arrive_and_wait();
        }
    });
    std::thread retire_worker([&] {
        for (int round = 0; round < kRounds; ++round) {
            round_start.arrive_and_wait();
            try {
                detector.retire_flow(FlowId{1} + static_cast<FlowId>(round));
                detector.retire_flow(kSecondWorkerBase + static_cast<FlowId>(round));
            } catch (...) {
                failed.store(true, std::memory_order_relaxed);
            }
            round_start.arrive_and_wait();
        }
    });

    first_evaluator.join();
    second_evaluator.join();
    statistics_reader.join();
    retire_worker.join();

    EXPECT_FALSE(failed.load(std::memory_order_relaxed));
    const auto statistics = detector.statistics();
    EXPECT_LE(statistics.observations, 2u * static_cast<std::uint64_t>(kRounds));
    EXPECT_LE(statistics.state_sources, 4u);
    EXPECT_LE(statistics.state_observations, config.max_tracked_flows);
    EXPECT_EQ(statistics.errors, 0u);
}

TEST(SynFloodDetector, StartupBurstNeedsMinimumObservationAndFiniteJson) {
    auto config = test_config();
    config.minimum_observation_seconds = 1.0;
    config.max_tracked_flows = 128;
    detection::SynFloodDetector detector(config);
    for (FlowId id = 1; id <= 100; ++id)
        EXPECT_TRUE(evaluate_incomplete(detector, id, 0).empty());
    auto later = make_flow(1, 0);
    later.last_seen = at_ms(1'000);
    const auto events = detector.evaluate(later, {});
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(std::get<double>(events[0].details.at("rate_per_second")), 100.0);
    EXPECT_EQ(events[0].to_json().find("inf"), std::string::npos);
}

TEST(SynFloodDetector, HighIncompleteVolumeBelowRateDoesNotAlert) {
    auto config = test_config();
    config.minimum_rate_per_second = 10.0;
    detection::SynFloodDetector detector(config);
    for (FlowId id = 1; id <= 8; ++id)
        EXPECT_TRUE(evaluate_incomplete(detector, id, static_cast<std::int64_t>(id - 1) * 1'000).empty());
    EXPECT_EQ(detector.statistics().detections, 0u);
}

TEST(SynFloodDetector, PacketwiseCompletionReducesIncompleteGaugeExactlyOnce) {
    auto config = test_config();
    config.minimum_attempts = 100;
    detection::SynFloodDetector detector(config);
    auto flow = make_flow(1, 0);
    EXPECT_TRUE(detector.evaluate(flow, {}).empty());
    flow.tcp_syn_ack_seen = true;
    flow.last_seen = at_ms(10);
    EXPECT_TRUE(detector.evaluate(flow, {}).empty());
    EXPECT_EQ(detector.statistics().incomplete_handshakes, 1u);
    flow.tcp_handshake_completed = true;
    flow.last_seen = at_ms(20);
    EXPECT_TRUE(detector.evaluate(flow, {}).empty());
    for (int i = 0; i < 10; ++i) EXPECT_TRUE(detector.evaluate(flow, {}).empty());
    EXPECT_EQ(detector.statistics().syn_ack_observations, 1u);
    EXPECT_EQ(detector.statistics().ack_completions, 1u);
    EXPECT_EQ(detector.statistics().incomplete_handshakes, 0u);
}

TEST(SynFloodDetector, OldFlowCompletionNeverChangesNewWindowForSameKey) {
    auto config = test_config();
    config.window_seconds = 1;
    config.minimum_attempts = 100;
    detection::SynFloodDetector detector(config);
    auto old = make_flow(1, 0);
    EXPECT_TRUE(detector.evaluate(old, {}).empty());
    detector.expire(at_ms(2'000));
    EXPECT_TRUE(evaluate_incomplete(detector, 2, 2'000).empty());
    old.tcp_syn_ack_seen = old.tcp_handshake_completed = true;
    old.last_seen = at_ms(2'100);
    EXPECT_TRUE(detector.evaluate(old, {}).empty());
    EXPECT_EQ(detector.statistics().incomplete_handshakes, 1u);
    EXPECT_EQ(detector.statistics().ack_completions, 0u);
}

TEST(SynFloodDetector, CooldownExpiryAllowsFreshEvidenceInAlreadyOpenWindow) {
    auto config = test_config();
    config.window_seconds = 1;
    config.cooldown_seconds = 2;
    detection::SynFloodDetector detector(config);
    for (FlowId id = 1; id < 4; ++id) expect_no_event(detector, id, (id - 1) * 100);
    ASSERT_EQ(evaluate_incomplete(detector, 4, 300).size(), 1u);
    detector.expire(at_ms(1'100));
    for (FlowId id = 5; id <= 8; ++id) expect_no_event(detector, id, 1'500 + (id - 5) * 100);
    ASSERT_EQ(evaluate_incomplete(detector, 9, 2'300).size(), 1u);
}

TEST(SynFloodDetector, AlertAndCooldownShareOneBoundedKeySlot) {
    auto config = test_config();
    config.max_tracked_buckets = 1;
    config.window_seconds = 1;
    config.cooldown_seconds = 5;
    detection::SynFloodDetector detector(config);
    for (FlowId id = 1; id < 4; ++id) expect_no_event(detector, id, (id - 1) * 100);
    ASSERT_EQ(evaluate_incomplete(detector, 4, 300).size(), 1u);
    EXPECT_EQ(detector.statistics().peak_sources, 1u);
    detector.expire(at_ms(2'000));
    EXPECT_EQ(detector.statistics().state_sources, 1u); // cooldown retains key
    expect_no_event(detector, 5, 2'000, kOtherSource);
    EXPECT_EQ(detector.statistics().state_rejections, 1u);
    expect_no_event(detector, 6, 2'000); // same key may open a new window
    EXPECT_EQ(detector.statistics().state_sources, 1u);
    detector.expire(at_ms(7'000));
    EXPECT_EQ(detector.statistics().state_sources, 0u);
}

TEST(SynFloodDetector, HostileCardinalityAndRepeatedSnapshotsStayBounded) {
    auto config = test_config();
    config.max_tracked_buckets = 4;
    config.max_tracked_flows = 8;
    detection::SynFloodDetector detector(config);
    for (FlowId id = 1; id <= 100'000; ++id) {
        auto flow = make_flow(id, 0);
        flow.key.dst_port = static_cast<Port>(1 + id % 65'535);
        flow.key.dst_ip = {{198, static_cast<std::uint8_t>(id >> 16),
                           static_cast<std::uint8_t>(id >> 8), static_cast<std::uint8_t>(id)}};
        EXPECT_TRUE(detector.evaluate(flow, {}).empty());
        EXPECT_LE(detector.statistics().state_sources, 4u);
        EXPECT_LE(detector.statistics().state_observations, 8u);
    }
    EXPECT_EQ(detector.statistics().state_rejections, 99'996u);
    detector.expire(at_ms(61'000));
    EXPECT_EQ(detector.statistics().state_sources, 0u);
    EXPECT_EQ(detector.statistics().state_observations, 0u);
    EXPECT_EQ(detector.statistics().incomplete_handshakes, 0u);
}

TEST(SynFloodDetector, InvalidConfigurationRejectedBeforePacketWork) {
    auto config = test_config();
    config.window_seconds = 0;
    EXPECT_THROW(detection::SynFloodDetector{config}, std::invalid_argument);
    config = test_config(); config.minimum_attempts = 0;
    EXPECT_THROW(detection::SynFloodDetector{config}, std::invalid_argument);
    config = test_config(); config.minimum_rate_per_second = std::numeric_limits<double>::infinity();
    EXPECT_THROW(detection::SynFloodDetector{config}, std::invalid_argument);
    config = test_config(); config.incomplete_ratio_threshold = 1.1;
    EXPECT_THROW(detection::SynFloodDetector{config}, std::invalid_argument);
    config = test_config(); config.minimum_incomplete_handshakes = 0;
    EXPECT_THROW(detection::SynFloodDetector{config}, std::invalid_argument);
    config = test_config(); config.cooldown_seconds = -1;
    EXPECT_THROW(detection::SynFloodDetector{config}, std::invalid_argument);
    config = test_config(); config.max_tracked_flows = 0;
    EXPECT_THROW(detection::SynFloodDetector{config}, std::invalid_argument);
    config = test_config(); config.state_expiration_seconds = 1;
    EXPECT_THROW(detection::SynFloodDetector{config}, std::invalid_argument);
    config = test_config(); config.minimum_observation_seconds = 0;
    EXPECT_THROW(detection::SynFloodDetector{config}, std::invalid_argument);
}
