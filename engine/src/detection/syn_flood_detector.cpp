#include "intriqo/detection/syn_flood_detector.hpp"
#include "intriqo/events/security_event.hpp"

#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <type_traits>

namespace intriqo::detection {
namespace {

long double elapsed_seconds(TimePoint end, TimePoint start) noexcept {
    using UnsignedCount = std::make_unsigned_t<Clock::duration::rep>;
    const auto end_count = static_cast<UnsignedCount>(end.time_since_epoch().count());
    const auto start_count = static_cast<UnsignedCount>(start.time_since_epoch().count());
    const bool positive = end >= start;
    const auto ticks = positive ? end_count - start_count : start_count - end_count;
    const auto seconds = std::chrono::duration<long double>(
        std::chrono::duration<UnsignedCount, Clock::duration::period>{ticks}).count();
    return positive ? seconds : -seconds;
}

double rate_per_second(std::uint64_t attempts, double elapsed) noexcept {
    return elapsed > 0.0 ? static_cast<double>(attempts) / elapsed : 0.0;
}

} // namespace

std::size_t SynFloodDetector::BucketKeyHash::operator()(const BucketKey& key) const noexcept {
    std::size_t hash = 0;
    for (const auto byte : key.source.octets) hash = hash * 131 + byte;
    for (const auto byte : key.destination.octets) hash = hash * 131 + byte;
    return hash * 131 + key.destination_port;
}

SynFloodDetector::SynFloodDetector(SynFloodConfig config) : config_(config) {
    if (!std::isfinite(config_.window_seconds) || config_.window_seconds <= 0.0)
        throw std::invalid_argument("syn flood window_seconds must be finite and positive");
    if (config_.minimum_attempts == 0)
        throw std::invalid_argument("syn flood minimum_attempts must be positive");
    if (!std::isfinite(config_.minimum_rate_per_second)
        || config_.minimum_rate_per_second < 0.0)
        throw std::invalid_argument(
            "syn flood minimum_rate_per_second must be finite and non-negative");
    if (!std::isfinite(config_.incomplete_ratio_threshold)
        || config_.incomplete_ratio_threshold < 0.0
        || config_.incomplete_ratio_threshold > 1.0)
        throw std::invalid_argument(
            "syn flood incomplete_ratio_threshold must be in [0, 1]");
    if (config_.minimum_incomplete_handshakes == 0)
        throw std::invalid_argument(
            "syn flood minimum_incomplete_handshakes must be positive");
    if (!std::isfinite(config_.cooldown_seconds) || config_.cooldown_seconds < 0.0)
        throw std::invalid_argument(
            "syn flood cooldown_seconds must be finite and non-negative");
    if (!std::isfinite(config_.state_expiration_seconds)
        || config_.state_expiration_seconds < config_.window_seconds)
        throw std::invalid_argument(
            "syn flood state expiration must be finite and at least the observation window");
    if (config_.max_tracked_buckets == 0 || config_.max_tracked_flows == 0)
        throw std::invalid_argument("syn flood state capacities must be positive");
    if (!std::isfinite(config_.minimum_observation_seconds)
        || config_.minimum_observation_seconds <= 0.0
        || config_.minimum_observation_seconds > config_.window_seconds)
        throw std::invalid_argument("syn flood minimum observation must be positive and within window");
}

void SynFloodDetector::erase_flow_identity_locked(
    std::unordered_map<FlowId, FlowIdentity>::iterator it) noexcept {
    if (it == flow_identities_.end()) return;
    flow_expiry_index_.erase({it->second.indexed_seen, it->first});
    flow_identities_.erase(it);
}

void SynFloodDetector::expire_locked(TimePoint now) noexcept {
    if (!has_watermark_ || now > watermark_) {
        watermark_ = now;
        has_watermark_ = true;
    }

    while (!expiry_index_.empty()) {
        const auto oldest = expiry_index_.begin();
        if (elapsed_seconds(watermark_, oldest->first) <= config_.window_seconds) break;
        const auto bucket = buckets_.find(oldest->second);
        if (bucket != buckets_.end()) {
            statistics_.incomplete_handshakes -= bucket->second.attempts
                - bucket->second.completed_handshakes;
            buckets_.erase(bucket);
            if (!suppressions_.contains(oldest->second)) --tracked_keys_;
        }
        expiry_index_.erase(oldest);
        ++statistics_.expired_sources;
    }

    while (!flow_expiry_index_.empty()) {
        const auto oldest = flow_expiry_index_.begin();
        const auto oldest_time = oldest->first.first;
        if (elapsed_seconds(watermark_, oldest_time)
            <= config_.state_expiration_seconds)
            break;
        const auto flow_id = oldest->second;
        const auto identity = flow_identities_.find(flow_id);
        // One node per identity; refresh it only when its indexed time becomes
        // due. Packet updates need only a scalar write, not an O(log N) erase
        // and insert. There are no stale/lazy duplicate expiry nodes.
        if (identity != flow_identities_.end()
            && elapsed_seconds(watermark_, identity->second.latest_seen)
                <= config_.state_expiration_seconds) {
            auto node = flow_expiry_index_.extract(oldest);
            node.key().first = identity->second.latest_seen;
            identity->second.indexed_seen = identity->second.latest_seen;
            flow_expiry_index_.insert(std::move(node));
        } else {
            flow_expiry_index_.erase(oldest);
            if (identity != flow_identities_.end()) {
                flow_identities_.erase(identity);
                ++statistics_.expired_observations;
            }
        }
    }

    while (!suppression_index_.empty()) {
        const auto oldest = suppression_index_.begin();
        if (elapsed_seconds(watermark_, oldest->first) < config_.cooldown_seconds) break;
        suppressions_.erase(oldest->second);
        if (!buckets_.contains(oldest->second)) --tracked_keys_;
        suppression_index_.erase(oldest);
    }
}

bool SynFloodDetector::suppression_active_locked(const BucketKey& key,
                                                 TimePoint now) const noexcept {
    const auto it = suppressions_.find(key);
    return it != suppressions_.end()
        && elapsed_seconds(now, it->second) < config_.cooldown_seconds;
}

std::vector<events::SecurityEvent> SynFloodDetector::evaluate(
    const flow::NetworkFlow& flow, const features::FlowFeatures& features) noexcept {
    std::lock_guard lock(mutex_);
    expire_locked(flow.last_seen);

    if (flow.key.protocol != Protocol::TCP || flow.key.src_ip == flow.key.dst_ip
        || flow.key.dst_port == 0)
        return {};

    // FlowTable supplies directional handshake metadata. The legacy counters
    // remain useful telemetry, but cannot distinguish a SYN-ACK-first capture
    // or an ACK without an observed SYN-ACK and therefore are not evidence for
    // handshake completion here.
    const bool handshake_started = flow.tcp_handshake_started
        || features.tcp_handshake_started;
    const bool syn_ack_seen = flow.tcp_syn_ack_seen || features.tcp_syn_ack_seen;
    const bool handshake_completed = flow.tcp_handshake_completed
        || features.tcp_handshake_completed;
    const BucketKey key{flow.key.src_ip, flow.key.dst_ip, flow.key.dst_port};

    try {
        const auto identity_it = flow_identities_.find(flow.flow_id);
        if (identity_it != flow_identities_.end()) {
            auto bucket_it = buckets_.find(identity_it->second.bucket);
            // Retained flow identities outlive their event window. This keeps a
            // long-lived flow from recounting itself after a window rolls over.
            if (bucket_it == buckets_.end()
                || bucket_it->second.started != identity_it->second.window_started) {
                auto& identity = identity_it->second;
                identity.latest_seen = std::max(identity.latest_seen, flow.last_seen);
                return {};
            }

            auto& identity = identity_it->second;
            const bool new_syn_ack = !identity.saw_syn_ack && syn_ack_seen;
            const bool complete_now = !identity.completed && handshake_completed;
            const bool new_completion = complete_now && !identity.completed;
            const auto latest = std::max(bucket_it->second.latest_seen, flow.last_seen);
            if (!new_syn_ack && !new_completion
                && (bucket_it->second.emitted
                    || bucket_it->second.attempts < config_.minimum_attempts)) {
                identity.latest_seen = std::max(identity.latest_seen, flow.last_seen);
                return {};
            }

            const auto attempts = bucket_it->second.attempts;
            const auto bucket_syn_acks = bucket_it->second.syn_acks
                + (new_syn_ack ? 1U : 0U);
            const auto completed = bucket_it->second.completed_handshakes
                + (new_completion ? 1U : 0U);
            const auto incomplete = attempts > completed ? attempts - completed : 0;
            const auto elapsed = static_cast<double>(
                elapsed_seconds(latest, bucket_it->second.started));
            const auto rate = rate_per_second(attempts, elapsed);
            const auto ratio = attempts == 0
                ? 0.0
                : static_cast<double>(incomplete) / static_cast<double>(attempts);
            const bool threshold = !bucket_it->second.emitted
                && elapsed >= config_.minimum_observation_seconds
                && attempts >= config_.minimum_attempts
                && rate >= config_.minimum_rate_per_second
                && incomplete >= config_.minimum_incomplete_handshakes
                && ratio >= config_.incomplete_ratio_threshold;
            const bool emit = threshold
                && !suppression_active_locked(identity.bucket, latest);

            std::vector<events::SecurityEvent> result;
            if (emit) {
                auto event = events::make_syn_flood_event(
                    identity.bucket.source, identity.bucket.destination, config_.severity,
                    identity.bucket.destination_port, attempts, bucket_syn_acks, completed,
                    incomplete, ratio, rate, config_.window_seconds, latest);
                event.details.emplace("minimum_syn_attempts",
                                      static_cast<std::int64_t>(config_.minimum_attempts));
                event.details.emplace("minimum_rate_per_second",
                                      config_.minimum_rate_per_second);
                event.details.emplace("minimum_incomplete_handshakes",
                                      static_cast<std::int64_t>(config_.minimum_incomplete_handshakes));
                event.details.emplace("incomplete_ratio_threshold",
                                      config_.incomplete_ratio_threshold);
                event.details.emplace("observed_elapsed_seconds", elapsed);
                event.details.emplace("minimum_observation_seconds", config_.minimum_observation_seconds);
                if (event.event_id.size() != 36) {
                    ++statistics_.errors;
                    return {};
                }
                result.push_back(std::move(event));
            }

            if (emit) {
                const auto inserted = suppressions_.emplace(identity.bucket, latest);
                if (inserted.second) {
                    try {
                        suppression_index_.emplace(latest, identity.bucket);
                    } catch (...) {
                        suppressions_.erase(inserted.first);
                        throw;
                    }
                }
            }

            identity.latest_seen = std::max(identity.latest_seen, flow.last_seen);
            identity.saw_syn_ack = identity.saw_syn_ack || new_syn_ack;
            identity.completed = identity.completed || new_completion;
            bucket_it->second.latest_seen = latest;
            bucket_it->second.syn_acks = bucket_syn_acks;
            bucket_it->second.completed_handshakes = completed;
            bucket_it->second.emitted = bucket_it->second.emitted || emit;
            if (new_syn_ack) ++statistics_.syn_ack_observations;
            if (new_completion) {
                ++statistics_.ack_completions;
                --statistics_.incomplete_handshakes;
            }
            if (emit) ++statistics_.detections;
            return result;
        }

        if (!handshake_started) return {};
        // Never re-admit a stale cumulative flow snapshot after identity
        // expiration or capacity recovery. FlowTable assigns a new identity
        // when a genuine later connection is first observed.
        if (elapsed_seconds(watermark_, flow.first_seen) > config_.window_seconds) {
            ++statistics_.state_rejections;
            return {};
        }

        auto bucket_it = buckets_.find(key);
        const bool new_bucket = bucket_it == buckets_.end();
        if (!new_bucket && flow.first_seen < bucket_it->second.started) {
            ++statistics_.state_rejections;
            return {};
        }
        if (new_bucket && has_watermark_
            && elapsed_seconds(watermark_, flow.last_seen) > config_.window_seconds) {
            ++statistics_.state_rejections;
            return {};
        }
        if (flow_identities_.size() >= config_.max_tracked_flows) {
            ++statistics_.state_rejections;
            return {};
        }
        if (new_bucket && !suppressions_.contains(key)
            && tracked_keys_ >= config_.max_tracked_buckets) {
            ++statistics_.state_rejections;
            return {};
        }

        const auto attempts = new_bucket ? 1ULL : bucket_it->second.attempts + 1;
        const auto bucket_syn_acks = (new_bucket ? 0ULL : bucket_it->second.syn_acks)
            + (syn_ack_seen ? 1ULL : 0ULL);
        const bool complete_now = handshake_completed;
        const auto completed = (new_bucket ? 0ULL
                                           : bucket_it->second.completed_handshakes)
            + (complete_now ? 1ULL : 0ULL);
        const auto incomplete = attempts > completed ? attempts - completed : 0;
        const auto started = new_bucket ? flow.first_seen : bucket_it->second.started;
        const auto latest = new_bucket ? flow.last_seen
            : std::max(bucket_it->second.latest_seen, flow.last_seen);
        const auto elapsed = static_cast<double>(elapsed_seconds(latest, started));
        const auto rate = rate_per_second(attempts, elapsed);
        const auto ratio = attempts == 0
            ? 0.0
            : static_cast<double>(incomplete) / static_cast<double>(attempts);
        const bool threshold = (new_bucket || !bucket_it->second.emitted)
            && elapsed >= config_.minimum_observation_seconds
            && attempts >= config_.minimum_attempts
            && rate >= config_.minimum_rate_per_second
            && incomplete >= config_.minimum_incomplete_handshakes
            && ratio >= config_.incomplete_ratio_threshold;
        const bool emit = threshold && !suppression_active_locked(key, latest);

        std::vector<events::SecurityEvent> result;
        if (emit) {
            auto event = events::make_syn_flood_event(
                key.source, key.destination, config_.severity, key.destination_port, attempts,
                bucket_syn_acks, completed, incomplete, ratio, rate,
                config_.window_seconds, latest);
            event.details.emplace("minimum_syn_attempts",
                                  static_cast<std::int64_t>(config_.minimum_attempts));
            event.details.emplace("minimum_rate_per_second",
                                  config_.minimum_rate_per_second);
            event.details.emplace("minimum_incomplete_handshakes",
                                  static_cast<std::int64_t>(config_.minimum_incomplete_handshakes));
            event.details.emplace("incomplete_ratio_threshold",
                                  config_.incomplete_ratio_threshold);
            event.details.emplace("observed_elapsed_seconds", elapsed);
            event.details.emplace("minimum_observation_seconds", config_.minimum_observation_seconds);
            if (event.event_id.size() != 36) {
                ++statistics_.errors;
                return {};
            }
            result.push_back(std::move(event));
        }

        const FlowIdentity pending_identity{
            key, started, flow.last_seen, flow.last_seen, syn_ack_seen, complete_now};
        std::map<std::pair<TimePoint, FlowId>, FlowId>::iterator flow_expiry_it;
        std::unordered_map<FlowId, FlowIdentity>::iterator identity_inserted_it;
        std::multimap<TimePoint, BucketKey>::iterator bucket_expiry_it;
        std::unordered_map<BucketKey, Bucket, BucketKeyHash>::iterator bucket_inserted_it;
        std::unordered_map<BucketKey, TimePoint, BucketKeyHash>::iterator suppression_it;
        std::multimap<TimePoint, BucketKey>::iterator suppression_index_it;
        bool inserted_flow_expiry = false;
        bool inserted_identity = false;
        bool inserted_bucket_expiry = false;
        bool inserted_bucket = false;
        bool inserted_suppression = false;
        bool inserted_suppression_index = false;
        const auto old_bucket = new_bucket ? Bucket{} : bucket_it->second;

        try {
            if (new_bucket) {
                bucket_expiry_it = expiry_index_.emplace(started, key);
                inserted_bucket_expiry = true;
                Bucket pending_bucket;
                pending_bucket.started = started;
                pending_bucket.latest_seen = latest;
                pending_bucket.attempts = attempts;
                pending_bucket.syn_acks = bucket_syn_acks;
                pending_bucket.completed_handshakes = completed;
                pending_bucket.emitted = emit;
                bucket_inserted_it = buckets_.emplace(key, std::move(pending_bucket)).first;
                inserted_bucket = true;
            }

            identity_inserted_it = flow_identities_.emplace(flow.flow_id, pending_identity).first;
            inserted_identity = true;
            flow_expiry_it = flow_expiry_index_.emplace(
                std::pair<TimePoint, FlowId>{flow.last_seen, flow.flow_id}, flow.flow_id).first;
            inserted_flow_expiry = true;

            if (!new_bucket) {
                bucket_it->second.latest_seen = latest;
                bucket_it->second.attempts = attempts;
                bucket_it->second.syn_acks = bucket_syn_acks;
                bucket_it->second.completed_handshakes = completed;
                bucket_it->second.emitted = bucket_it->second.emitted || emit;
            }

            if (emit) {
                auto suppression = suppressions_.emplace(key, latest);
                suppression_it = suppression.first;
                inserted_suppression = suppression.second;
                if (inserted_suppression) {
                    suppression_index_it = suppression_index_.emplace(latest, key);
                    inserted_suppression_index = true;
                }
            }
        } catch (...) {
            if (!new_bucket && bucket_it != buckets_.end()) bucket_it->second = old_bucket;
            if (inserted_suppression_index) suppression_index_.erase(suppression_index_it);
            if (inserted_suppression) suppressions_.erase(suppression_it);
            if (inserted_flow_expiry) flow_expiry_index_.erase(flow_expiry_it);
            if (inserted_identity) flow_identities_.erase(identity_inserted_it);
            if (inserted_bucket) buckets_.erase(bucket_inserted_it);
            if (inserted_bucket_expiry) expiry_index_.erase(bucket_expiry_it);
            ++statistics_.errors;
            return {};
        }

        ++statistics_.observations;
        if (new_bucket && !suppressions_.contains(key)) ++tracked_keys_;
        // An alert adds a cooldown entry for this already-admitted key; it does
        // not consume a second key slot. Every index has at most one record per
        // corresponding bounded container.
        if (new_bucket && emit && inserted_suppression) ++tracked_keys_;
        ++statistics_.syn_observations;
        if (!complete_now) ++statistics_.incomplete_handshakes;
        if (syn_ack_seen) ++statistics_.syn_ack_observations;
        if (complete_now) ++statistics_.ack_completions;
        if (emit) ++statistics_.detections;
        statistics_.peak_sources = std::max(
            statistics_.peak_sources, static_cast<std::uint64_t>(tracked_keys_));
        statistics_.peak_observations = std::max(
            statistics_.peak_observations, static_cast<std::uint64_t>(flow_identities_.size()));
        return result;
    } catch (...) {
        ++statistics_.errors;
        return {};
    }
}

DetectorStatistics SynFloodDetector::statistics() const noexcept {
    std::lock_guard lock(mutex_);
    auto result = statistics_;
    result.state_sources = tracked_keys_;
    result.state_observations = flow_identities_.size();
    return result;
}

void SynFloodDetector::expire(TimePoint now) noexcept {
    std::lock_guard lock(mutex_);
    expire_locked(now);
}

void SynFloodDetector::retire_flow(FlowId id) noexcept {
    std::lock_guard lock(mutex_);
    erase_flow_identity_locked(flow_identities_.find(id));
}

void SynFloodDetector::reset() noexcept {
    std::lock_guard lock(mutex_);
    buckets_.clear();
    expiry_index_.clear();
    suppressions_.clear();
    suppression_index_.clear();
    flow_identities_.clear();
    flow_expiry_index_.clear();
    tracked_keys_ = 0;
    statistics_.incomplete_handshakes = 0;
    watermark_ = {};
    has_watermark_ = false;
}

} // namespace intriqo::detection
