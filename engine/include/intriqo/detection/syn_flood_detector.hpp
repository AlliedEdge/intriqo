#pragma once

#include "intriqo/detection/detector.hpp"
#include <map>
#include <mutex>
#include <unordered_map>

namespace intriqo::detection {

/// Configuration for the deterministic fixed-window SYN-flood detector.
///
/// Defaults are deliberately conservative: a ten-second window must contain
/// at least 100 unique initial SYN flow identities and 50 attempts per second,
/// with at least 50 incomplete handshakes and a 0.90 incomplete ratio. Alerts
/// are suppressed for ten seconds, and live state is bounded to 4096 bucket
/// keys and 100000 flow identities. The one-second minimum observation span
/// prevents zero-duration/startup bursts from satisfying the rate threshold;
/// it is not a per-connection TCP timeout or an accuracy-calibrated threshold.
struct SynFloodConfig {
    double window_seconds{10.0};
    std::size_t minimum_attempts{100};
    double minimum_rate_per_second{50.0};
    double incomplete_ratio_threshold{0.90};
    std::size_t minimum_incomplete_handshakes{50};
    double cooldown_seconds{10.0};
    std::size_t max_tracked_buckets{4096};
    std::size_t max_tracked_flows{100000};
    double state_expiration_seconds{60.0};
    events::Severity severity{events::Severity::HIGH};
    double minimum_observation_seconds{1.0};
};

/// Detects high-volume half-open TCP handshakes.
///
/// A bucket is a fixed event-time window keyed by source address, destination
/// address, and destination port. Only one observation per FlowId can add an
/// initial SYN attempt. Directional handshake metadata from the cumulative
/// flow observation is counted once per retained identity. A
/// bucket is emitted at most once; a separate bounded suppression index carries
/// the configured cooldown across adjacent windows for the same key. Flow
/// identities expire after state_expiration_seconds if their owning flow is
/// never retired, so direct detector users cannot retain IDs forever.
class SynFloodDetector final : public Detector {
public:
    explicit SynFloodDetector(SynFloodConfig config = {});

    [[nodiscard]] std::string_view name() const noexcept override {
        return "syn_flood";
    }

    [[nodiscard]] std::vector<events::SecurityEvent>
    evaluate(const flow::NetworkFlow&, const features::FlowFeatures&) noexcept override;

    [[nodiscard]] DetectorStatistics statistics() const noexcept override;
    void expire(TimePoint) noexcept override;
    void retire_flow(FlowId) noexcept override;
    void reset() noexcept override;

private:
    struct BucketKey {
        IPv4Address source;
        IPv4Address destination;
        Port destination_port{0};

        [[nodiscard]] bool operator==(const BucketKey&) const noexcept = default;
    };

    struct BucketKeyHash {
        [[nodiscard]] std::size_t operator()(const BucketKey&) const noexcept;
    };

    struct Bucket {
        TimePoint started{};
        TimePoint latest_seen{};
        std::uint64_t attempts{0};
        std::uint64_t syn_acks{0};
        std::uint64_t completed_handshakes{0};
        bool emitted{false};
    };

    struct FlowIdentity {
        BucketKey bucket;
        TimePoint window_started{};
        TimePoint latest_seen{};
        TimePoint indexed_seen{};
        bool saw_syn_ack{false};
        bool completed{false};
    };

    SynFloodConfig config_;
    std::unordered_map<BucketKey, Bucket, BucketKeyHash> buckets_;
    // Exactly one entry per active bucket; no stale/lazy nodes accumulate.
    std::multimap<TimePoint, BucketKey> expiry_index_;
    // Last alert time is retained only for the configured cooldown. It is
    // The UNION of active and cooldown keys is bounded by max_tracked_buckets;
    // each key has at most one active node and one cooldown node (and indexes).
    std::unordered_map<BucketKey, TimePoint, BucketKeyHash> suppressions_;
    std::multimap<TimePoint, BucketKey> suppression_index_;
    std::unordered_map<FlowId, FlowIdentity> flow_identities_;
    // Exactly one entry per retained flow identity. FlowId breaks timestamp
    // ties and makes the key unique without stale/lazy nodes.
    std::map<std::pair<TimePoint, FlowId>, FlowId> flow_expiry_index_;
    std::size_t tracked_keys_{0}; ///< Union of active bucket and cooldown keys.
    TimePoint watermark_{};
    bool has_watermark_{false};
    DetectorStatistics statistics_;
    mutable std::mutex mutex_;

    void expire_locked(TimePoint) noexcept;
    [[nodiscard]] bool suppression_active_locked(const BucketKey&, TimePoint) const noexcept;
    void erase_flow_identity_locked(
        std::unordered_map<FlowId, FlowIdentity>::iterator) noexcept;
};

} // namespace intriqo::detection
