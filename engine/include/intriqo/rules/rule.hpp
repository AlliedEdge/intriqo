#pragma once

#include "intriqo/flow/flow.hpp"
#include "intriqo/features/features.hpp"
#include "intriqo/events/security_event.hpp"
#include <optional>
#include <string>

namespace intriqo::rules {

/// A single deterministic detection rule.
///
/// Rules are stateless predicates — they inspect a flow + features and either
/// fire (returning a SecurityEvent) or pass (returning std::nullopt).
/// Stateful tracking belongs in Detector subclasses, not in rules.
class Rule {
public:
    virtual ~Rule() = default;

    [[nodiscard]] virtual std::string name() const = 0;

    [[nodiscard]] virtual std::optional<events::SecurityEvent>
    match(const flow::NetworkFlow& flow,
          const features::FlowFeatures& features) const noexcept = 0;
};

} // namespace intriqo::rules
