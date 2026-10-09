"""Post-hoc attack classification for IsolationForest anomalies.

The IsolationForest detects *that* a flow is anomalous but cannot name the
attack.  This module applies deterministic rules over the same nine flow
features to infer *what kind* of attack it likely is — turning a generic
ML_ANOMALY into an actionable IDS alert.

Rules are intentionally conservative: a classification is only emitted when
the feature evidence is unambiguous.  Flows that are anomalous but do not
match a known pattern are labelled UNKNOWN_ANOMALY with a generic description.

Classification output is a plain dataclass; no I/O or model loading occurs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .flow_features_v2 import FlowFeaturesV2

# ── Severity levels (must match SecurityEventCreate validator) ────────────────
SEVERITY_CRITICAL: Final = "CRITICAL"
SEVERITY_HIGH: Final = "HIGH"
SEVERITY_MEDIUM: Final = "MEDIUM"
SEVERITY_LOW: Final = "LOW"


@dataclass(frozen=True)
class AttackClassification:
    """Result of post-hoc attack identification for one anomalous flow."""

    attack_type: str        # short machine-readable label, e.g. "SYN_FLOOD"
    severity: str           # LOW | MEDIUM | HIGH | CRITICAL
    confidence: str         # HIGH | MEDIUM | LOW
    description: str        # human-readable one-liner shown in the dashboard


# ── Rule helpers ──────────────────────────────────────────────────────────────

def _syn_dominant(f: FlowFeaturesV2) -> bool:
    """Most packets are SYNs and almost none are FINs (no completed handshake)."""
    return f.syn_packet_fraction >= 0.7 and f.fin_packet_fraction <= 0.05


def _high_rate(f: FlowFeaturesV2) -> bool:
    return f.packets_per_second >= 50.0


def _very_high_rate(f: FlowFeaturesV2) -> bool:
    return f.packets_per_second >= 200.0


def _one_directional(f: FlowFeaturesV2) -> bool:
    """Almost all traffic flows one way — no reply traffic."""
    return f.minor_direction_packet_fraction <= 0.05


def _highly_asymmetric_bytes(f: FlowFeaturesV2) -> bool:
    return f.ipv4_direction_byte_imbalance >= 0.85


def _small_packets(f: FlowFeaturesV2) -> bool:
    """Typical for header-only floods — packets carry no real payload."""
    return f.mean_ipv4_packet_bytes <= 80.0


def _large_packets(f: FlowFeaturesV2) -> bool:
    return f.mean_ipv4_packet_bytes >= 900.0


def _fin_dominant(f: FlowFeaturesV2) -> bool:
    """Mostly FIN packets — RST/FIN scan pattern."""
    return f.fin_packet_fraction >= 0.6 and f.syn_packet_fraction <= 0.1


def _balanced_directions(f: FlowFeaturesV2) -> bool:
    """Traffic is roughly symmetric — suggests reflection/amplification response."""
    return f.minor_direction_packet_fraction >= 0.2


def _irregular_timing(f: FlowFeaturesV2) -> bool:
    """High inter-arrival time variance — bursty / covert-channel pattern."""
    return f.flow_iat_std_seconds >= 1.0


def _sustained(f: FlowFeaturesV2) -> bool:
    return f.duration_seconds >= 5.0


def _short_lived(f: FlowFeaturesV2) -> bool:
    return f.duration_seconds <= 1.0


# ── Main classifier ───────────────────────────────────────────────────────────

def classify_attack(features: FlowFeaturesV2, anomaly_score: float) -> AttackClassification:
    """Return the most specific attack label supported by the feature evidence.

    Rules are evaluated in priority order — the first match wins.  Confidence
    reflects how many independent feature signals agree with the classification.
    """
    f = features

    # ── SYN Flood ─────────────────────────────────────────────────────────────
    # Classic SYN flood: high-rate, one-directional, mostly SYN packets,
    # small packet size (header only), no completed handshakes.
    if _syn_dominant(f) and _one_directional(f) and _high_rate(f) and _small_packets(f):
        confidence = "HIGH" if _very_high_rate(f) and f.syn_packet_fraction >= 0.85 else "MEDIUM"
        return AttackClassification(
            attack_type="SYN_FLOOD",
            severity=SEVERITY_HIGH,
            confidence=confidence,
            description=(
                f"SYN flood detected: {f.packets_per_second:.0f} pkt/s, "
                f"{f.syn_packet_fraction * 100:.0f}% SYN, no completed handshakes."
            ),
        )

    # ── SYN Flood (relaxed — asymmetric bytes variant) ────────────────────────
    if _syn_dominant(f) and _highly_asymmetric_bytes(f) and _high_rate(f):
        return AttackClassification(
            attack_type="SYN_FLOOD",
            severity=SEVERITY_HIGH,
            confidence="MEDIUM",
            description=(
                f"Probable SYN flood: {f.syn_packet_fraction * 100:.0f}% SYN packets, "
                f"high byte asymmetry ({f.ipv4_direction_byte_imbalance:.2f}), "
                f"{f.packets_per_second:.0f} pkt/s."
            ),
        )

    # ── UDP / ICMP Flood (volumetric, no SYN/FIN flags) ──────────────────────
    if (
        _very_high_rate(f)
        and f.syn_packet_fraction <= 0.05
        and f.fin_packet_fraction <= 0.05
        and _one_directional(f)
        and _small_packets(f)
    ):
        return AttackClassification(
            attack_type="UDP_FLOOD",
            severity=SEVERITY_HIGH,
            confidence="MEDIUM",
            description=(
                f"Volumetric flood (UDP/ICMP): {f.packets_per_second:.0f} pkt/s, "
                f"no TCP flags, one-directional, {f.mean_ipv4_packet_bytes:.0f} B/pkt avg."
            ),
        )

    # ── Amplification / Reflection Attack ─────────────────────────────────────
    # Large response packets back to a single source — DNS/NTP/SSDP amplification.
    if (
        _large_packets(f)
        and _highly_asymmetric_bytes(f)
        and _balanced_directions(f)
        and f.syn_packet_fraction <= 0.05
    ):
        return AttackClassification(
            attack_type="AMPLIFICATION_ATTACK",
            severity=SEVERITY_HIGH,
            confidence="MEDIUM",
            description=(
                f"Possible amplification/reflection: large packets "
                f"({f.mean_ipv4_packet_bytes:.0f} B avg), high byte asymmetry "
                f"({f.ipv4_direction_byte_imbalance:.2f}), bidirectional traffic."
            ),
        )

    # ── Port / Network Scan ───────────────────────────────────────────────────
    # Short-lived, one-directional, moderate SYN fraction — scanning behaviour.
    if (
        _short_lived(f)
        and _one_directional(f)
        and f.syn_packet_fraction >= 0.4
        and f.packet_count <= 20
    ):
        return AttackClassification(
            attack_type="PORT_SCAN",
            severity=SEVERITY_MEDIUM,
            confidence="MEDIUM",
            description=(
                f"Probable port scan: short flow ({f.duration_seconds:.2f}s), "
                f"one-directional, {f.syn_packet_fraction * 100:.0f}% SYN, "
                f"{int(f.packet_count)} packets."
            ),
        )

    # ── RST / FIN Scan ────────────────────────────────────────────────────────
    if _fin_dominant(f) and _one_directional(f) and _short_lived(f):
        return AttackClassification(
            attack_type="FIN_SCAN",
            severity=SEVERITY_MEDIUM,
            confidence="MEDIUM",
            description=(
                f"Probable FIN/RST scan: {f.fin_packet_fraction * 100:.0f}% FIN packets, "
                f"one-directional, {f.duration_seconds:.2f}s duration."
            ),
        )

    # ── Data Exfiltration ─────────────────────────────────────────────────────
    # Sustained, large-packet, highly asymmetric upload from internal host.
    if (
        _sustained(f)
        and _large_packets(f)
        and _highly_asymmetric_bytes(f)
        and not _very_high_rate(f)
    ):
        return AttackClassification(
            attack_type="DATA_EXFILTRATION",
            severity=SEVERITY_HIGH,
            confidence="LOW",
            description=(
                f"Possible data exfiltration: sustained flow ({f.duration_seconds:.1f}s), "
                f"large packets ({f.mean_ipv4_packet_bytes:.0f} B avg), "
                f"high byte asymmetry ({f.ipv4_direction_byte_imbalance:.2f})."
            ),
        )

    # ── Covert Channel / Slow Probe ───────────────────────────────────────────
    if _irregular_timing(f) and _sustained(f) and f.packets_per_second <= 5.0:
        return AttackClassification(
            attack_type="COVERT_CHANNEL",
            severity=SEVERITY_MEDIUM,
            confidence="LOW",
            description=(
                f"Possible covert channel or slow probe: irregular inter-arrival times "
                f"(σ={f.flow_iat_std_seconds:.2f}s), low rate ({f.packets_per_second:.2f} pkt/s), "
                f"{f.duration_seconds:.1f}s duration."
            ),
        )

    # ── Unknown Anomaly (fallback) ────────────────────────────────────────────
    # The IsolationForest flagged this flow but no rule matched a specific pattern.
    # Severity scales with how far above threshold the score is.
    margin = anomaly_score - 0.5153855054112947  # distance above locked threshold
    if margin >= 0.15:
        severity = SEVERITY_HIGH
    elif margin >= 0.05:
        severity = SEVERITY_MEDIUM
    else:
        severity = SEVERITY_LOW

    return AttackClassification(
        attack_type="UNKNOWN_ANOMALY",
        severity=severity,
        confidence="LOW",
        description=(
            f"Anomalous flow with no matching attack signature "
            f"(score {anomaly_score:.4f}, {f.packets_per_second:.1f} pkt/s, "
            f"{f.duration_seconds:.2f}s, {f.syn_packet_fraction * 100:.0f}% SYN)."
        ),
    )


__all__ = ["AttackClassification", "classify_attack"]
