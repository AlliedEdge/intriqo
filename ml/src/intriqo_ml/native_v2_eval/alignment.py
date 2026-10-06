"""Conservative association of native v2 flows with controller ground truth."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from intriqo_ml.flow_features_v2 import FlowFeatureRecordV2

from .schema import AlignmentStatus, ExperimentManifest, ExperimentScenario


def _timestamp_ns(value: str) -> int:
    """Convert the native canonical UTC timestamp to an integer nanosecond key."""
    parsed = value
    date, clock = parsed[:19].split("T")
    year, month, day = (int(part) for part in date.split("-"))
    hour, minute, second = (int(part) for part in clock.split(":"))
    # The controlled corpus uses modern UTC dates.  This integer calendar
    # conversion avoids float datetime timestamps and preserves nine digits.
    import calendar

    seconds = calendar.timegm((year, month, day, hour, minute, second))
    return seconds * 1_000_000_000 + int(parsed[20:29])


def _interval_overlap_ns(
    left_start: int, left_end: int, right_start: int, right_end: int
) -> int:
    start = max(left_start, right_start)
    end = min(left_end, right_end)
    if end > start:
        return end - start
    # A one-packet/zero-duration flow is still exactly associated when its
    # point is inside another interval.  Boundary-only contact is not overlap.
    if left_start == left_end and right_start <= left_start <= right_end:
        return 0
    if right_start == right_end and left_start <= right_start <= left_end:
        return 0
    return -1


def _ports_match(actual: int, expected: int | None) -> bool:
    return expected is None or actual == expected


def _tuple_matches(record: FlowFeatureRecordV2, scenario: ExperimentScenario) -> bool:
    network = record.metadata.network
    return (
        network.protocol == scenario.protocol
        and network.src_ip == scenario.attacker_ip
        and network.dst_ip == scenario.victim_ip
        and _ports_match(network.src_port, scenario.source_port)
        and _ports_match(network.dst_port, scenario.destination_port)
    )


@dataclass(frozen=True)
class AlignmentRow:
    capture_id: str
    experiment_id: str | None
    native_line_number: int
    engine_instance_id: str
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    native_start_timestamp: str
    native_end_timestamp: str
    source_label_id: str | None
    source_scenario_id: str | None
    label: str | None
    attack_family: str | None
    match_status: AlignmentStatus
    match_method: str
    candidate_count: int
    overlap_ns: int
    ambiguity_reason: str | None
    eligible: bool

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def align_record(
    record: FlowFeatureRecordV2,
    *,
    capture_id: str,
    capture_experiment_id: str | None,
    manifest: ExperimentManifest,
    native_line_number: int,
) -> AlignmentRow:
    """Align one native row without resolving ambiguity by precedence.

    The direction is deliberate: native flow metadata retains the first
    observed tuple, and controller labels identify attacker-to-victim traffic.
    A reverse-direction match is therefore not silently treated as equivalent.
    """
    network = record.metadata.network
    start = _timestamp_ns(record.metadata.first_seen)
    end = _timestamp_ns(record.metadata.timestamp)
    base = {
        "capture_id": capture_id,
        "experiment_id": capture_experiment_id,
        "native_line_number": native_line_number,
        "engine_instance_id": record.metadata.engine_instance_id,
        "flow_id": record.metadata.flow_id,
        "src_ip": network.src_ip,
        "dst_ip": network.dst_ip,
        "src_port": network.src_port,
        "dst_port": network.dst_port,
        "protocol": network.protocol,
        "native_start_timestamp": record.metadata.first_seen,
        "native_end_timestamp": record.metadata.timestamp,
    }
    if capture_experiment_id is None:
        return AlignmentRow(
            **base,
            source_label_id=None,
            source_scenario_id=None,
            label=None,
            attack_family=None,
            match_status="UNKNOWN",
            match_method="missing_capture_experiment_id",
            candidate_count=0,
            overlap_ns=-1,
            ambiguity_reason="capture is not declared by the experiment manifest",
            eligible=False,
        )

    tuple_candidates = [
        scenario
        for scenario in manifest.experiments
        if scenario.experiment_id == capture_experiment_id
        and _tuple_matches(record, scenario)
    ]
    candidates: list[tuple[ExperimentScenario, int]] = []
    for scenario in tuple_candidates:
        if scenario.start_timestamp is None or scenario.end_timestamp is None:
            continue
        overlap = _interval_overlap_ns(
            start,
            end,
            _timestamp_ns(scenario.start_timestamp),
            _timestamp_ns(scenario.end_timestamp),
        )
        if overlap >= 0:
            candidates.append((scenario, overlap))

    if not candidates:
        reason = (
            "ground-truth timestamps are not populated"
            if tuple_candidates
            else "no directional five-tuple/protocol candidate"
        )
        return AlignmentRow(
            **base,
            source_label_id=None,
            source_scenario_id=None,
            label=None,
            attack_family=None,
            match_status="UNKNOWN",
            match_method="experiment_id+tuple+time",
            candidate_count=0,
            overlap_ns=-1,
            ambiguity_reason=reason,
            eligible=False,
        )

    if len(candidates) > 1:
        return AlignmentRow(
            **base,
            source_label_id=None,
            source_scenario_id=None,
            label=None,
            attack_family=None,
            match_status="AMBIGUOUS",
            match_method="experiment_id+tuple+overlapping_intervals",
            candidate_count=len(candidates),
            overlap_ns=max(overlap for _, overlap in candidates),
            ambiguity_reason="multiple controller intervals overlap this native flow",
            eligible=False,
        )

    scenario, overlap = candidates[0]
    exact_tuple = (
        scenario.source_port is not None
        and scenario.destination_port is not None
        and network.src_port == scenario.source_port
        and network.dst_port == scenario.destination_port
    )
    exact_interval = (
        scenario.start_timestamp == record.metadata.first_seen
        and scenario.end_timestamp == record.metadata.timestamp
    )
    status: AlignmentStatus = "EXACT" if exact_tuple and exact_interval else "PARTIAL"
    return AlignmentRow(
        **base,
        source_label_id=scenario.source_label_id,
        source_scenario_id=scenario.scenario_id,
        label=scenario.label,
        attack_family=scenario.attack_family,
        match_status=status,
        match_method="experiment_id+directional_five_tuple+exact_interval"
        if status == "EXACT"
        else "experiment_id+directional_tuple+positive_time_overlap",
        candidate_count=1,
        overlap_ns=overlap,
        ambiguity_reason=None,
        eligible=status == "EXACT",
    )


def align_records(
    records: list[tuple[int, FlowFeatureRecordV2]],
    *,
    capture_id: str,
    capture_experiment_id: str | None,
    manifest: ExperimentManifest,
) -> list[AlignmentRow]:
    return [
        align_record(
            record,
            capture_id=capture_id,
            capture_experiment_id=capture_experiment_id,
            manifest=manifest,
            native_line_number=line_number,
        )
        for line_number, record in records
    ]
