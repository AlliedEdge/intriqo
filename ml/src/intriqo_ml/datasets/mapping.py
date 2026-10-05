"""Conservative CIC-IDS2017 projection, not a fabricated FlowFeatureRecord."""

from __future__ import annotations

import math
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from intriqo_ml.flow_features import UINT32_MAX, UINT64_MAX, FlowFeatureRecord

from .config import FEATURES, DatasetError, FeatureName

REQUIRED_COLUMNS = (
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Packets/s",
    "Label",
)
MAPPING = (
    {
        "source": "Flow Duration",
        "target": "duration_seconds",
        "transform": "divide by 1000000",
        "unit": "seconds",
    },
    {
        "source": "Total Fwd Packets + Total Backward Packets",
        "target": "packet_count",
        "transform": "sum; direction-invariant",
        "unit": "packets",
    },
    {
        "source": "Flow Packets/s",
        "target": "packets_per_second",
        "transform": "direct; finite nonnegative only",
        "unit": "packets/second",
    },
)
# These columns may be audited for elementary numeric integrity, but are NEVER
# model inputs: payload bytes != IPv4 total lengths; original flag counts are buggy.
AUDIT_COLUMNS = (
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "SYN Flag Count",
    "FIN Flag Count",
    "RST Flag Count",
)
VALID_LABELS = frozenset(
    {
        "BENIGN",
        "FTP-Patator",
        "SSH-Patator",
        "DoS slowloris",
        "DoS Slowhttptest",
        "DoS Hulk",
        "DoS GoldenEye",
        "Heartbleed",
        "Web Attack � Brute Force",
        "Web Attack � XSS",
        "Web Attack � Sql Injection",
        "Web Attack – Brute Force",
        "Web Attack – XSS",
        "Web Attack – Sql Injection",
        "Infiltration",
        "Bot",
        "PortScan",
        "DDoS",
    }
)


@dataclass(frozen=True)
class RowIssue:
    code: str
    field: str


class InvalidRow(ValueError):
    def __init__(self, issue: RowIssue) -> None:
        self.issue = issue
        super().__init__("invalid dataset row")


def _text(row: dict[str, Any], column: str) -> str:
    raw = row.get(column, "")
    value = "" if raw is None else str(raw).strip()
    if not value:
        raise InvalidRow(RowIssue("missing_value", column))
    return value


def _integer(row: dict[str, Any], column: str, maximum: int) -> int:
    value = _text(row, column)
    try:
        number = Decimal(value)
    except InvalidOperation:
        raise InvalidRow(RowIssue("invalid_numeric", column)) from None
    if not number.is_finite():
        raise InvalidRow(RowIssue("nonfinite", column))
    if number < 0 or number > maximum:
        raise InvalidRow(RowIssue("numeric_range", column))
    if number != number.to_integral_value():
        raise InvalidRow(RowIssue("fractional_count", column))
    return int(number)


def _number(row: dict[str, Any], column: str) -> float:
    value = _text(row, column)
    try:
        number = float(value)
    except ValueError:
        raise InvalidRow(RowIssue("invalid_numeric", column)) from None
    if not math.isfinite(number):
        raise InvalidRow(RowIssue("nonfinite", column))
    if number < 0:
        raise InvalidRow(RowIssue("numeric_range", column))
    return number


@dataclass(frozen=True)
class MappedRow:
    values: tuple[float, ...]
    label: str
    is_attack: bool


def map_cicids2017_row(
    row: dict[str, Any], features: tuple[FeatureName, ...] = FEATURES
) -> MappedRow:
    duration = _integer(row, "Flow Duration", (1 << 63) - 1) / 1_000_000
    forward = _integer(row, "Total Fwd Packets", UINT64_MAX)
    reverse = _integer(row, "Total Backward Packets", UINT64_MAX)
    packets = forward + reverse
    if packets == 0 or forward == 0 or packets > UINT64_MAX:
        raise InvalidRow(RowIssue("impossible_packets", "Total Fwd Packets"))
    if duration == 0 and packets > 0:
        raise InvalidRow(RowIssue("impossible_duration", "Flow Duration"))
    # Future numeric matrices use float64; reject rather than silently round a
    # uint64 counter not exactly representable by that model-input vocabulary.
    if packets > 1 << 53:
        raise InvalidRow(RowIssue("float64_precision", "Total Fwd Packets"))
    rate = _number(row, "Flow Packets/s")
    expected_rate = packets / duration if duration else 0.0
    if not math.isclose(rate, expected_rate, rel_tol=1e-6, abs_tol=1e-9):
        raise InvalidRow(RowIssue("inconsistent_rate", "Flow Packets/s"))
    for column in AUDIT_COLUMNS:
        if column not in row:
            continue
        if column.endswith("Flag Count"):
            count = _integer(row, column, UINT32_MAX)
            if count > packets:
                raise InvalidRow(RowIssue("impossible_flag_count", column))
        elif column.startswith("Total Length"):
            count = _integer(row, column, UINT64_MAX)
            direction_packets = forward if "Fwd" in column else reverse
            if direction_packets == 0 and count != 0:
                raise InvalidRow(RowIssue("impossible_bytes", column))
        else:
            value = _number(row, column)
            if duration == 0 and value != 0:
                raise InvalidRow(RowIssue("inconsistent_rate", column))
    label = _text(row, "Label")
    if label not in VALID_LABELS:
        raise InvalidRow(RowIssue("invalid_label", "Label"))
    values = {
        "duration_seconds": duration,
        "packet_count": float(packets),
        "packets_per_second": rate,
    }
    try:
        selected = tuple(values[feature] for feature in features)
    except KeyError:
        raise DatasetError("unsupported_feature") from None
    return MappedRow(selected, label, label != "BENIGN")


def project_flow_features(
    record: FlowFeatureRecord, features: tuple[FeatureName, ...] = FEATURES
) -> tuple[float, ...]:
    """Copy selected validated v1 fields for a future model; never derive rates."""
    values: list[float] = []
    for feature in features:
        if feature not in FEATURES:
            raise DatasetError("unsupported_feature")
        value = getattr(record.features, feature)
        if feature == "packet_count" and value > 1 << 53:
            raise DatasetError("float64_precision")
        values.append(float(value))
    return tuple(values)
