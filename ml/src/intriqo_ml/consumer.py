"""Bounded JSONL consumer: ``python -m intriqo_ml.consumer FILE``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import BinaryIO, TextIO

from .flow_features import (
    MAX_RECORD_BYTES,
    FlowFeatureError,
    FlowFeatureRecord,
    parse_flow_feature_record,
)


@dataclass(frozen=True)
class FlowFeatureLine:
    """One validated record or one payload-free rejection, with a 1-based line."""

    line_number: int
    record: FlowFeatureRecord | None
    error: FlowFeatureError | None


@dataclass(frozen=True)
class ConsumptionCounts:
    validated: int
    rejected: int


def read_line(stream: BinaryIO) -> bytes | None:
    """Read one bounded physical line, returning None at EOF.

    Oversized lines are drained in bounded chunks before raising a sanitized
    error, so the next call starts at the next line. Only LF or CRLF terminates
    JSONL records; a final record without a line terminator is supported.
    """
    chunk = stream.readline(MAX_RECORD_BYTES + 3)
    if not chunk:
        return None
    if chunk.endswith(b"\n"):
        terminator_size = 2 if chunk.endswith(b"\r\n") else 1
        if len(chunk) - terminator_size > MAX_RECORD_BYTES:
            raise FlowFeatureError("record_too_large")
        return chunk
    if len(chunk) <= MAX_RECORD_BYTES:
        return chunk
    while chunk and not chunk.endswith(b"\n"):
        chunk = stream.readline(MAX_RECORD_BYTES + 3)
    raise FlowFeatureError("record_too_large")


def iter_flow_feature_records(stream: BinaryIO) -> Iterator[FlowFeatureLine]:
    """Yield a typed result for every physical line; malformed lines continue."""
    line_number = 0
    while True:
        try:
            raw = read_line(stream)
        except FlowFeatureError as error:
            line_number += 1
            yield FlowFeatureLine(line_number, None, error)
            continue
        if raw is None:
            return
        line_number += 1
        try:
            record = parse_flow_feature_record(raw)
        except FlowFeatureError as error:
            yield FlowFeatureLine(line_number, None, error)
        else:
            yield FlowFeatureLine(line_number, record, None)


def consume_flow_feature_records(
    stream: BinaryIO, *, error_stream: TextIO | None = None
) -> ConsumptionCounts:
    """Count validation results, optionally emitting payload-free rejections."""
    validated = rejected = 0
    for result in iter_flow_feature_records(stream):
        if result.error is None:
            validated += 1
        else:
            rejected += 1
            if error_stream is not None:
                print(
                    f"line {result.line_number}: rejected: {result.error}",
                    file=error_stream,
                )
    return ConsumptionCounts(validated, rejected)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate flow_features.v1 JSONL records"
    )
    parser.add_argument("file", metavar="FILE", help="UTF-8 JSONL input file")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        with open(args.file, "rb") as stream:
            counts = consume_flow_feature_records(stream, error_stream=sys.stderr)
    except OSError:
        print("cannot read input file", file=sys.stderr)
        return 2
    print(f"validated={counts.validated} rejected={counts.rejected}")
    return 1 if counts.rejected else 0


if __name__ == "__main__":
    raise SystemExit(main())
