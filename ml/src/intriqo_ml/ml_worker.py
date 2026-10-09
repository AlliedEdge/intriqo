"""Optional bounded worker for native ``flow_features.v2`` JSONL.

Run this as a separate operator-managed process.  It consumes a regular local
staging file and never starts, controls, or communicates with the C++ engine.
The durable ledger reserves each ML decision before an anomaly is written or
delivered.  Consequently this worker provides at-most-once ML decisions and
best-effort delivery, rather than a replaying delivery queue.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import queue
import signal
import sqlite3
import stat
import sys
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Protocol, TextIO

from .attack_classifier import classify_attack
from .flow_features import MAX_RECORD_BYTES, FlowFeatureError
from .flow_features_v2 import FlowFeatureRecordV2, parse_flow_feature_record_v2
from .inference_v2 import (
    DetectorState,
    MLConfig,
    MLDetectionResult,
    MLDetector,
    deterministic_event_id,
)
from .ml_transport import ControlPlaneTransport, DeliveryStatus, TransportConfig

DEFAULT_QUEUE_CAPACITY = 256
DEFAULT_SHUTDOWN_TIMEOUT = 30.0
DEFAULT_FOLLOW_POLL_SECONDS = 0.05


def parse_dedup_limit(environ: Mapping[str, str] | None = None) -> int:
    """Read the worker-only durable ledger cap without touching artifacts."""

    value = (os.environ if environ is None else environ).get("INTRIQO_ML_MAX_DEDUP_ENTRIES", "100000")
    try:
        parsed = int(value)
    except ValueError:
        raise ValueError("INTRIQO_ML_MAX_DEDUP_ENTRIES must be a positive integer") from None
    if parsed <= 0:
        raise ValueError("INTRIQO_ML_MAX_DEDUP_ENTRIES must be a positive integer")
    return parsed


class DetectorLike(Protocol):
    state: DetectorState

    def detect(self, record: FlowFeatureRecordV2) -> MLDetectionResult: ...


class TransportLike(Protocol):
    def send(self, payload: Mapping[str, Any]) -> Any: ...


@dataclass(frozen=True)
class InputLine:
    """One physical line or one payload-free parser failure."""

    line_number: int
    raw: bytes | None = None
    error: FlowFeatureError | None = None
    drop_reason: str | None = None


def iter_bounded_jsonl(
    stream: BinaryIO,
    *,
    follow: bool = False,
    stop_event: threading.Event | None = None,
    poll_seconds: float = DEFAULT_FOLLOW_POLL_SECONDS,
) -> Iterator[InputLine]:
    """Yield complete bounded physical lines.

    In follow mode a final partial line is held until LF/CRLF arrives.  At
    EOF, polling is finite and interruptible; a stop discards the incomplete
    line.  Oversized lines are drained in fixed-size chunks without retaining
    their contents, so a malformed producer cannot grow this process's memory.
    """

    if (
        not isinstance(poll_seconds, (int, float))
        or isinstance(poll_seconds, bool)
        or not math.isfinite(float(poll_seconds))
        or poll_seconds <= 0
    ):
        raise ValueError("poll_seconds must be a positive finite number")
    stop = stop_event or threading.Event()
    line_number = 0
    buffered = bytearray()
    oversized = False
    while True:
        if stop.is_set():
            if buffered or oversized:
                line_number += 1
                yield InputLine(line_number, drop_reason="shutdown_partial")
            return
        chunk = stream.readline(MAX_RECORD_BYTES + 3)
        if not chunk:
            if buffered or oversized:
                if follow:
                    if stop.is_set():
                        line_number += 1
                        yield InputLine(line_number, drop_reason="shutdown_partial")
                        return
                    stop.wait(poll_seconds)
                    continue
                line_number += 1
                if oversized or len(buffered) > MAX_RECORD_BYTES:
                    yield InputLine(line_number, error=FlowFeatureError("record_too_large"))
                else:
                    # A final line without LF is accepted by the underlying
                    # parser, but retain its category for payload-free metrics.
                    yield InputLine(line_number, bytes(buffered), drop_reason="input_partial")
                buffered.clear()
                oversized = False
                continue
            if follow:
                stop.wait(poll_seconds)
                continue
            return

        if oversized:
            # We retain only the state bit after crossing the bound.  The
            # bounded read has already consumed this physical line's prefix.
            if chunk.endswith(b"\n"):
                line_number += 1
                yield InputLine(line_number, error=FlowFeatureError("record_too_large"))
                oversized = False
            continue

        buffered.extend(chunk)
        if len(buffered) > MAX_RECORD_BYTES + 2 and not chunk.endswith(b"\n"):
            oversized = True
            buffered.clear()
        if not chunk.endswith(b"\n"):
            # The next read completes this line, or the follow loop waits at
            # EOF.  Do not expose partial input to the JSON parser.
            continue

        line_number += 1
        terminator_size = 2 if buffered.endswith(b"\r\n") else 1
        if len(buffered) - terminator_size > MAX_RECORD_BYTES:
            yield InputLine(line_number, error=FlowFeatureError("record_too_large"))
        else:
            yield InputLine(line_number, bytes(buffered))
        buffered.clear()
        oversized = False


@dataclass
class WorkerStats:
    """Payload-free counters suitable for a human or metrics collector."""

    status: str = "starting"
    detector_state: str = "STARTING"
    delivery_mode: str = "output_only"
    load_seconds: float = 0.0
    validated: int = 0
    rejected: int = 0
    queue_overflows: int = 0
    queue_depth: int = 0
    queue_peak: int = 0
    dropped_records: int = 0
    dropped_queue_overflow: int = 0
    dropped_shutdown: int = 0
    dropped_input_partial: int = 0
    dropped_oversize: int = 0
    dropped_malformed: int = 0
    abandoned_drops: int = 0
    inference_errors: int = 0
    inference_count: int = 0
    inference_seconds: float = 0.0
    inference_seconds_max: float = 0.0
    inference_seconds_mean: float = 0.0
    decisions_reserved: int = 0
    decisions_duplicate: int = 0
    ledger_capacity_drops: int = 0
    ledger_failures: int = 0
    anomalies: int = 0
    output_failures: int = 0
    delivered: int = 0
    delivery_duplicates: int = 0
    delivery_failures: int = 0
    lines_read: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, name: str, amount: float = 1) -> None:
        with self._lock:
            setattr(self, name, getattr(self, name) + amount)

    def set(self, name: str, value: Any) -> None:
        with self._lock:
            setattr(self, name, value)

    def observe_queue(self, depth: int) -> None:
        with self._lock:
            self.queue_depth = depth
            self.queue_peak = max(self.queue_peak, depth)

    def observe_inference(self, elapsed: float) -> None:
        with self._lock:
            self.inference_count += 1
            self.inference_seconds += elapsed
            self.inference_seconds_max = max(self.inference_seconds_max, elapsed)
            self.inference_seconds_mean = self.inference_seconds / self.inference_count

    def snapshot(self) -> dict[str, int | float | str]:
        with self._lock:
            return {
                "status": self.status,
                "detector_state": self.detector_state,
                "delivery_mode": self.delivery_mode,
                "load_seconds": self.load_seconds,
                "lines_read": self.lines_read,
                "validated": self.validated,
                "rejected": self.rejected,
                "queue_overflows": self.queue_overflows,
                "queue_depth": self.queue_depth,
                "queue_peak": self.queue_peak,
                "dropped_records": self.dropped_records,
                "dropped_queue_overflow": self.dropped_queue_overflow,
                "dropped_shutdown": self.dropped_shutdown,
                "dropped_input_partial": self.dropped_input_partial,
                "dropped_oversize": self.dropped_oversize,
                "dropped_malformed": self.dropped_malformed,
                "abandoned_drops": self.abandoned_drops,
                "inference_errors": self.inference_errors,
                "inference_count": self.inference_count,
                "inference_seconds": self.inference_seconds,
                "inference_seconds_max": self.inference_seconds_max,
                "inference_seconds_mean": self.inference_seconds_mean,
                "decisions_reserved": self.decisions_reserved,
                "decisions_duplicate": self.decisions_duplicate,
                "ledger_capacity_drops": self.ledger_capacity_drops,
                "ledger_failures": self.ledger_failures,
                "anomalies": self.anomalies,
                "output_failures": self.output_failures,
                "delivered": self.delivered,
                "delivery_duplicates": self.delivery_duplicates,
                "delivery_failures": self.delivery_failures,
            }


class ReserveStatus(str):
    RESERVED = "reserved"
    ALREADY_RESERVED = "already_reserved"
    CAPACITY = "capacity"


class DecisionLedger:
    """Durable, bounded, non-evicting reservation ledger."""

    def __init__(self, path: Path, max_entries: int) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        try:
            current = path.lstat()
        except FileNotFoundError:
            current = None
        except OSError:
            raise
        if current is not None and (
            stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode)
        ):
            raise ValueError("ledger must be a regular non-symlink file")
        self.path = path
        self.max_entries = max_entries
        # The inference consumer owns all mutations, but the ledger is opened
        # by the CLI thread before that consumer starts.
        self._connection = sqlite3.connect(
            str(path), timeout=5.0, isolation_level=None, check_same_thread=False
        )
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS ml_decisions ("
            "engine_instance_id TEXT NOT NULL, flow_id TEXT NOT NULL, "
            "detector TEXT NOT NULL, model_hash TEXT NOT NULL, event_id TEXT NOT NULL, "
            "is_anomaly INTEGER NOT NULL, reserved_at TEXT NOT NULL, "
            "PRIMARY KEY (engine_instance_id, flow_id, detector, model_hash))"
        )

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> DecisionLedger:  # noqa: PYI034
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def contains(self, result: MLDetectionResult) -> bool:
        identity = (
            result.engine_instance_id,
            result.flow_id,
            result.detector_name,
            result.model_sha256,
        )
        existing = self._connection.execute(
            "SELECT 1 FROM ml_decisions WHERE engine_instance_id=? AND flow_id=? "
            "AND detector=? AND model_hash=? LIMIT 1",
            identity,
        ).fetchone()
        return existing is not None

    def contains_identity(
        self, engine_instance_id: str, flow_id: str, detector: str, model_hash: str
    ) -> bool:
        existing = self._connection.execute(
            "SELECT 1 FROM ml_decisions WHERE engine_instance_id=? AND flow_id=? "
            "AND detector=? AND model_hash=? LIMIT 1",
            (engine_instance_id, flow_id, detector, model_hash),
        ).fetchone()
        return existing is not None

    def reserve(self, result: MLDetectionResult) -> str:
        """Atomically reserve a decision before any event output."""

        identity = (
            result.engine_instance_id,
            result.flow_id,
            result.detector_name,
            result.model_sha256,
        )
        event_id = deterministic_event_id(result)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self._connection.execute(
                "SELECT event_id FROM ml_decisions WHERE engine_instance_id=? AND flow_id=? "
                "AND detector=? AND model_hash=?",
                identity,
            ).fetchone()
            if existing is not None:
                self._connection.execute("COMMIT")
                return ReserveStatus.ALREADY_RESERVED
            count = self._connection.execute("SELECT COUNT(*) FROM ml_decisions").fetchone()
            if count is None or int(count[0]) >= self.max_entries:
                self._connection.execute("ROLLBACK")
                return ReserveStatus.CAPACITY
            self._connection.execute(
                "INSERT INTO ml_decisions VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
                (*identity, event_id, int(result.is_anomaly)),
            )
            self._connection.execute("COMMIT")
            return ReserveStatus.RESERVED
        except Exception:
            try:
                self._connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise


def _event_payload(result: MLDetectionResult, record: FlowFeatureRecordV2) -> dict[str, Any]:
    """Build the v1 event enriched with post-hoc attack classification."""

    classification = classify_attack(record.features, result.anomaly_score)

    return {
        "event_id": deterministic_event_id(result),
        "event_type": "ML_ANOMALY",
        "severity": classification.severity,
        "timestamp": result.inference_timestamp,
        "source_address": record.metadata.network.src_ip,
        "destination_address": record.metadata.network.dst_ip,
        "description": classification.description,
        "details": {
            "detector": "isolation_forest_v2",
            "detection_source": "ML",
            "attack_type": classification.attack_type,
            "confidence": classification.confidence,
            "result": result.to_dict(),
        },
    }


class MLWorker:
    """Bounded reader/inference/delivery pipeline."""

    def __init__(
        self,
        detector: DetectorLike,
        ledger: DecisionLedger,
        output: TextIO,
        *,
        transport: TransportLike | None = None,
        queue_capacity: int = DEFAULT_QUEUE_CAPACITY,
        shutdown_timeout_seconds: float = DEFAULT_SHUTDOWN_TIMEOUT,
    ) -> None:
        if not isinstance(queue_capacity, int) or isinstance(queue_capacity, bool) or queue_capacity <= 0:
            raise ValueError("queue_capacity must be positive")
        if (
            not isinstance(shutdown_timeout_seconds, (int, float))
            or isinstance(shutdown_timeout_seconds, bool)
            or not math.isfinite(float(shutdown_timeout_seconds))
            or shutdown_timeout_seconds <= 0
        ):
            raise ValueError("shutdown timeout must be a positive finite number")
        self.detector = detector
        self.ledger = ledger
        self.output = output
        self.transport = transport
        self.queue_capacity = queue_capacity
        self.shutdown_timeout_seconds = shutdown_timeout_seconds
        detector_state = getattr(detector.state, "value", str(detector.state))
        load_seconds = getattr(detector, "load_seconds", 0.0)
        if not isinstance(load_seconds, (int, float)) or not math.isfinite(float(load_seconds)):
            load_seconds = 0.0
        self.stats = WorkerStats(
            detector_state=str(detector_state),
            delivery_mode="control_plane" if transport is not None else "output_only",
            load_seconds=float(load_seconds),
        )
        self.stop_event = threading.Event()
        self._output_lock = threading.Lock()
        self._inference_thread: threading.Thread | None = None

    @property
    def resources_may_be_in_use(self) -> bool:
        """Whether a timed-out daemon thread still owns worker resources."""

        return self._inference_thread is not None and self._inference_thread.is_alive()

    def stop(self) -> None:
        self.stop_event.set()

    def run(
        self,
        stream: BinaryIO,
        *,
        follow: bool = False,
        poll_seconds: float = DEFAULT_FOLLOW_POLL_SECONDS,
    ) -> dict[str, int | float | str]:
        work: queue.Queue[tuple[FlowFeatureRecordV2, int] | None] = queue.Queue(
            maxsize=self.queue_capacity
        )

        inference_stop = threading.Event()

        def inference_loop() -> None:
            while True:
                try:
                    item = work.get(timeout=0.05)
                except queue.Empty:
                    if inference_stop.is_set():
                        return
                    continue
                self.stats.observe_queue(work.qsize())
                try:
                    if item is None:
                        return
                    record, _line = item
                    self._process(record)
                finally:
                    work.task_done()

        inference_thread = threading.Thread(target=inference_loop, name="ml-inference", daemon=True)
        self._inference_thread = inference_thread
        inference_thread.start()
        self.stats.set("status", "running")
        try:
            for line in iter_bounded_jsonl(
                stream, follow=follow, stop_event=self.stop_event, poll_seconds=poll_seconds
            ):
                self.stats.add("lines_read")
                if line.error is not None:
                    self.stats.add("rejected")
                    self.stats.add("dropped_records")
                    if line.error.code == "record_too_large":
                        self.stats.add("dropped_oversize")
                    else:
                        self.stats.add("dropped_malformed")
                    continue
                if line.drop_reason == "shutdown_partial":
                    self.stats.add("dropped_records")
                    self.stats.add("dropped_shutdown")
                    continue
                assert line.raw is not None
                try:
                    record = parse_flow_feature_record_v2(line.raw)
                except FlowFeatureError:
                    self.stats.add("rejected")
                    self.stats.add("dropped_records")
                    self.stats.add("dropped_malformed")
                    continue
                if line.drop_reason == "input_partial":
                    self.stats.add("dropped_input_partial")
                self.stats.add("validated")
                try:
                    work.put_nowait((record, line.line_number))
                    self.stats.observe_queue(work.qsize())
                except queue.Full:
                    # Drop-newest: the reader never blocks behind slow ML or
                    # HTTP and never grows an unbounded in-memory backlog.
                    self.stats.add("queue_overflows")
                    self.stats.add("dropped_queue_overflow")
                    self.stats.add("dropped_records")
        except OSError:
            self.stats.set("status", "input_failure")
        finally:
            # Let already-admitted records drain, but do not wait forever on a
            # producer or transport that ignored the bounded timeout contract.
            deadline = time.monotonic() + self.shutdown_timeout_seconds
            sentinel_queued = False
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    work.put(None, timeout=min(0.05, remaining))
                    sentinel_queued = True
                    break
                except queue.Full:
                    if not inference_thread.is_alive():
                        break
            while sentinel_queued and work.unfinished_tasks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.01, remaining))
            inference_thread.join(timeout=max(0.0, deadline - time.monotonic()))
            if inference_thread.is_alive() or work.unfinished_tasks:
                inference_stop.set()
                abandoned = 0
                while True:
                    try:
                        pending = work.get_nowait()
                    except queue.Empty:
                        break
                    work.task_done()
                    if pending is not None:
                        abandoned += 1
                if abandoned:
                    self.stats.add("abandoned_drops", abandoned)
                    self.stats.add("dropped_shutdown", abandoned)
                    self.stats.add("dropped_records", abandoned)
                self.stats.observe_queue(work.qsize())
                self.stats.set("status", "shutdown_timeout")
            elif self.stats.snapshot()["status"] == "running":
                self.stats.set("status", "stopped")
        return self.stats.snapshot()

    def _process(self, record: FlowFeatureRecordV2) -> None:
        if self._already_reserved(record):
            self.stats.add("decisions_duplicate")
            return
        started = time.perf_counter()
        try:
            result = self.detector.detect(record)
        except Exception:  # noqa: BLE001 - inference must isolate one bad record
            self.stats.observe_inference(time.perf_counter() - started)
            self.stats.add("inference_errors")
            self._update_detector_state()
            return
        self.stats.observe_inference(time.perf_counter() - started)
        self._update_detector_state()
        try:
            reservation = self.ledger.reserve(result)
        except (OSError, sqlite3.Error):
            self.stats.add("ledger_failures")
            return
        if reservation == ReserveStatus.ALREADY_RESERVED:
            self.stats.add("decisions_duplicate")
            return
        if reservation == ReserveStatus.CAPACITY:
            self.stats.add("ledger_capacity_drops")
            return
        self.stats.add("decisions_reserved")
        if not result.is_anomaly:
            return
        self.stats.add("anomalies")
        payload = _event_payload(result, record)
        try:
            with self._output_lock:
                self.output.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
                self.output.flush()
        except (OSError, ValueError):
            self.stats.add("output_failures")
            return
        if self.transport is None:
            return
        try:
            delivery = self.transport.send(payload)
            status = getattr(delivery, "status", None)
            if status is DeliveryStatus.DELIVERED or status == DeliveryStatus.DELIVERED:
                self.stats.add("delivered")
            elif status is DeliveryStatus.DUPLICATE or status == DeliveryStatus.DUPLICATE:
                self.stats.add("delivery_duplicates")
            else:
                self.stats.add("delivery_failures")
        except Exception:  # noqa: BLE001 - delivery failures are payload-free
            self.stats.add("delivery_failures")

    def _update_detector_state(self) -> None:
        try:
            state = self.detector.state
            self.stats.set("detector_state", getattr(state, "value", str(state)))
        except Exception:  # noqa: BLE001 - state metrics must not affect processing
            self.stats.set("detector_state", "UNKNOWN")

    def _already_reserved(self, record: FlowFeatureRecordV2) -> bool:
        """Skip scoring when the real detector exposes its locked model hash."""

        artifacts = getattr(self.detector, "artifacts", None)
        model_hash = getattr(artifacts, "model_sha256", None)
        if not isinstance(model_hash, str):
            return False
        detector_name = getattr(self.detector, "detector_name", "isolation_forest_v2")
        if not isinstance(detector_name, str):
            return False
        try:
            return self.ledger.contains_identity(
                record.metadata.engine_instance_id,
                record.metadata.flow_id,
                detector_name,
                model_hash,
            )
        except (OSError, sqlite3.Error):
            # The authoritative reserve still fails closed below if the ledger
            # is unavailable; a pre-check must never turn that into a decision.
            return False


def _path_key(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _assert_distinct(paths: Sequence[Path]) -> None:
    keys = [_path_key(path) for path in paths]
    if len(set(keys)) != len(keys):
        raise ValueError("input, output, ledger, stats, and artifacts must be distinct")
    for index, first in enumerate(paths):
        for second in paths[index + 1 :]:
            try:
                if first.exists() and second.exists() and os.path.samefile(first, second):
                    raise ValueError("input, output, ledger, stats, and artifacts must be distinct")
            except FileNotFoundError:
                continue


def _assert_regular_input(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("input must be a regular non-symlink file")


def _assert_new_file(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise
    if stat.S_ISLNK(info.st_mode):
        raise ValueError(f"{label} must not be a symlink")
    raise ValueError(f"{label} output must be a new file")


def _assert_ledger_path(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("ledger must be a regular non-symlink file")


def _is_within(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def _assert_write_locations(
    input_path: Path,
    output_path: Path,
    ledger_path: Path,
    stats_path: Path | None,
    status_path: Path | None,
    artifact_paths: Sequence[Path],
) -> None:
    write_paths = [output_path, ledger_path]
    if stats_path is not None:
        write_paths.append(stats_path)
    if status_path is not None:
        write_paths.append(status_path)
    protected_dirs = {_path_key(input_path.parent)}
    protected_dirs.update(_path_key(path.parent) for path in artifact_paths)
    for write_path in write_paths:
        resolved = _path_key(write_path)
        if any(_is_within(resolved, directory) for directory in protected_dirs):
            raise ValueError("worker outputs must be outside input and artifact directories")

    # SQLite may create these files after the initial ledger check.  Reserve
    # their names as well so they cannot alias an input, output, stats, or
    # immutable artifact path.
    protected_paths = [input_path, output_path, ledger_path, *artifact_paths]
    if stats_path is not None:
        protected_paths.append(stats_path)
    if status_path is not None:
        protected_paths.append(status_path)
    sidecar_paths = [
        path
        for path in protected_paths
        for suffix in ("", "-wal", "-shm")
        for path in (_path_key(Path(str(path) + suffix)),)
    ]
    _assert_distinct(sidecar_paths)
    for path in (Path(str(ledger_path) + "-wal"), Path(str(ledger_path) + "-shm")):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ValueError("ledger sidecars must be regular non-symlink files")


def _write_stats(path: Path, stats: Mapping[str, int | float | str]) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(dict(stats), stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")


def _write_status(path: Path | None, state: str, detector_state: str, reason: str | None = None) -> None:
    """Publish a payload-free runtime status document for local orchestration."""

    if path is None:
        return
    if path.is_symlink():
        raise ValueError("status file must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    payload: dict[str, str] = {"state": state, "detector_state": detector_state}
    if reason:
        payload["reason"] = reason
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    os.replace(temporary, path)


def _positive_float_arg(value: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("must be a positive finite number") from None
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Optional bounded ML worker for flow_features.v2 JSONL")
    parser.add_argument("input", metavar="INPUT", help="operator-managed local JSONL staging file")
    parser.add_argument("--output", required=True, help="new anomaly JSONL output (must not exist)")
    parser.add_argument("--ledger", required=True, help="durable SQLite decision ledger")
    parser.add_argument("--stats", help="new payload-free JSON stats file (must not exist)")
    parser.add_argument("--status-file", help="replaceable payload-free runtime status JSON file")
    parser.add_argument("--follow", action="store_true", help="wait for complete newline-terminated records")
    parser.add_argument("--queue-capacity", type=int, default=DEFAULT_QUEUE_CAPACITY)
    parser.add_argument("--shutdown-timeout", type=_positive_float_arg, default=DEFAULT_SHUTDOWN_TIMEOUT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(list(argv) if argv is not None else None)
    status_path = Path(args.status_file).expanduser() if args.status_file else None
    try:
        config = MLConfig.from_env()
    except ValueError as error:
        _write_status(status_path, "FAILED", DetectorState.FAILED.value, "configuration_failure")
        print(json.dumps({"status": "configuration_failure", "failure": type(error).__name__}))
        return 2
    # Disabled is a true no-op: no input/output/ledger/model path is opened.
    if not config.enabled:
        _write_status(status_path, "DISABLED", DetectorState.DEGRADED.value, "disabled_by_configuration")
        print(json.dumps({"status": "disabled", "detector_state": DetectorState.DEGRADED.value}))
        return 0
    if args.queue_capacity <= 0:
        _write_status(status_path, "FAILED", DetectorState.FAILED.value, "invalid_queue_capacity")
        print("queue capacity must be positive", file=sys.stderr)
        return 2
    detector = MLDetector(config)
    if detector.state is not DetectorState.READY:
        _write_status(status_path, "FAILED", detector.state.value, "artifact_validation_failed")
        print(json.dumps({"status": "detector_failed", "detector_state": detector.state.value}))
        return 1
    _write_status(status_path, "READY", detector.state.value)
    input_path = Path(args.input).expanduser()
    output_path = Path(args.output).expanduser()
    ledger_path = Path(args.ledger).expanduser()
    stats_path = Path(args.stats).expanduser() if args.stats else None
    artifact_paths = [
        path
        for path in (
            config.model_path,
            config.threshold_path,
            config.feature_schema_path,
            config.feature_contract_path,
            config.model_metadata_path
            or (config.model_path.with_name("model_metadata.json") if config.model_path else None),
        )
        if path is not None
    ]
    input_stream: BinaryIO | None = None
    output_stream: TextIO | None = None
    ledger: DecisionLedger | None = None
    transport: ControlPlaneTransport | None = None
    worker: MLWorker | None = None
    resources_deferred = False
    try:
        _assert_regular_input(input_path)
        _assert_new_file(output_path, "output")
        if stats_path is not None:
            _assert_new_file(stats_path, "stats")
        if status_path is not None and status_path.is_symlink():
            raise ValueError("status file must not be a symlink")
        _assert_ledger_path(ledger_path)
        protected_paths: list[Path] = [input_path, output_path, ledger_path, *artifact_paths]
        if stats_path is not None:
            protected_paths.append(stats_path)
        if status_path is not None:
            protected_paths.append(status_path)
        _assert_distinct(protected_paths)
        _assert_write_locations(input_path, output_path, ledger_path, stats_path, status_path, artifact_paths)
        input_stream = input_path.open("rb")
        output_stream = output_path.open("x", encoding="utf-8")
        max_entries = parse_dedup_limit()
        ledger = DecisionLedger(ledger_path, max_entries)
        if os.environ.get("INTRIQO_CONTROL_PLANE_URL") or os.environ.get(
            "INTRIQO_CONTROL_PLANE_TOKEN"
        ):
            transport = ControlPlaneTransport(TransportConfig.from_env())
        worker = MLWorker(
            detector,
            ledger,
            output_stream,
            transport=transport,
            queue_capacity=args.queue_capacity,
            shutdown_timeout_seconds=args.shutdown_timeout,
        )
        previous_handlers = {
            signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)
        }

        def request_stop(_signum: int, _frame: Any) -> None:
            assert worker is not None
            worker.stop()

        signal.signal(signal.SIGINT, request_stop)
        signal.signal(signal.SIGTERM, request_stop)
        try:
            assert input_stream is not None
            stats = worker.run(input_stream, follow=args.follow)
        finally:
            resources_deferred = worker.resources_may_be_in_use
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        if stats_path is not None:
            _write_stats(stats_path, stats)
        _write_status(status_path, "STOPPED", detector.state.value)
    except (OSError, ValueError, sqlite3.Error) as error:
        # Never echo exception text: it can contain paths, URLs, or driver
        # details.  The status remains explicit but payload-free.
        _write_status(status_path, "FAILED", DetectorState.FAILED.value, "startup_failure")
        print(json.dumps({"status": "startup_failure", "failure": type(error).__name__}))
        return 1
    finally:
        if not resources_deferred:
            if transport is not None:
                transport.close()
            if ledger is not None:
                ledger.close()
            if output_stream is not None:
                output_stream.close()
            if input_stream is not None:
                input_stream.close()
    print(json.dumps(stats, sort_keys=True, separators=(",", ":")))
    return 0 if stats.get("status") == "stopped" else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DecisionLedger",
    "InputLine",
    "MLWorker",
    "ReserveStatus",
    "WorkerStats",
    "iter_bounded_jsonl",
    "main",
]
