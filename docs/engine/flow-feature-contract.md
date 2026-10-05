# FlowFeatureRecord v1 — data contract, not an ML model

## Pre-change audit (2026-10-05)

The working tree was clean on `main` before this phase. The audit inspected
`features.hpp`, `extractor.cpp`, `flow.hpp`, `flow_table.cpp`, the IPv4 parser,
pipeline/runtime implementations, SecurityEvent serialization and file/queued
event sinks, CMake/CTest, flow/feature/detector/runtime tests, Python project
configuration, existing end-to-end fixtures and benchmark tools.

`FlowFeatures` currently supplies `packet_count`, `byte_count`,
`duration_seconds`, `bytes_per_packet`, `packets_per_second`, `bytes_per_second`,
`syn_count`, `fin_count`, `rst_count`, `initial_syn_count`, `syn_ack_count`,
`ack_count`, `tcp_handshake_started`, `tcp_syn_ack_seen`, and
`tcp_handshake_completed`. The legacy `connection_attempts` is a uint32 cast of
total packet count, not observed TCP attempts; it is deliberately **excluded**
from this contract without changing the existing detector inputs.

`NetworkFlow` additionally contains forward/reverse packet and byte counts,
the existing monotonically assigned uint64 `flow_id`, a first-observed oriented
five-tuple, `first_seen`, and nondecreasing `last_seen`. Byte accounting sums
parsed IPv4 total lengths, including IP/transport headers but excluding Ethernet
and not counting only application payload. Only successfully parsed packets
contribute; capture loss, parser rejection and hidden traffic are not inferred.

The flow table searches direct then reverse tuples, expires on idle age >=
timeout, deterministically evicts oldest `(last_seen, flow_id)` at its capacity,
and flushes remaining flows in the same order. FIN/RST are counted, not actual
retirement signals; `FlowState::FINISHED` is an enum, not an implemented close
state machine. Existing handshake evidence is ordered flags/direction only,
without TCP sequence/acknowledgment-number verification. Late packets contribute
counts but do not rewind timestamps; `first_seen` is creation time, not the
minimum of subsequently arriving late timestamps.

Not available/reliable for v1: packet-size distributions/variance, interarrival
statistics, payload bytes/content, RTT, retransmissions, TCP sequence validation,
window statistics, application identity, labels, anomaly scores, capture-loss
per-flow attribution, or IPv6. No dataset columns are fabricated.

C++ has no JSON library dependency: SecurityEvent uses a small handwritten
serializer. Its event contract is left unchanged. Feature serialization uses
fixed ordering, locale-independent round-trip double precision, complete JSON
string escaping, finite numeric checks and checked UTC timestamp formatting.
The Python ML folder has reserved directories and a pyproject but no implemented
worker or consumer; the new consumer will not import ML libraries.

## Frozen v1 boundary

JSON object: required `schema_version`, `metadata`, `features`. Version is exactly
`flow_features.v1`. All fields listed below are required, never null; unknown
fields are rejected at every level. Adding a field or changing semantics requires
a new version; a future explicitly dispatched v2 parser must not reinterpret v1.

`metadata` contains `engine_instance_id` (canonical lowercase UUID), `flow_id`
(canonical nonzero decimal uint64 string), `first_seen`, `timestamp` (last packet
time), `export_reason` (`idle_expired`, `capacity_evicted`, `shutdown_flush`), and
`network` (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`). Timestamps use
UTC RFC3339 with exactly nine fractional digits and `Z`. The existing engine ID
is not replaced: correlation key is `(engine_instance_id, flow_id)`, and the UUID
only scopes the existing counter across process/pipeline lifetimes.

`features` contains the 15 trustworthy FlowFeatures fields above and the four
directional NetworkFlow counters (`fwd_packet_count`, `rev_packet_count`,
`fwd_byte_count`, `rev_byte_count`). No normalization or calculation in Python.

The implementation and measured validation report will document the complete
field table, operational behavior, commands and actual results below.

## Complete v1 example

This is the three-packet, one-second handshake used by the C++ contract test:

```json
{
  "schema_version": "flow_features.v1",
  "metadata": {
    "engine_instance_id": "01234567-89ab-4cde-8f01-23456789abcd",
    "flow_id": "42",
    "first_seen": "2023-11-14T22:13:20.000000000Z",
    "timestamp": "2023-11-14T22:13:21.000000000Z",
    "export_reason": "idle_expired",
    "network": {
      "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
      "src_port": 40000, "dst_port": 443, "protocol": "TCP"
    }
  },
  "features": {
    "packet_count": 3, "byte_count": 120, "duration_seconds": 1,
    "bytes_per_packet": 40, "packets_per_second": 3, "bytes_per_second": 120,
    "fwd_packet_count": 2, "rev_packet_count": 1,
    "fwd_byte_count": 80, "rev_byte_count": 40,
    "syn_count": 2, "fin_count": 0, "rst_count": 0,
    "initial_syn_count": 1, "syn_ack_count": 1, "ack_count": 1,
    "tcp_handshake_started": true, "tcp_syn_ack_seen": true,
    "tcp_handshake_completed": true
  }
}
```

## Field contract

Every field is **required and non-null**. There are no optional v1 fields.
`uint64` means JSON integer token in `[0, 18446744073709551615]`; `uint32`
means integer token in `[0, 4294967295]`. Ports are integer tokens in
`[0, 65535]`. Boolean values must be actual JSON booleans, not `0`/`1`.
Float64 measurements are finite in `[0, DBL_MAX]`; JSON integer spelling such
as `1` is allowed for a floating measurement. Integer counters are serialized
without floating conversion; consumers must not route them through JavaScript
Number or another lossy intermediate. Float-derived values retain the existing
extractor's binary64 rounding; this is not arbitrary-precision arithmetic.

### Identification/correlation metadata (not a normalized feature vector)

| Name/path | Type/unit/range | Meaning and source |
|---|---|---|
| `schema_version` | string, exact `flow_features.v1` | Explicit wire semantics; never inferred from field presence |
| `metadata.engine_instance_id` | canonical lowercase 36-character UUID | Generated once for the enabled pipeline lifetime, normally UUID v4; scopes the existing flow counter across restarts; callers supplying IDs must keep scopes unique |
| `metadata.flow_id` | canonical decimal string, `1..UINT64_MAX`, no leading zero | Existing `NetworkFlow.flow_id`, not a new tuple hash or unrelated identity |
| `metadata.first_seen` | UTC RFC3339 string, 9 fractional digits, year `0001..9999` | Timestamp of the packet that created the flow |
| `metadata.timestamp` | same timestamp type, `>= first_seen` | Existing nondecreasing `last_seen`, not emission time or idle-expiry time |
| `metadata.export_reason` | enum string | `idle_expired`, `capacity_evicted`, or `shutdown_flush`; lifecycle metadata, not an anomaly label |
| `metadata.network.src_ip` | canonical dotted IPv4 string | Source of first-observed tuple; not necessarily the true client/initiator |
| `metadata.network.dst_ip` | canonical dotted IPv4 string | Destination of first-observed tuple |
| `metadata.network.src_port` | uint16, port number | First tuple's source port; parser supplies zero for ICMP/OTHER |
| `metadata.network.dst_port` | uint16, port number | First tuple's destination port; parser supplies zero for ICMP/OTHER |
| `metadata.network.protocol` | `TCP`, `UDP`, `ICMP`, `OTHER` | Existing parser category; OTHER does not preserve the original unsupported IP protocol number |

Native C++ clock bounds can be narrower than the RFC3339 range. This Linux build
supports `1677-09-21T00:12:43.145224192Z` through
`2262-04-11T23:47:16.854775807Z`. Nanoseconds are preserved as strings in Python;
`NanosecondTimestamp` exposes UTC whole seconds plus integer nanoseconds.
`as_datetime()` rejects conversions that would silently lose submicrosecond data.

### Measurements

Forward means the first observed tuple; reverse means its exact swapped tuple.
"Total" means both directions, **successfully parsed captured packets only**.
Counts include retransmitted/duplicate observations; they are not estimated
unique wire packets. All values are copied/extracted by C++; Python validates
types/invariants but does not recreate feature calculations.

| Feature name | Type / unit | Direction | Meaning / calculation | Kind |
|---|---|---|---|---|
| `packet_count` | uint64 / packets | total | Number of accepted packet observations accumulated in this flow | raw |
| `byte_count` | uint64 / bytes | total | Sum of parsed IPv4 `total_length`, including IPv4 and transport headers, excluding Ethernet | raw |
| `duration_seconds` | float64 / seconds | total | `last_seen - first_seen`, using widened clock ticks before subtraction; nonnegative | derived |
| `bytes_per_packet` | float64 / bytes/packet | total | `byte_count / packet_count`; zero when packet count is zero | derived mean/ratio |
| `packets_per_second` | float64 / packets/second | total | `packet_count / duration_seconds`; **zero** when duration is zero | derived rate |
| `bytes_per_second` | float64 / bytes/second | total | `byte_count / duration_seconds`; **zero** when duration is zero | derived rate |
| `fwd_packet_count` | uint64 / packets | forward | Existing forward packet counter | raw |
| `rev_packet_count` | uint64 / packets | reverse | Existing reverse packet counter; not a guessed response count | raw |
| `fwd_byte_count` | uint64 / bytes | forward | Sum of forward IPv4 total lengths | raw |
| `rev_byte_count` | uint64 / bytes | reverse | Sum of reverse IPv4 total lengths | raw |
| `syn_count` | uint32 / packets | total | TCP packets with SYN bit set, including SYN-ACK and unusual flag combinations | raw flag count |
| `fin_count` | uint32 / packets | total | TCP packets with FIN bit set | raw flag count |
| `rst_count` | uint32 / packets | total | TCP packets with RST bit set | raw flag count |
| `initial_syn_count` | uint32 / packets | total | TCP flags masked by SYN/ACK/FIN/RST equal SYN only; repeated initial SYN observations are included | raw flag count |
| `syn_ack_count` | uint32 / packets | total | Same mask equals SYN+ACK, excluding FIN/RST | raw flag count |
| `ack_count` | uint32 / packets | total | Same mask equals ACK, excluding SYN/FIN/RST; includes ACK data packets, not all ACK-bit packets | raw flag count |
| `tcp_handshake_started` | bool / evidence | first forward packet | First packet is TCP initial SYN (no ACK/FIN/RST); later SYNs cannot establish this retroactively | derived ordered evidence |
| `tcp_syn_ack_seen` | bool / evidence | reverse | After started evidence, reverse SYN+ACK without FIN/RST observed | derived ordered evidence |
| `tcp_handshake_completed` | bool / evidence | forward | After SYN-ACK evidence, forward ACK without SYN/FIN/RST observed; no sequence-number validation | derived ordered evidence |

Other TCP flag bits (PSH/ECE/CWR/URG) are not excluded by the four-bit masks.
For non-TCP records all six TCP counts are zero and all three booleans false;
zero/false means **no applicable observed evidence**, not proof of a healthy flow.
Directional totals must sum exactly to their totals; an empty direction cannot
contain bytes. Each TCP flag count must not exceed packet count, initial SYN +
SYN-ACK must not exceed SYN, and SYN + ACK-only must not exceed packet count.
Handshake implications/directions are checked. These are validity constraints,
not preprocessing, normalization, or inference. Native counters retain their
existing widths; no overflow recovery or lost-packet reconstruction is invented.

## Lifecycle and emission decision

Streaming is **opt-in**, disabled by default. `PipelineImpl::retire()` evaluates
the existing deterministic detectors with their original inputs, retires their
flow identity, then constructs/adopts one feature record. It never passes a raw
packet or application payload to the feature sink.

| Boundary | Export reason | Behavior |
|---|---|---|
| Idle age >= configured timeout | `idle_expired` | Emitted once when packet-time expiry or live idle maintenance actually removes the flow |
| Active flow capacity pressure | `capacity_evicted` | Oldest timestamp/ID flow emitted once, preserving useful partial evidence |
| EOF, explicit pipeline flush, SIGINT/SIGTERM, runtime error cleanup | `shutdown_flush` | Remaining flows emitted once before closing/draining the feature sink |
| FIN/RST | none immediately | Counters remain in the same flow until ordinary retirement; trailing ACKs/retransmissions remain observable |
| Each packet / active snapshots | none | No packet-by-packet output or duplicate snapshots |

One-packet and same-timestamp flows are retained with zero duration/rates.
Incomplete/midstream handshakes are not discarded. Long-running active flows do
not emit until retirement; this is an intentional v1 latency limitation.
Expiry does not add idle time to duration. Late packets do not change the
first-observed orientation or rewind timestamps. A tuple observed again after
retirement receives the flow table's next existing ID. Repeated flush/maintenance
does not re-emit removed flows. Flow state limits and detector retirement ordering
are unchanged; no FIN close state machine is introduced.

## Serialization and version handling

- UTF-8 JSON Lines: one JSON object plus LF per record, no array wrapper or packet
  payload. File sink **appends**, never truncates prior data.
- Fixed field order and names, classic locale, binary64 `max_digits10` precision,
  integer-preserving counters and decimal-string ID. Repeated serialization of
  the same record is byte-identical; a fresh engine's UUID intentionally differs.
- UTC date/time formatting checks clock bounds, handles negative epochs without
  subtraction overflow, and preserves nine fractional digits. Construction
  validates numeric/time bounds without rendering timestamps; serialization
  and textual timestamp rendering execute in the file worker.
- All textual fields are validated/closed primitives and JSON-escaped. No
  free-form application text exists. Nonfinite/negative measurements and invalid
  metadata/accounting are rejected, not silently clamped or replaced.
- Maximum JSON body: **8192 bytes**, plus one LF on C++ output. Python also
  accepts a single CRLF or a final line without LF. Blank lines are malformed.
- The checked-in draft-07 schema is
  `contracts/features/flow_features_v1.json`, generated from the exact Pydantic
  wire models. A parity test prevents drift. Draft-07 cannot enforce directional
  sums, chronology, integer token spelling, duplicate keys, depth/byte budgets
  or all handshake implications; use the Python parser for complete validation.
- v1 has no optional fields. Unknown fields are rejected at every nesting level.
  Versioned changes must introduce a new schema and explicit consumer dispatch;
  unsupported versions raise `UnsupportedSchemaVersionError`, never reinterpret
  the record. C++ emits only v1 in this phase.

## Sink abstraction, failure, and backpressure

`transport::FlowFeatureSink` exposes `submit(record)`, `flush()`, and
`statistics()`. `submit(true)` is **admission**, not acknowledgment of delivery.
`FileFlowFeatureSink(path, capacity)` implements a single-use worker with a
preallocated ring of fixed-shape records; UUID storage is reserved before capture.
Default pending capacity is **4096**, configurable **1..65536**, plus at most
one in-flight record. There is no unbounded queue or Python/network callback.
Queue locks never span serialization or file I/O. This is short synchronized
admission, not a lock-free or hard-real-time guarantee.

- Overflow **drops newest**, increments `records_dropped` and `queue_overflows`,
  and preserves already admitted records. Deterministic capture continues.
- A malformed record/copy/serialization failure is dropped and counted in
  `validation_failures`; subsequent good records remain eligible.
- Open/thread/write/close failures disable the sink and increment
  `write_failures` once. Pending/in-flight/future rejected records are counted
  once as dropped; file payload/path/error text is not logged.
- Factory/allocation/UUID failures have separate `feature_setup_failures` or
  `feature_generation_failures`. Flow generation errors are caught before they
  can escape to packet ingestion. Optional setup failure warns and leaves the
  deterministic IDS available; ordinary inability to allocate the IDS itself
  is not masked as successful startup.
- Shutdown closes admission, drains or counts every loss, joins the worker and
  closes the descriptor. Flush is concurrent-safe and idempotent. False means
  recorded loss/failure, but the pipeline does not turn that into an IDS stop.
- Regular-file writes can stall despite `O_NONBLOCK`. **There is no hard shutdown
  deadline**; flush/destruction joins rather than detaching a live worker.
- Writes mean complete lines accepted by the kernel, not `fsync` durability.
  Partial writes/EINTR are handled; fatal partial writes can leave a truncated
  final line. There are no retries/replay guarantees. Restart appends; operators
  must isolate/remove a truncated tail before appending if needed.
- File growth itself is not capped/rotated. This is a local **validation sink**,
  not the final production transport or durable telemetry spool. Monitor disk
  space and apply retention outside the active writer; never claim zero loss.

Runtime/CLI expose the following separate feature counters (not security-event
sink failures): `feature_records_generated`, `feature_generation_failures`,
`feature_setup_failures`, `feature_records_submitted` (all attempts),
`feature_records_written`, `feature_records_dropped`, `feature_queue_depth`,
`feature_queue_peak_depth`, `feature_queue_overflows`, `feature_write_failures`,
`feature_validation_failures`, and generation/serialization/write seconds.
Generation seconds include admission; worker timings are elapsed, not CPU time.
After file flush: submitted = written + dropped, depth = 0. Pipeline-retired
flows = generated + generation failures when streaming is configured; disabled
streaming produces zero records. Live async snapshots can be transiently skewed.
The CLI warns on loss but returns success when deterministic IDS work succeeded;
inspect feature counters, not exit code alone, for telemetry completeness.

## Python validation consumer

`intriqo_ml.FlowFeatureRecord` and its nested frozen Pydantic v2 models separate
metadata/network from 19 measurement fields. `parse_flow_feature_record(str |
bytes)` rejects missing/null/wrong-type/extra fields, invalid enums/IPs/timestamps,
nonfinite/negative/out-of-range measurements, inconsistent counts/handshakes,
duplicate JSON keys, unsupported versions and depth beyond 16 containers.
`FlowFeatureError.code` and exception messages are bounded, payload-free diagnostics.

`consumer.read_line()` reads bounded binary chunks; oversized physical lines are
drained without accumulating them. `iter_flow_feature_records()` yields each
line's validated record or sanitized error and continues after malformed input.
The CLI prints validated/rejected counts; exit 0 is clean, 1 means rejected
records, 2 means file/argument errors. Consumption does not rewrite source data.
No ML dependencies are imported by this package; adding Pydantic is the only new
runtime dependency. Existing reserved ML dependencies are not exercised.

```bash
build/flow-release/engine/intriqo-engine --synthetic --synthetic-packets 30 \
  --output events.jsonl --feature-output features.jsonl --feature-queue-capacity 4096
PYTHONPATH=ml/src control-plane/.venv/bin/python -m intriqo_ml.consumer features.jsonl
# validated=10 rejected=0

INTRIQO_ENGINE_BINARY="$PWD/build/flow-release/engine/intriqo-engine" \
  control-plane/.venv/bin/python -m pytest ml/tests -c ml/pyproject.toml -q
PYTHONPATH=ml/src:engine/tests/fixtures \
  INTRIQO_ENGINE_BINARY="$PWD/build/flow-release/engine/intriqo-engine" \
  control-plane/.venv/bin/python -m pytest tests/e2e/test_flow_feature_boundary.py -q
```

Event/feature destinations must be separate files; CLI rejects known identical
paths/hardlinks to avoid mixed contracts. File readiness/failure is independent
of the event sink. No new environment variable, broker, service, or endpoint is
required. Normal deployment can install the src-layout `intriqo-ml` package;
the examples use its source path and the existing development interpreter.

## Privacy, security, and exact future integration point

The stream carries traffic-sensitive IP/port/time metadata, **never** raw
packets, payloads, JWTs, passwords, tokens, credentials, URLs or application logs.
Do not treat metadata as model input by default: a future worker should select
an explicit `.features` vector and retain metadata separately for correlation.
The C++ interface remains measurement-oriented, with no ML normalization.

The local sink pins parent directory descriptors, rejects symlinks in every
path component, sets `O_CLOEXEC`/`O_NOFOLLOW`, requires a regular file on a
recognized local Linux filesystem, and creates files with mode **0600**.
Existing permissions are retained and must be tightened by the operator when
necessary. Devices/FIFOs/FUSE/unknown or remote filesystem types are rejected;
this implementation is Linux-specific. The parent directory and executable
configuration must be trusted; do not share destinations between writers.
Payload-free errors and closed/escaped strings prevent telemetry/log injection.
The bounded parser is not a sandbox for arbitrary application data.

Future ML integration is **after**
`intriqo_ml.consumer.iter_flow_feature_records()` returns a validated record:
`record.features` goes to a future preprocessing/model pipeline, while
`record.metadata` supplies `(engine_instance_id, flow_id)` and the original
network/time context. Future results can use the existing SecurityEvent →
Control Plane boundary; that result conversion/correlation is not implemented
here. Existing deterministic SecurityEvents may aggregate many flows and are
not claimed to carry this new correlation key. A future transport implements
`FlowFeatureSink` behind the same retirement hook, preserving bounded admission
and independent failure. Any off-host stream must require **TLS, authentication,
authorization and retention policy**; no unauthenticated ML endpoint exists.

**IMPLEMENTED:** C++ → versioned flow feature record → bounded JSONL stream
boundary → Python validation. **NOT IMPLEMENTED:** ML training, inference,
anomaly scoring, model selection, preprocessing/normalization, ML SecurityEvent
generation, Kafka, Redis, frontend work or new detectors.

See [measured validation and file inventory](flow-feature-validation.md).
