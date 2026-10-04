# C++ IDS Engine

← [README](../../README.md) · [Historical runtime report](runtime-validation.md) · [Capture hardening measurements](capture-hardening-validation.md)

## Implemented scope

The C++20 IDS executable `intriqo-engine` passively captures packets, parses
IPv4/TCP/UDP/ICMP, rejects malformed/truncated input, tracks bidirectional flows,
extracts flow features, invokes registered deterministic detectors, serializes
SecurityEvent v1 JSON (UUID v4 IDs, UTC timestamps), and sends events to a file
or the existing authenticated FastAPI ingestion endpoint. `PortScanDetector`
is the only concrete detector enabled in this phase. No packet injection or
response/blocking action is implemented.

Live Linux, classic PCAP replay, and synthetic capture all use the same runtime,
parser, pipeline, registry, and sink path. Synthetic input is finite reproducible
test data, never transmitted onto a network.

## Architecture and boundaries

```text
Authorized live traffic / classic PCAP / synthetic packets
                        ↓
                    CaptureSource
                        ↓
              EngineImpl → IPv4Parser
                        ↓
           PipelineImpl → existing FlowTable
                        ↓
             FlowFeatures::from_flow
                        ↓
       DetectorRegistry → PortScanDetector
                        ↓
                SecurityEvent v1
                        ↓
            FileEventSink / HttpEventSink
                        ↓ HTTP
             FastAPI → PostgreSQL
                        ↓
          Existing agent platform / React SOC
```

`runtime::Engine` remains the abstract interface; `EngineImpl` is its concrete
blocking, single-run implementation. It owns capture, pipeline and event sink.
The registry implements the existing `Detector` interface, so
`PipelineImpl(std::unique_ptr<Detector>)` and direct detector usage remain valid.

The C++ boundary remains capture/parsing/flows/features/deterministic detection/
event generation. Python remains ingestion/persistence/incidents/tasks/findings/
audit/policy. Agents remain investigation/orchestration with constrained tools;
React remains presentation. This phase adds no infrastructure or layer migration.

### Lifecycle

Configure dependencies and optional observers before `run()`. A readiness
observer runs after the concrete source has initialized; a packet callback
borrows capture-owned bytes only for that callback. Capture errors throw
descriptive exceptions. `stop()` and `metrics()` are thread-safe while `run()`
blocks. Source and engine instances are single-use; create new instances to
restart. A stop requested before startup is retained.

EOF, SIGINT, SIGTERM, source failure, and delivery failure finish through the
same shutdown path: stop capture, finish synchronous callbacks, flush active
flows/reset detector state, flush the sink, freeze runtime duration, then
report errors. The CLI signal handler only writes a lock-free flag; a sleeping
watcher requests stop outside signal context. Capture uses `poll` and an
`eventfd` wakeup, with bounded nonselectable-device retry, not a busy loop.
Sink failures stop capture and return a nonzero exit code after cleanup. Optional
queued delivery closes admission, drains admitted events and joins its worker
before the final summary; admission is not counted as successful delivery.

## Build and prerequisites

Requirements: CMake ≥ 3.24, C++20 compiler, threads; GoogleTest for C++ tests and
Python 3 for CLI tests. CMake downloads GoogleTest 1.14.0 unless an existing
source tree is provided with `FETCHCONTENT_SOURCE_DIR_GOOGLETEST`.

```bash
# Debian/Ubuntu, if live capture is wanted (administrator-managed installation):
sudo apt install libpcap-dev

cmake -S . -B build/runtime-release -DCMAKE_BUILD_TYPE=Release -DINTRIQO_BUILD_TESTS=ON
cmake --build build/runtime-release --parallel
ctest --test-dir build/runtime-release --output-on-failure
build/runtime-release/engine/intriqo-engine --help

# Explicit offline-only build; missing libpcap also automatically permits offline modes:
cmake -S . -B build/runtime-offline -DCMAKE_BUILD_TYPE=Release -DINTRIQO_ENABLE_PCAP=OFF
```

Standalone `cmake -S engine -B engine/build ...` and `make engine-test` remain
supported; their executable path is `engine/build/intriqo-engine`. Do not reuse
a CMake cache after moving the checkout: configure a fresh build directory.
Custom libpcap installations can use `CMAKE_PREFIX_PATH`, or `PCAP_INCLUDE_DIR`
and `PCAP_LIBRARY` when pkg-config is unavailable. The live-disabled binary
fails clearly when `--interface` is requested instead of silently using a stub.

Live capture requires Linux and authorization to open the interface, normally
`CAP_NET_RAW` or administrator-approved root execution. Some capture settings
may require additional OS privileges. Do not grant capture rights to arbitrary
untrusted executables. The engine never escalates its own privileges.

## Capture modes and CLI

Select **exactly one** capture mode:

```bash
build/runtime-release/engine/intriqo-engine --synthetic --output events.jsonl
build/runtime-release/engine/intriqo-engine --pcap authorized-input.pcap --output events.jsonl
build/runtime-release/engine/intriqo-engine --interface eth0
build/runtime-release/engine/intriqo-engine --interface eth0 --filter "tcp" --no-promiscuous
build/runtime-release/engine/intriqo-engine --interface eth0 --snaplen 65535 --sink http
```

| Mode | Implementation and requirements |
|---|---|
| Synthetic | `SyntheticCaptureSource`: checksummed Ethernet/IPv4/TCP SYN fixtures with documentation-only addresses; fixed epoch and 1 ms timestamp increments; finite input, no privileges |
| PCAP | Existing `PcapReplaySource`: classic PCAP 2.4; little/big endian, micro/nanosecond precision; explicit record validation; no libpcap required |
| Live | `LiveCaptureSource`: Linux libpcap, selected interface, BPF filter, configurable snaplen/promiscuity, correct caplen/original length and micro/nanosecond timestamps |

Supported capture datalinks: Ethernet, raw IP/IPv4/IPv6, BSD NULL/LOOP, Linux
cooked SLL/SLL2. Cooked/loopback frames normalize into the existing parser's
Ethernet/raw-IP representation. Original captured and wire lengths remain
separate from normalized byte lengths, so header normalization cannot fabricate
or conceal truncation. Non-IPv4 input is rejected; normalization is not IPv6
parsing support. Unsupported datalinks fail clearly. Captured data is not padded
to wire length. Classic PCAP malformed headers/records are errors, not normal EOF.

The CLI replays PCAP as fast as possible. `PcapReplayConfig::realtime=true` is
available to library callers and uses interruptible pacing. Replay does not
inject traffic. BPF/snaplen/promiscuity CLI flags are live-only.

**Local capture does not imply network-wide monitoring.** Visibility depends on
what the selected interface receives. Network-wide visibility needs an
authorized SPAN/mirror port, TAP, or equivalent network configuration.
Promiscuous mode is not a substitute for an appropriate traffic source.

## Runtime configuration

| Option | Default / meaning |
|---|---|
| `--interface IFACE` / `--pcap FILE` / `--synthetic` | Exactly one required |
| `--filter EXPR` | No BPF filter by default; libpcap validates expression |
| `--snaplen BYTES` | 65535, accepted range 1..16777216; small values can deliberately truncate input |
| `--no-promiscuous` | Promiscuous mode otherwise enabled |
| `--capture-buffer-bytes BYTES` | 16777216 (16 MiB), positive libpcap kernel buffer request; live only |
| `--capture-timeout-ms MS` | 100, range 1..60000; buffered capture timeout, live only |
| `--capture-immediate` | Off by default; disables buffering, live only |
| `--flow-idle-timeout SECONDS` | 60, finite positive idle expiration |
| `--max-active-flows N` | 100000, positive active-flow capacity |
| `--max-tracked-sources N` | 4096, positive port-scan source-window capacity |
| `--max-tracked-observations N` | 100000, positive counted flow-ID capacity |
| `--sink file\|http` | `file` |
| `--event-queue-capacity N` | 0 (synchronous); 1..1000000 enables bounded pending-event ring plus one in flight |
| `--output PATH` | `intriqo-events.jsonl`, file mode only |
| `--control-plane-url URL` | Overrides environment base URL, HTTP mode only |
| `--portscan-window SECONDS` | 10, finite and positive |
| `--portscan-unique-port-threshold N` | 10, range 1..65535 |
| `--portscan-minimum-attempts N` | 10, positive |
| `--synthetic-packets N` | 10, positive CLI count (library permits empty input) |
| `--synthetic-unique-ports N` | 10, range 1..65535 |
| `--log-level error\|info\|debug` | `info`; errors always reported, `debug` adds runtime diagnostic; required startup/shutdown summaries remain visible at all levels |
| `--help` | Usage without initializing capture |

Aliases: `--synthetic-packet-count`, `--portscan-window-seconds`.
Invalid options return exit code 2; initialization/runtime/delivery errors return
1; normal EOF and graceful SIGINT/SIGTERM return 0. No credentials can be set
through a CLI token argument. CLI state/queue values override these environment
defaults: `INTRIQO_FLOW_IDLE_TIMEOUT_SECONDS`, `INTRIQO_MAX_ACTIVE_FLOWS`,
`INTRIQO_PORTSCAN_MAX_SOURCES`, `INTRIQO_PORTSCAN_MAX_OBSERVATIONS`,
`INTRIQO_EVENT_QUEUE_CAPACITY`.

### Control Plane environment

| Variable | Purpose |
|---|---|
| `INTRIQO_CONTROL_PLANE_URL` | HTTP base URL, e.g. `http://127.0.0.1:8000`; required for HTTP unless CLI URL override supplied |
| `INTRIQO_CONTROL_PLANE_TOKEN` | Existing AGENT service-identity bearer token from the authentication API; never compiled into source or printed |
| `INTRIQO_CONTROL_PLANE_ENDPOINT` | Existing endpoint override, default `/api/v1/events`, appended to base URL |

```bash
export INTRIQO_CONTROL_PLANE_URL=http://127.0.0.1:8000
export INTRIQO_CONTROL_PLANE_TOKEN="$IDS_ENGINE_JWT"
build/runtime-release/engine/intriqo-engine --interface eth0 --filter "tcp" --sink http
```

Do not put real tokens in repository files, benchmark results, command arguments,
or shell tracing. URLs and token values are omitted/redacted from CLI diagnostics.
Service identity/RBAC/authentication are unchanged.

## Detector registration

```cpp
auto registry = std::make_unique<intriqo::detection::DetectorRegistry>();
registry->add(std::make_unique<intriqo::detection::PortScanDetector>(config));
auto pipeline = std::make_unique<intriqo::pipeline::PipelineImpl>(std::move(registry));
```

The registry dispatches every evaluation/reset to its registered detectors.
Null and duplicate registrations are rejected. Registration freezes on first
evaluation; names are available for startup reporting. Engine contains no
port-scan-specific logic. Future detectors can implement the existing `Detector`
interface and be registered without changing capture or runtime.

The existing port-scan detector counts distinct TCP destination ports and flow
attempts per source address within its window, suppressing duplicate flow IDs
and emitting once per source/window. It is not SYN-only or an attack attribution
system; benign connection activity can meet its thresholds. Severity stays HIGH
by default. Changing the threshold/window/minimum-attempts is supported; this
phase does not introduce new detectors or detection algorithms.

## Capture Reliability and State Management

### Bounded lifecycle

FlowTable has at most `max_active_flows` map entries and the same number of
ordered `(last_seen, FlowId)` index entries. Expire eligible flows before new
admission; if still full, deterministically evict the oldest timestamp/ID and
increment `flows_evicted`. No stale heap/index records or per-packet full-map
expiry scan accumulate. Idle timeout uses `>=`; late packets do not rewind
`last_seen`. Live idle poll callbacks maintain flow/detector state even without
packets. Offline replay uses event time, not the current wall clock.
FIN/RST remain tracked counters, not immediate flow close. Shutdown drains both
indexes and resets detector state. These are count bounds, not a heap-byte SLA.

Port-scan source windows expire beyond the 10-second default event-time window.
Counted flow IDs stay until pipeline retirement, so a still-active flow cannot
recount after window expiry. An ordered index has one record per source; ports
are naturally bounded to 65535/source. Capacity pressure rejects new admission
and increments `detector_state_rejections`; existing windows are not silently
evicted. Detection coverage is therefore reduced when limits are reached.
Late packets within existing windows remain eligible; stale new-source windows
are rejected against a monotonic watermark. Threshold meaning and one event per
source/window remain unchanged. Size limits for the real workload; many sources
times many unique ports can still require substantial memory.

### Capture versus processing versus delivery

Buffered libpcap is the default: requested 16 MiB kernel buffer, 100 ms timeout,
`pcap_dispatch(256)` batches, interruptible draining until no buffered packets,
and `pcap_stats` every 100 ms plus startup/shutdown. The runtime reports raw
receive/capture/interface drops separately from callback/parse/processing counts.
Unsupported and truncated/malformed packet categories are distinct; unavailable
capture statistics print `N/A`. Loopback counters are not unique wire packets.
Neither a larger buffer nor batching guarantees loss-free capture. Immediate
mode lowered the single-event latency but lost substantial traffic in the
measured 10000 UDP/s load; see the report before choosing that tradeoff.

Parsing, flow tracking and detection remain synchronous. Optional
`--event-queue-capacity 256` decouples event transport only, with at most 256
pending events plus one in flight. Overflow rejects/counts the event, stops
capture, drains admitted work and returns an error. Worker acknowledgments, not
enqueue success, drive `events_emitted`. No durable/retry buffering is added.
The queue relieved a measured single slow-HTTP stall; it cannot absorb sustained
event production exceeding sink capacity. The default 0 retains synchronous
capture starvation under a slow sink. Shutdown depends on underlying I/O/DNS.

### Soak and memory methodology

`intriqo-state-soak` drives checksummed varied-source/port/repeated-flow fixtures
through the full runtime; it alternates capacity pressure with logical-time
expiry, verifies a two-window scan, and streams RSS/CPU/state samples. Fixture
logical time is separate from wall duration: packet P99 is not measured.
`reliability_benchmark.py` supplies ordinary local loopback UDP plus a known TCP
scan, captures only reserved ports, and measures the actual engine PID. No
packets are injected or sent to external targets. RSS includes kernel-capture
mappings; post-flush RSS and inherited `ru_maxrss` are different scopes.

One-second CI soak is included in CTest. Manual release runs support
**300 / 1800 / 3600 seconds**; only 300-second runs were completed in validation.
See [runnable procedures and raw evidence](capture-hardening-validation.md#10-soak-test-methodology).
Final state fixture: 3 million packets, peak flows/sources/IDs **256/64/128**,
RSS **4628/5028/5028 KiB** initial/peak/final. Final live five-minute run:
**3000010 captured/processed**, zero reported capture/interface drops, one event,
RSS **5760/22660/6412 KiB**. These observations are not a no-leak or NIC-capacity
guarantee; the [16-part report](capture-hardening-validation.md) retains all
observed baseline/immediate/synchronous-HTTP losses and remaining gaps.

## Event sinks

- **File:** append JSONL, synchronously serialize/write/flush/close each event.
  Errors opening/writing/flushing are counted and reported.
- **HTTP:** synchronous POST of unchanged SecurityEvent v1 JSON to the existing
  API, with optional bearer token. Success means a 2xx response; non-2xx/socket
  errors are failures. Nonblocking connect/send/receive share a 3-second socket
  deadline, fragmented status lines are supported, and peer disconnects cannot
  terminate the engine through SIGPIPE. DNS resolution remains a system blocking
  operation outside that socket deadline.
- Sink `prepare()`/`flush()`/`error()` are additive default methods, so existing sink
  implementations still compile. Runtime checks file sink writability before
  capture starts. Ordinary built-in sinks have no queued events at flush.
- Optional `QueuedEventSink`: one bounded in-process worker around either sink.
  `submit(true)` means admission only; additive `delivery_statistics()` reports
  actual acknowledged events, failures, pending depth/peak/overflow and sink time.
  A successful flush drains and joins; error/overflow returns nonzero without
  counting the same earlier delivery failure twice. Engine observers see event
  generation/admission, not necessarily the worker's final acknowledgment.

**The existing transport supports plain HTTP hostname/IPv4 URLs, not HTTPS.**
Use it only on a trusted local/isolated link. Do not transmit bearer credentials
across an untrusted network. There is no retry queue, durable spool, transport batching,
or delivery guarantee beyond acknowledged submission; failures stop runtime
instead of silently dropping events. Capture readiness does not guarantee the
HTTP endpoint is available; delivery is verified at actual event submission.

## Runtime statistics

`EngineImpl::metrics()` returns a thread-safe `EngineMetrics` snapshot:

| Counter/gauge | Meaning |
|---|---|
| `packets_received` | Packet callbacks accepted by runtime, not libpcap's raw kernel receive count |
| `packets_parsed` | Successful existing IPv4 parser results |
| `packets_rejected` | All unparsed/unsupported/truncated packets; received = parsed + rejected |
| `packets_malformed` | Malformed/truncated subset of rejected; unsupported protocols are not counted malformed |
| `packets_dropped` | libpcap/kernel drop + interface-drop counters; zero for offline sources, platform-dependent semantics |
| `flows_created` | Actual newly created bidirectional flows |
| `flows_expired` | Idle flows expired by packet time or live idle maintenance |
| `flows_evicted`, `peak_active_flows` | Capacity retirement count and exact active-flow high-water |
| `flows_flushed` | Remaining flows drained at shutdown, not mislabeled expired |
| `flows_active` | Gauge; zero after successful pipeline flush |
| `detections_fired` | Generated SecurityEvents, regardless of delivery outcome |
| `events_emitted` | Actual underlying sink acknowledgments, not queue admission |
| `sink_failures` | Failed submissions/prepare/flush/admission; queued prior failures are not recounted by flush |
| `queue_depth`, `queue_peak_depth`, `queue_overflows` | Pending events (not in-flight), peak pending and capacity-rejected events |
| `packets_seen` | Raw live `ps_recv` or finite-source input count; check availability |
| `packets_captured` | Actual runtime callbacks, aliasing received |
| `capture_drops`, `interface_drops` | Separate raw `ps_drop` / `ps_ifdrop`; not parser rejects |
| `capture_errors`, `capture_statistics_available` | Source failure count and explicit raw-counter availability |
| `packets_unsupported`, `packets_truncated` | Rejected unsupported subset; truncated subset of malformed |
| `packets_processed` | Pipeline ingests that completed successfully |
| `detector_observations` | Admitted unique flow observations, not every packet |
| `detector_state_sources`, `detector_state_observations` | Live source windows and retained counted IDs |
| `detector_peak_sources`, `detector_peak_observations` | Exact detector-state high-water counts |
| `detector_expired_sources`, `detector_state_rejections`, `detector_errors` | Expired windows, rejected admissions and evaluation/allocation errors |
| `processing_seconds`, `processing_packets_per_second` | Packet callback time including synchronous sink work; completed packets / callback time |
| `event_sink_seconds` | Actual underlying submit/flush time, not additional queued drain wait |
| `runtime_seconds`, `pps`, `snapshot_time` | Steady-clock duration, derived rate, UTC snapshot timestamp |

Output aliases `events_generated` / `detections_generated` mean `detections_fired`;
`event_sink_failures` means `sink_failures`. `packets_truncated` is already included
in malformed/rejected, not an additional quantity to sum. The compatibility drop
ratio helper uses delivered + dropped counts; kernel filtering/direction/loopback
counting makes it unsuitable as a capture-loss or wire-loss metric.
Runtime snapshots do not call libpcap from another thread. Capture publishes
counters while draining batches and at shutdown. CLI summaries are measured,
not precomputed. There is no Prometheus or HTTP metrics endpoint in this phase.

## Tests and controlled live validation

Normal CTest tests need no physical interface or capture privilege. They cover
runtime input/detection/delivery/accounting/empty/malformed/error/stop/flush/
registry/PCAP behavior, capture record validation/normalization/timestamps/
pacing, and CLI options/signals/HTTP failures. All 19 original C++ tests remain.

```bash
ctest --test-dir build/runtime-release --output-on-failure
control-plane/.venv/bin/python -m pytest control-plane/tests -q
(cd agents && ../control-plane/.venv/bin/python -m pytest tests -q)
INTRIQO_ENGINE_DEMO="$PWD/build/runtime-release/engine/intriqo_port_scan_demo" \
  control-plane/.venv/bin/python -m pytest tests/e2e/test_vertical_slice.py -q

# Explicit opt-in; use only the existing local development/test PostgreSQL:
INTRIQO_RUN_LIVE_TEST=1 \
INTRIQO_ENGINE_BINARY="$PWD/build/runtime-release/engine/intriqo-engine" \
  control-plane/.venv/bin/python -m pytest tests/e2e/test_live_capture.py -q
```

The live test creates an existing-API AGENT identity, starts local FastAPI, reserves
ten local TCP listeners at `127.0.0.2`, filters only traffic from `127.0.0.1`,
and makes ordinary local TCP connections. It verifies live detection, HTTP
delivery, API readback, PostgreSQL row, and audit outcome, then tests each signal.
No external network is scanned and no raw packets are injected.

For an unprivileged x86_64 Linux host with Docker already available, the test
optionally accepts `INTRIQO_LIVE_DOCKER_IMAGE=ubuntu:26.04`. That ephemeral
validation-only process receives NET_RAW and mounts only the executable/public
libraries read-only, not repository files or credentials. Tokens pass by environment
name, never command arguments. This is not a deployment architecture requirement.
The database fixtures use a development database and may delete test records;
never point the regression suite at a production database.

## Performance methodology

Keep `intriqo_engine_benchmark` for continuity: it consumes already-parsed packets,
so it is not a raw capture/parser throughput measurement. The new
`intriqo-runtime-benchmark` measures CaptureSource → parser → flows → feature
extraction → registry → real PortScanDetector → JSON serialization and real
`FileEventSink(/dev/null)`. HTTP/PostgreSQL latency is not included in its offline
throughput results. It reports actual packet/flow/event rates, parse fraction,
rejections/drops/sink failures, steady-clock wall time, CPU user/system seconds,
CPU utilization, process high-water RSS, post-flush resident RSS, and event
capture-to-observer latency when timestamps are valid. Observer latency includes
sink submission; it is not isolated algorithm or HTTP latency.

```bash
build/runtime-release/engine/intriqo_engine_benchmark
build/runtime-release/engine/intriqo-runtime-benchmark --synthetic
build/runtime-release/engine/intriqo-runtime-benchmark --pcap authorized-input.pcap
build/runtime-release/engine/intriqo-runtime-benchmark --interface lo --filter "tcp" --duration-seconds 3

# Reproducible deterministic fixture generation and 3 runs of each offline mode:
python3 scripts/benchmark/runtime_benchmark.py --build build/runtime-release \
  --packets 100000 --ports 1000 --repeats 3
# Optional bounded local-only live workload, with approved capture privileges:
python3 scripts/benchmark/runtime_benchmark.py --build build/runtime-release --live
# Optional already-authorized Docker launcher, not required for normal execution:
python3 scripts/benchmark/runtime_benchmark.py --build build/runtime-release \
  --live --docker-image ubuntu:26.04
```

The driver refuses non-Release builds, records CPU model, RAM, OS/kernel,
compiler/version, build type, git commit and dirty flag, input packet/port counts,
PCAP SHA256, detector configuration, CPU affinity and UTC time. Results default
to ignored `benchmarks/engine/results/runtime.json`. Synthetic/PCAP fixture
timestamps are historical; their wall-clock detection latency is **N/A**, not
invented. Event rate is workload-derived (one source produces one event), not
maximum sink capacity. Live rates average the bounded interval including idle
time; local generator/loopback results are not saturation or line-rate claims.

Linux `getrusage` high-water RSS may inherit a launcher's resident-memory peak;
use the separate `/proc/self/status` post-flush RSS snapshot and interpret both
scopes explicitly. Neither is a heap-only profiler. Use comparable builds,
input/flow cardinality, filters, sink and detector settings across runs. Record
load/variance and observed drops; do not generalize a small loopback workload to
physical NIC, mirror-port, or network-wide throughput.

## Known limitations and future work

**Implemented, with limits:**

- Linux/libpcap is the only live backend. Datalink normalization is limited to
  the types above; no VLAN decoding, IPv6 parser, IP fragment reassembly, TCP
  stream reassembly or application-protocol inspection is added here.
- Live snaplen truncation is rejected, even when enough header bytes remain for
  a partial interpretation. BPF filtering limits visibility intentionally.
- Runtime parsing/detection is synchronous; default slow sinks can stall capture
  and cause reported kernel drops. Optional bounded event delivery is not durable.
  The configurable capture buffer absorbs bounded bursts, not sustained overload;
  libpcap/OS determines the actual buffer layout and memory use.
- Flow and detector state are bounded as documented above, but capacity eviction/
  observation rejection reduces coverage. Large count limits are not a tight byte
  budget. FIN/RST flags do not close flows immediately in the current implementation.
- Detection counts distinct TCP ports by source, not confirmed malicious scans;
  loopback's same-address connections cannot trigger this detector. Validation
  intentionally uses two distinct loopback addresses. Clock/out-of-order input
  can affect existing time-window/flow semantics.
- Missing libpcap or permission errors are explicit, not successful empty
  capture. Best-effort positive libpcap activation warnings do not abort capture.
- HTTP is plain-text, synchronous, no retry/TLS/persistent connection; blocking
  resolver latency remains outside the socket deadline. File writes flush but
  are not `fsync` durability guarantees. Neither sink is a durable queue.
- Synthetic data is deterministic test input. Live validation proves only a
  local authorized interface → PostgreSQL path, not production network-wide
  capture, physical-NIC performance or loss-free sustained operation.

**Future, not implemented by this phase:** additional deterministic detectors,
durable/TLS transport and DNS-deadline hardening, missing agents, LLM integration,
response/blocking, packet injection, new UI features, WebSockets/SSE, Prometheus,
Kafka/Redis/Kubernetes/microservices and cloud deployment.

Recommended next phase: keep the same boundaries; execute 30/60-minute soaks,
establish buffered saturation and packet-latency evidence on an explicitly
authorized NIC/mirror, size state/queue memory, and exercise sustained slow/failing
ingestion and shutdown deadlines before expanding detector or agent scope.
