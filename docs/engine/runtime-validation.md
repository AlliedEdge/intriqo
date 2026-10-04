# IDS runtime implementation and validation report

**Historical runtime-slice report.** Measurements and findings below describe
the original implementation, not the subsequent hardening result. Its observed
capture drops are intentionally preserved. Current state/queue policies and
new measurements are in [Capture Reliability and State Management](capture-hardening-validation.md).

Validated on 2026-10-04 (Asia/Calcutta). Checkout:
`/run/media/rayan/Workspace1/01_Projects/intriqo`.
The functional runtime/live vertical slice is implemented. This report does
**not** claim loss-free sustained production capture or full autonomous SOC
completion. See [engine reference](ids-engine.md) for interfaces and limitations.

## 1. Files added

- `engine/include/intriqo/runtime/engine_impl.hpp`
- `engine/src/runtime/engine_impl.cpp`
- `engine/include/intriqo/detection/detector_registry.hpp`
- `engine/src/detection/detector_registry.cpp`
- `engine/src/capture/capture_internal.hpp`
- `engine/src/capture/live_source.cpp`
- `engine/src/capture/synthetic_source.cpp`
- `engine/tools/engine_main.cpp`
- `engine/tools/benchmark_runtime.cpp`
- `engine/tests/integration/runtime_fixture.hpp`
- `engine/tests/integration/test_runtime.cpp`
- `engine/tests/integration/test_capture.cpp`
- `engine/tests/test_cli.py`
- `tests/e2e/test_live_capture.py`
- `scripts/benchmark/runtime_benchmark.py`
- `docs/engine/runtime-validation.md`

Generated artifact: `benchmarks/engine/results/runtime.json` (git-ignored raw
benchmark measurements; no credentials). Build artifacts are git-ignored under
`build/runtime-release`, `build/runtime-no-pcap`, and `build/runtime-asan`.

## 2. Files modified

- `CMakeLists.txt` — root CTest discovery.
- `engine/CMakeLists.txt` — new runtime/capture/registry sources, executables,
  threads and optional libpcap discovery/fallback/offline switch.
- `Makefile` — correct existing benchmark target and add runtime benchmark.
- `engine/include/intriqo/capture/capture.hpp` — concrete sources, statistics,
  readiness hook and configurable buffer, keeping existing callback interface.
- `engine/include/intriqo/packet/packet.hpp` — original captured/wire lengths
  appended without breaking existing aggregate initializers.
- `engine/include/intriqo/metrics/metrics.hpp` — actual runtime/delivery/rejection
  counters and bounded estimated drop ratio.
- `engine/include/intriqo/pipeline/pipeline.hpp`
- `engine/include/intriqo/pipeline/pipeline_impl.hpp`
- `engine/src/pipeline/pipeline_impl.cpp` — additive statistics, synchronized
  processing, expiry before update, flush/error cleanup.
- `engine/include/intriqo/transport/event_sink.hpp`
- `engine/src/transport/event_sink.cpp` — additive prepare/flush/error lifecycle,
  file readiness/errors and deadline/RAII/SIGPIPE-safe HTTP operations.
- `engine/src/capture/pcap_source.cpp` — validated classic replay, normalized
  datalinks, endian/precision handling and interruptible realtime pacing.
- `engine/tests/CMakeLists.txt`
- `engine/tests/integration/CMakeLists.txt` — register new tests.
- `tests/e2e/test_vertical_slice.py` — optional demo-binary environment override
  and use current Python interpreter after checkout relocation; assertions intact.
- `README.md`
- `docs/engine/ids-engine.md` — working commands and factual implemented/future
  distinction, removing stale line-rate/implemented-agent claims.

Concurrent frontend changes appeared during execution and were left untouched;
they are **not** part of this IDS implementation. No Control Plane/agent/frontend
implementation files, contracts, authentication flows or deployment topology
were changed by the IDS implementation. At validation time, no commit had yet
been made; separate frontend edits are outside this IDS report.

## 3. Architecture changes

Only concrete orchestration and capture/registration implementations were added:

`CaptureSource → EngineImpl/IPv4Parser → PipelineImpl/FlowTable → FlowFeatures →
DetectorRegistry/PortScanDetector → SecurityEvent → EventSink → FastAPI/PostgreSQL`.

The existing abstract Engine, CaptureSource packet callbacks, Pipeline and
Detector interfaces remain usable. New hooks/counters have compatible defaults.
Existing packet parsing, flow storage, feature extraction, port-scan algorithm,
serialization and API ingestion logic are reused, not duplicated/replaced.
Sink/source failures propagate after clean shutdown; lifecycle is single-run.
No new detectors, infrastructure, agents, LLMs, blocking/injection or UI work.

## 4. New CLI commands

Executable: `build/runtime-release/engine/intriqo-engine`.

```bash
build/runtime-release/engine/intriqo-engine --help
build/runtime-release/engine/intriqo-engine --interface eth0 --filter "tcp"
build/runtime-release/engine/intriqo-engine --pcap authorized-input.pcap
build/runtime-release/engine/intriqo-engine --synthetic
build/runtime-release/engine/intriqo-engine --interface eth0 --sink http
```

Available controls: sink/output/base URL, live filter/snaplen/promiscuity/kernel
buffer, port-scan window/distinct-port/minimum-attempt thresholds, synthetic
input count/ports, and logging level. SIGINT/SIGTERM both stop/flush/report.
The separate `intriqo-runtime-benchmark` supports synthetic, PCAP and bounded
live capture. Original demo and `intriqo_engine_benchmark` are retained unchanged.

## 5. Configuration variables

The executable adopts **existing** runtime environment conventions, not a new
secret configuration format:

- `INTRIQO_CONTROL_PLANE_URL`: HTTP base URL.
- `INTRIQO_CONTROL_PLANE_TOKEN`: existing AGENT bearer token, environment only.
- `INTRIQO_CONTROL_PLANE_ENDPOINT`: defaults to `/api/v1/events`.

New test/validation controls, not service credentials:

- `INTRIQO_ENGINE_DEMO`: optional existing E2E executable override.
- `INTRIQO_ENGINE_BINARY`: live-test executable override.
- `INTRIQO_RUN_LIVE_TEST=1`: explicit local live-test opt-in.
- `INTRIQO_LIVE_DOCKER_IMAGE`: optional ephemeral Linux validation launcher.

Runtime configuration otherwise uses validated CLI flags. No secrets are
hard-coded in the new code or printed in evidence.

## 6. New test results

**23 new C++ cases pass**, covering synthetic startup/processing/detection/
delivery, empty/malformed/unsupported input, source/sink/flush/observer failures,
pending and concurrent stop, metrics, actual flow expiration/flushing, null
dependencies, bounded drop ratio, registry dispatch/freeze/reset, classic PCAP
validation/timestamps/endian handling, cooked-frame normalization and stoppable
realtime pacing. No physical interface is needed for ordinary CTest execution.

The `RuntimeCLI` CTest entry runs **6 Python unittest cases** for help/options,
real JSONL output, actionable source failure, file sink initialization failure,
SIGINT/SIGTERM, real local HTTP delivery and HTTP 500/token-redaction behavior.
Two additional opt-in live cases pass, detailed below.

## 7. Full existing regression results

| Check actually run | Result |
|---|---|
| Release/libpcap `ctest --test-dir build/runtime-release --output-on-failure` | **43/43 entries passed**: original 19 + new 23 C++ + CLI runner |
| Release/no-libpcap `ctest --test-dir build/runtime-no-pcap --output-on-failure` | **43/43 passed** |
| Debug ASan+UBSan `ctest --test-dir build/runtime-asan --output-on-failure` | **43/43 passed** |
| Control Plane `.venv/bin/python -m alembic upgrade head`, then `.venv/bin/python -m pytest tests/ -q` from `control-plane` | Migration succeeded; **64 passed** |
| Agent platform `../control-plane/.venv/bin/python -m pytest tests/ -q` from `agents` | **81 passed**, plus **4 subtests** |
| Existing `tests/e2e/test_vertical_slice.py` with built demo override | **1 passed**; real C++/FastAPI/PostgreSQL/incident/task/finding/audit path, including 401/500 delivery errors |
| Frontend `npm run test -- --run` from `frontend/dashboard` | **11 passed**, 4 test files; no frontend edits by this task |
| Ruff on new CLI/live-test/benchmark Python files with Control Plane config | **Passed** |
| `git diff --check` | **Passed** |

Release and sanitizer builds completed. Existing parser/feature/flow conversion
warnings and upstream GoogleTest compiler warnings remain; they were not
misreported as new runtime warnings. The initial IDS validation did not run
TSan, physical-NIC soak tests, frontend build/lint, or exhaustive fuzzing.

## 8. Controlled live-capture validation

Actual Linux/libpcap capture was tested, not mocked or replayed. Host had
libpcap 1.10.6 runtime libraries but no development headers or unprivileged
NET_RAW access. Development headers were extracted into `/tmp/opencode` without
changing global packages; CMake linked the system libpcap. An ephemeral
`ubuntu:26.04` process with only NET_RAW capture capability mounted the compiled
binary and public shared libraries read-only. Existing local FastAPI and
PostgreSQL remained the real service/persistence path. No repository-mounted
credentials or deployment infrastructure were introduced.

Command:

```bash
INTRIQO_RUN_LIVE_TEST=1 INTRIQO_LIVE_DOCKER_IMAGE=ubuntu:26.04 \
INTRIQO_ENGINE_BINARY="$PWD/build/runtime-release/engine/intriqo-engine" \
  control-plane/.venv/bin/python -m pytest tests/e2e/test_live_capture.py -q
```

Only ordinary TCP connections from `127.0.0.1` to ten reserved listeners on
`127.0.0.2` were generated. The source filter excluded unrelated host traffic.
An AGENT token was created through the existing authentication API and supplied
only by environment. The test verified the generated PORT_SCAN through API
readback, a real PostgreSQL `security_events` row and `EVENT_INGESTED` successful
audit record. Each signal was sent to the actual live engine.

| Final validation run | Parsed / received | Created / flushed flows | Events emitted | Drops / malformed / rejected / sink failures | Duration |
|---|---:|---:|---:|---|---:|
| SIGINT | 30 / 30 | 10 / 10 | 1 | all 0 | 0.478018 s |
| SIGTERM | 30 / 30 | 10 / 10 | 1 | all 0 | 0.298770 s |

Both returned exit code 0 with active flows 0. **2 tests passed**.
This proves the required local live traffic → runtime → detector → HTTP →
FastAPI → PostgreSQL path, not physical-NIC or network-wide coverage.

## 9. Release benchmark methodology and environment

Final recorded benchmark began at `2026-10-03T20:56:13Z` (2026-10-04 local).

| Field | Recorded value |
|---|---|
| CPU | Intel Core 5 210H |
| RAM | 23,694,364 KiB (about 22.6 GiB) |
| OS | Ubuntu 26.04.1 LTS, x86_64, glibc 2.43 |
| Kernel | `7.0.0-34-generic` |
| Compiler | `/usr/bin/c++`, GCC `15.2.0`, Ubuntu package `15.2.0-16ubuntu1` |
| Build | Release, C++20, libpcap 1.10.6 |
| Base git commit | `0856e47036dacfa45e5edf8585491abd2dd83db8` |
| Source state | Dirty working tree with this implementation and unrelated concurrent frontend edits; not a committed release |
| CPU affinity | CPUs 0–11, not pinned; shared developer host, not an isolated benchmark machine |
| Offline input | 100,000 checksummed Ethernet/IPv4/TCP SYN packets, documentation addresses, 1,000 distinct ports/flows, 1 ms packet-time increments |
| PCAP SHA256 | `7d5ce6d0d50098892c5478b208be2b645101f4ce3cfdc27431c736ef0f990a9e` |
| Detector | Registry containing PortScanDetector, window 10 s, unique-port threshold 10, minimum attempts 10, HIGH severity |
| Sink | Real FileEventSink(`/dev/null`); JSON serialization/file transport included, HTTP/PostgreSQL excluded from throughput timings |
| Repeats | 3 synthetic, 3 PCAP, 1 bounded live measurement |
| Live workload | 1,000 ordinary local TCP connections across ten ports; capture SYN-only BPF, `lo`, no promiscuity, snaplen 65535, buffer request 16 MiB, duration 3 s |

Commands:

```bash
cmake -S . -B build/runtime-release -DCMAKE_BUILD_TYPE=Release -DINTRIQO_BUILD_TESTS=ON \
  -DPCAP_INCLUDE_DIR=/tmp/opencode/intriqo-deps/root/usr/include \
  -DPCAP_LIBRARY=/usr/lib/x86_64-linux-gnu/libpcap.so.0.8 \
  -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST="$PWD/engine/build/_deps/googletest-src"
cmake --build build/runtime-release --parallel 4
python3 scripts/benchmark/runtime_benchmark.py --live --docker-image ubuntu:26.04
build/runtime-release/engine/intriqo_engine_benchmark
```

The dependency paths above describe this validation environment; a normal
`libpcap-dev` installation does not need those overrides. The driver generates
the exact fixture and records environment/configuration/counts/hash itself.
Raw results are `benchmarks/engine/results/runtime.json`; summary below preserves
actual measurements without private payloads. Wall time includes final flush.
CPU percent uses aggregate user+system time divided by wall time; small values
above 100% are possible because the process includes a signal-watcher thread.

## 10. Actual benchmark numbers

### Full raw-packet runtime, offline modes

Each run received/parsed 100,000 packets, created/flushed 1,000 flows, emitted
1 real event, and finished with 0 active flows. Every run had 0 malformed,
rejected, dropped packets and 0 sink failures. Parse fraction: **100%**.

| Mode/run | Wall seconds | Packets/s = parsed packets/s | Flows/s | Events/s | CPU % | High-water RSS KiB | Post-flush RSS KiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| Synthetic 1 | 0.368166 | 271,616.37 | 2,716.16 | 2.7162 | 100.051 | 30,160 | 6,316 |
| Synthetic 2 | 0.397387 | 251,644.15 | 2,516.44 | 2.5164 | 100.097 | 30,160 | 6,256 |
| Synthetic 3 | 0.405663 | 246,509.99 | 2,465.10 | 2.4651 | 100.063 | 30,160 | 6,132 |
| PCAP 1 | 0.368931 | 271,053.55 | 2,710.54 | 2.7105 | 100.043 | 30,160 | 6,212 |
| PCAP 2 | 0.373030 | 268,074.69 | 2,680.75 | 2.6807 | 100.152 | 30,160 | 6,264 |
| PCAP 3 | 0.417231 | 239,675.25 | 2,396.75 | 2.3968 | 100.158 | 30,160 | 6,264 |

Median throughput: **251,644 packets/s synthetic**, **268,075 packets/s PCAP**.
Synthetic generation/checksums and PCAP file IO are inside their respective
timings. Historical fixture timestamps make detection latency **N/A** in both
modes. Single-event rate is not a maximum event-sink capacity claim.

High-water RSS can include the Python launcher's inherited process memory peak;
the separately measured post-flush RSS snapshot is approximately 6 MiB. It is
not peak engine-only heap memory, and the snapshot alone is not a memory bound.

### Live capture, deliberately bursty local input

- Offered: **1,000** local TCP connections in **0.146651 s**.
- Captured/parsed: **867 packets**, **867 created/flushed flows**, parse fraction 100%.
- Wall interval: **3.019462 s**, including idle time and flush.
- Packet/parse/flow rate: **287.14/s** averaged over that interval.
- Events: **1 emitted**, **0.331185/s**; sink failures: **0**.
- Malformed/rejected: **0**; active flows after flush: **0**.
- **Kernel/libpcap reported drops: 265**. This is not a loss-free result.
- CPU: user **0.020584 s**, system **0.021526 s**, utilization **1.394619%**.
- Memory: high-water RSS **38,840 KiB**, post-flush RSS **6,524 KiB**.
- Capture-to-engine-observer latency: **0.408996 ms**, **one event sample**;
  includes file sink submission, not isolated detector/HTTP latency.

Linux loopback/libpcap kernel drop counters include direction/filter-dependent
semantics; do not subtract 265 from the offered connection count to infer an
exact wire loss percentage. The 3-second rate is generator/idle-interval-bound,
not maximum capture throughput. Burst drops remain real and visible despite
the bounded buffer. Earlier runs also exposed drops; they prompted buffered
batch draining and a configurable capture buffer, not a zero-loss claim.

### Existing benchmark retained

Unchanged `intriqo_engine_benchmark`: **100,000 already-parsed packets**, **1,000
active flows**, **0.350379 s**, **285,405 packets/s** in the final run.
Its pre-parsed input and different detector settings mean it is not directly
comparable with the full-runtime numbers or proof of a speed improvement over
the previously reported ~307k result.

## 11. Known limitations

1. **Capture is not loss-free under bursts.** The recorded live benchmark reports
   drops. Kernel buffering and synchronous processing are not a substitute for
   workload/flow-cardinality sizing, pacing or authorized NIC/mirror validation.
2. **Existing long-run detector/flow limits remain.** PortScanDetector retains
   source windows/counted flow IDs until reset. Flow expiration scans active
   flows on packet arrival, with no idle timer or hard capacity limit. Memory and
   cost can grow with traffic; FIN/RST does not immediately retire flows.
3. **Plain HTTP only.** No TLS, asynchronous/durable delivery, retry spool or
   persistent connections was added. Use bearer credentials only on a trusted
   local/isolated network; blocking DNS is outside the socket deadline.
4. **Protocol/capture scope is limited.** IPv4 only; no VLAN decoding, IPv6
   parsing, fragment/TCP reassembly or application inspection. Classic PCAP,
   not PCAPNG. No physical-NIC, SPAN/TAP, network-wide or sustained high-rate
   zero-drop claim follows from loopback verification.
5. **Detection is deterministic thresholding, not attribution.** Existing
   source/port counting may flag benign traffic; only PortScanDetector is enabled.
6. Runtime/source instances are single-use; restart by constructing new instances.
   Snapshot drop rates are estimates, and benchmark memory/latency scopes are
   explicitly limited above. No production-readiness certification is implied.

### Definition-of-done evidence

- [x] Concrete Engine runtime and Linux LiveCaptureSource.
- [x] PCAP and synthetic paths retained and verified.
- [x] PortScanDetector registered through the composite detector mechanism.
- [x] Real `intriqo-engine` executable, validated CLI and environment configuration.
- [x] SIGINT/SIGTERM clean capture stop, flow/sink flush and statistics summary.
- [x] Actual runtime metrics and clear source/sink failures.
- [x] Live generated SecurityEvent delivered to existing authenticated HTTP API.
- [x] API, PostgreSQL event row and successful ingestion audit verified.
- [x] All 19 original C++ tests and all new runtime/capture/CLI cases passing.
- [x] Existing Python/agent/Control Plane/E2E tests passing; frontend tests also run.
- [x] Release benchmarks reproducible with recorded environment and actual drops.
- [x] README/engine documentation distinguish implemented, future and limitations.
- [x] No unrelated architecture/deployment/auth/agent/UI implementation changes.

## 12. Recommended next phase

**Long-running IDS hardening, within the same architecture:** bound detector
window/flow-ID retention and flow capacity, improve expiration cost/idle cleanup,
exercise high-cardinality/long-duration traffic and idle shutdown, characterize
real authorized NIC/SPAN/TAP capture drops, and harden trusted event transport
delivery. Do that before adding detectors/agents or declaring unattended
production operation. Kafka, Redis, Kubernetes, microservices, Prometheus,
LLM integration, blocking/injection and UI redesign remain deferred.

## Capture Reliability and State Management

The next hardening phase was implemented and validated on 2026-10-04 without
changing Control Plane/agent/React responsibilities. The original numbers and
limitations above remain historical evidence; state growth and capture
accounting limitations were addressed, not retroactively erased.

- Flow state: 60-second default timeout, 100000-flow cap, bounded ordered idle
  index, live idle maintenance and explicit deterministic eviction counters.
- Detector state: 4096 source windows / 100000 counted active-flow IDs by
  default, event-time expiration, retirement deduplication, explicit rejection
  at capacity, synchronized current/peak/error counters.
- Capture: buffered `pcap_dispatch(256)`, 100-ms `pcap_stats` sampling,
  configurable timeout/immediate mode, raw `ps_recv` / `ps_drop` / `ps_ifdrop`
  separate from callbacks, parser rejects and completed processing.
- Backpressure: synchronous default retained; a measured slow-HTTP probe
  justified optional bounded event delivery. Same final binary reported
  **16128 / 117476 capture drops** for 0.5/1-second synchronous acknowledgments;
  queued capacity 256 reported **0 / 0**, one acknowledgment and peak depth 1.
  No durability or sustained-overload guarantee follows.
- Final tests: **70/70 CTest entries** each Release/no-libpcap/ASan+UBSan;
  Control Plane **64**, agents **81 + 4 subtests**, existing E2E **1**, live E2E
  **4** (both signals and delivery modes), frontend regression **11**.
- Five-minute live soak: **3000010 captured/processed**, **0** reported capture/
  interface drops/rejects, one event, peak 11 flows/final zero. Sampled initial/
  peak/final RSS **5760 / 22660 / 6412 KiB**, CPU **1.323683%**.
- Five-minute varied state fixture: **3000000 packets**, peak flows/sources/IDs
  **256/64/128**, final state zero; RSS **4628 / 5028 / 5028 KiB**. Large eviction/
  rejection counts are expected stress outcomes, not concealed detection coverage.
- Final matched offline medians: baseline **444094 / 483196 pps**, candidate
  **1632097 / 1767229 pps** synthetic/PCAP; three runs each. The shared-host
  variance and distinct live/offline scopes are documented. Buffered saturation
  was not established; ~225k UDP/s was the highest short tested offered point.

See [the full 16-part report](capture-hardening-validation.md) for exact files,
configuration/counter meaning, preserved historical/failed evidence, all new
versioned result paths, actual CPU/RSS/drop figures and 5/30/60-minute procedures.
Only five-minute durations were run. Plain HTTP/DNS/shutdown constraints,
physical-NIC validation, packet P99 and prolonged capacity testing remain open.
