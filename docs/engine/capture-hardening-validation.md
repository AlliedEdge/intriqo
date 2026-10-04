# Capture reliability and state-management validation

## Pre-implementation audit (2026-10-04)

Base commit: `765b19d`; clean working tree before this phase. No React, Python
Control Plane or agent implementation changes are part of this work.

- Flow state: `FlowTable::flows_` unordered map has no maximum. `expire()` scans
  the entire map. Pipeline invokes expiration before every packet update, using
  packet timestamps only; idle live capture does not trigger expiration. FIN/RST
  is counted, not immediate retirement. Shutdown `flush()` clears all flows.
- Detector state: `PortScanDetector::windows_` stores source-address windows and
  per-source unique ports; `counted_flows_` stores every observed TCP flow ID until
  reset. Destination addresses are not keys. Ports have a natural 16-bit bound
  but sources/flow IDs do not. A revisited source resets its window; unrelated
  inactive sources never expire. Shutdown resets both containers.
- Capture state: live libpcap is nonblocking, polled with eventfd cancellation.
  Immediate mode is forced on. Snapshot length, promiscuity, timeout and a
  requested 16 MiB buffer are set before activation. Batches are drained with
  `pcap_next_ex`, at most 64 before statistics sampling. Application work happens
  inside that call's synchronous callback. Busy interfaces can outpace it.
- Metrics: live `pcap_stats` wraps are extended, but runtime exposes only the
  sum of `ps_drop`/`ps_ifdrop`; raw `ps_recv` is omitted. This makes capture loss
  indistinct from platform-specific interface drops. Parser rejection is already
  separately counted, but unsupported/truncation breakdown and processing/sink
  elapsed time are absent. Statistics unavailability is not represented.
- Sinks/backpressure: FileEventSink serializes/open/appends/flushes per event.
  HttpEventSink synchronously resolves/connects/sends/receives inside packet
  processing. Socket deadline is 3 s; DNS is outside it. There is no queue.
  Either slow sink can stall capture; this alone does not identify the measured
  burst-loss cause. Delivery failures stop capture, surface after flushing,
  and never count as successful emissions.
- Memory: capture buffers are bounded but flow/detector containers are not.
  Existing runtime/source lifecycle is single-use. Stop/EOF/error cleanup flushes
  pipeline and sink; normal live idleness does not retire state.
- Benchmarks/tests: existing 43 CTest entries pass on a freshly relocated Release
  build. Existing benchmark includes flow scanning and one event, not high-cardinality
  steady-state/long-run stress. Old results are retained, including their drops.

### Baseline, before source changes

Fresh `build/hardening-baseline` Release binary at the base commit was retained
for same-workload comparisons. Existing driver ran 3 synthetic and 3 PCAP repeats
and its local TCP burst; raw results saved as a new file
`benchmarks/engine/results/hardening-baseline-v2.json`, not overwriting `runtime.json`.
The burst offered 1,000 local connections with FileEventSink(`/dev/null`):
**863 packets captured/parsed**, **272 reported kernel/interface drops**, one event
delivered. This reproduces capture loss without HTTP and is not a zero-loss claim.

The audit above was recorded before implementation. The following report records
the implemented policies and actual subsequent measurements, not projections.

## Capture Reliability and State Management

Validated on 2026-10-04, Asia/Calcutta, in
`/run/media/rayan/Workspace1/01_Projects/intriqo`. No commits or pushes were made
in this hardening phase. The original runtime report and `runtime.json` remain
historical evidence; the new versioned files do not overwrite them.

## 1. Exact files added

- `docs/engine/capture-hardening-validation.md`
- `engine/include/intriqo/transport/queued_event_sink.hpp`
- `engine/src/transport/queued_event_sink.cpp`
- `engine/tools/runtime_reporting.hpp`
- `engine/tools/state_soak.cpp`
- `engine/tests/integration/test_hardening.cpp`
- `engine/tests/integration/test_queued_delivery.cpp`
- `scripts/benchmark/reliability_benchmark.py`
- `scripts/benchmark/test_reliability.py`
- `scripts/benchmark/sink_stall_probe.py`

Generated measurements are git-ignored under `benchmarks/engine/results/`; the
specific successful evidence files are listed with their results below. The
local `.omnirush/swarm.md` is an ignored coordination record, not runtime code.

## 2. Exact files modified

- `engine/CMakeLists.txt`
- `engine/include/intriqo/capture/capture.hpp`
- `engine/include/intriqo/detection/detector.hpp`
- `engine/include/intriqo/detection/detector_registry.hpp`
- `engine/include/intriqo/detection/port_scan_detector.hpp`
- `engine/include/intriqo/flow/flow.hpp`
- `engine/include/intriqo/metrics/metrics.hpp`
- `engine/include/intriqo/pipeline/pipeline.hpp`
- `engine/include/intriqo/pipeline/pipeline_impl.hpp`
- `engine/include/intriqo/runtime/engine_impl.hpp`
- `engine/include/intriqo/transport/event_sink.hpp`
- `engine/src/capture/capture_internal.hpp`
- `engine/src/capture/live_source.cpp`
- `engine/src/capture/pcap_source.cpp`
- `engine/src/capture/synthetic_source.cpp`
- `engine/src/detection/detector_registry.cpp`
- `engine/src/detection/port_scan_detector.cpp`
- `engine/src/flow/flow_table.cpp`
- `engine/src/pipeline/pipeline_impl.cpp`
- `engine/src/runtime/engine_impl.cpp`
- `engine/tests/CMakeLists.txt`
- `engine/tests/integration/CMakeLists.txt`
- `engine/tests/test_cli.py`
- `engine/tools/benchmark_runtime.cpp`
- `engine/tools/engine_main.cpp`
- `tests/e2e/test_live_capture.py`
- `docs/engine/ids-engine.md`
- `docs/engine/runtime-validation.md`
- `README.md`

The concurrent diff in
`frontend/dashboard/src/components/layout/auth-console.css` was not edited,
staged, or attributed to hardening. Its existing trailing whitespace prevents a
whole-tree `git diff --check` pass; the hardening-only check passes.

## 3. Architectural changes

The existing path remains capture → parser → flow/features → registry/port scan
→ SecurityEvent v1 → file/HTTP → existing Control Plane/PostgreSQL. There are no
new detectors, agents, ML, services, deployment dependencies, metrics endpoints,
or React changes. Additive interface hooks have defaults for existing callers.
An optional **in-process event-delivery worker**, not a packet-processing queue,
wraps the existing sink. Parsing/detection remain on the capture callback thread.

## 4. Flow-state policy

- Default idle timeout: **60 seconds**; maximum active flows: **100000**.
- CLI `--flow-idle-timeout` / `--max-active-flows` override
  `INTRIQO_FLOW_IDLE_TIMEOUT_SECONDS` / `INTRIQO_MAX_ACTIVE_FLOWS`.
- An unordered flow map has one ordered `(last_seen, FlowId)` idle-index entry
  per flow. Updating a timestamp reuses the index node; stale entries do not
  accumulate. No full-map scan occurs on every packet.
- Expire eligible flows first (`elapsed >= timeout`). If still full on new flow
  admission, deterministically evict the oldest `(last_seen, FlowId)`.
- Retirement evaluates the completed flow before retiring its detector ID.
  Eviction is explicit in `flows_evicted`, not a parser/capture loss.
- Live idle poll callbacks perform maintenance using wall time. Offline replay
  uses packet/event time only. Late packets do not rewind `last_seen`.
- FIN/RST remain counted flags, not immediate close semantics. Bidirectional
  accounting is retained; the initial forward packet is now counted correctly.
- Flush empties both indexes and resets detector live state; runtime instances
  remain single-use. `flows_created = expired + evicted + flushed + active`
  holds after successful processing/cleanup.

## 5. Detector-state policy

Source windows default to **4096** and retained counted flow IDs to **100000**.
CLI `--max-tracked-sources` / `--max-tracked-observations` override
`INTRIQO_PORTSCAN_MAX_SOURCES` / `INTRIQO_PORTSCAN_MAX_OBSERVATIONS`.
Destination addresses are not new detector keys; each source's distinct TCP
ports are naturally bounded by the 16-bit port space.

Window expiration uses a bounded ordered index and a monotonic event-time
watermark. Expiry is strictly beyond the configured window, preserving the
existing boundary and thresholds. Accepted flow IDs are retired only when their
flows end, not simply when a window expires: long-lived flows cannot recount
themselves in a new window. Late attempts within an existing window are accepted;
attempts before its start and stale new-source windows are explicitly rejected.

When either capacity is full, reject new observations, increment
`detector_state_rejections`, and retain admitted state. This can reduce detection
coverage; it is not a loss-free detection policy. Source/ID gauges, high-water
gauges, expired-source and allocation/error counters expose the lifecycle.
Evaluation/reset/maintenance/registry forwarding are synchronized. Reset clears
live containers but retains cumulative counters. One event per source/window
and existing distinct-port/minimum-attempt threshold meaning are preserved.

## 6. Capture-statistics implementation

Libpcap's `pcap_stats` is sampled on the owning capture thread every **100 ms**,
at initialization and shutdown, with unsigned 32-bit wrap extension. Snapshots
do not call libpcap concurrently. `pcap_dispatch(256)` drains bounded batches
without waiting again until a zero dispatch establishes the buffer is empty;
exceptions never unwind through C frames, and eventfd permits cancellation.

| Runtime field | Exact meaning |
|---|---|
| `packets_seen` | Raw live `ps_recv`; finite-source input count offline |
| `packets_captured`, `packets_received` | Actual application packet callbacks |
| `capture_drops` | Raw `ps_drop`, not parser failures |
| `interface_drops` | Raw `ps_ifdrop`; zero does not establish hardware support |
| `capture_statistics_available` | Whether these source statistics are available |
| `capture_errors` | Source/read/normalization errors, not pipeline exceptions |
| `packets_parsed` | Successful IPv4 parser results |
| `packets_rejected` | All parser/unsupported/truncation rejections |
| `packets_malformed` | Malformed including truncation; excludes unsupported |
| `packets_unsupported` | Unsupported protocol/frame subset of rejected |
| `packets_truncated` | Truncated subset of malformed; do not sum it twice |
| `packets_processed` | Successfully completed pipeline ingests |
| `detections_fired`, output `events_generated` / `detections_generated` | Generated events, not acknowledgments |
| `events_emitted` | Actual successful underlying file/HTTP acknowledgments |
| `sink_failures`, output `event_sink_failures` | Failed delivery/lifecycle/admission operations |
| `processing_seconds`, `processing_packets_per_second` | Callback elapsed time and processed/callback-time rate |
| `event_sink_seconds` | Actual sink submit/flush time; queued drain waiting is not added twice |

`packets_received = packets_parsed + packets_rejected`; processed can be less
than parsed on stop/processing failure. Compatibility `packets_dropped` remains
capture + interface drops only. Unavailable detailed capture numbers print
`N/A`, not an invented zero. The availability flag governs numeric snapshots.
Loopback `ps_recv` is neither offered datagrams nor unique wire packets: do not
infer a wire-loss percentage or universally divide it by two.

## 7. Capture configuration

Defaults: snapshot **65535 bytes**, promiscuity enabled, requested kernel buffer
**16777216 bytes**, buffered timeout **100 ms**, immediate mode **off**.
Controls: `--snaplen`, `--no-promiscuous`, `--capture-buffer-bytes`,
`--capture-timeout-ms`, `--capture-immediate` (all live-only). Buffered timeout
must be positive. Buffer requests are platform-dependent, not zero-loss promises.

## 8. Queue/backpressure decision and justification

The pre-change file-sink loss disproved the assumption that HTTP caused the
original burst loss, so capture/state hardening came first. A later controlled
real-CLI HTTP probe showed that a **single delayed acknowledgment** independently
causes starvation. This justified the optional bounded sink wrapper.

`--event-queue-capacity N` / `INTRIQO_EVENT_QUEUE_CAPACITY` accepts 0..1000000;
default **0** retains synchronous behavior. A practical test setting is **256**.
The preallocated ring holds at most N pending events plus **one in flight**.
Short admission locks never span transport I/O. Depth/peak exclude that one
worker event. Emission is counted only after the underlying acknowledgment.
Capacity exhaustion rejects/counts the event in both `queue_overflows` and
`sink_failures`, requests capture stop, and returns nonzero after draining.
Worker failure is noticed on the next packet/idle maintenance or shutdown.
No retries or silent discard are introduced. Flush closes admission, drains
admitted events once in order, joins, and flushes the underlying sink; repeated
flush does not double-count a previous failure.

This is an event-count bound, not a generic payload-byte budget or durable spool.
Shutdown can take the sum of admitted sink operation times; DNS/file stalls
are not made bounded by adding a queue. A permanently slow sink eventually
overflows. The measured evidence and remaining synchronous losses are in §13.

## 9. Test results

| Actual final check | Result |
|---|---|
| `ctest --test-dir build/hardening-final-release --output-on-failure` | **70/70 passed** |
| `ctest --test-dir build/hardening-final-no-pcap --output-on-failure` | **70/70 passed** |
| `ctest --test-dir build/hardening-final-asan --output-on-failure` | **70/70 passed**, ASan + UBSan enabled |
| Control Plane Alembic `upgrade head` | Succeeded |
| `control-plane/.venv/bin/python -m pytest control-plane/tests/ -q` | **64 passed** |
| From `agents`: `../control-plane/.venv/bin/python -m pytest tests/ -q` | **81 passed + 4 subtests** |
| Existing E2E with final `INTRIQO_ENGINE_DEMO` override | **1 passed** |
| Live E2E with final `INTRIQO_ENGINE_BINARY`, local Docker opt-in | **4 passed**: both signals × synchronous/queued HTTP |
| From `frontend/dashboard`: `npm run test -- --run` | **11 passed**, 4 files |
| Ruff with Control Plane config on changed Python harness/CLI/live test files | Passed |
| `git diff --check -- . ':!frontend'` | Passed; unrelated frontend whitespace remains |

The original **19 C++ unit cases** and existing runtime tests/assertions remain.
There are **25 new C++ hardening/queue cases** (17 + 8). CTest's 70 entries include
the CLI runner (**11 Python cases**), reliability runner (**10 Python cases**),
and one-second `StateSoakShort`; they are not 70 standalone C++ cases.
Coverage includes expiration boundaries/late packets, deterministic eviction,
direction counters, flow retirement/deduplication, detector caps/windows,
capture-vs-parser-vs-processing accounting/unavailable stats, PCAP read errors,
sink timing, repeated fresh-instance lifecycle, queue bounds/overflow, admission
versus acknowledgment, failure/drain order, and active-traffic signal shutdown.

Failed attempts were not hidden: an initial shared development DB contained
earlier E2E identities, causing `MultipleResultsFound` in the first Control Plane
test (**1 failed, 63 passed**). Existing per-test teardown cleaned it; the
sequential rerun passed all 64 without changing assertions. Do not run these DB
suites concurrently or against production data.

Live E2E exposed a pre-existing query-precision issue: the lower bound
`09:30:06.591106Z` excluded the acknowledged PostgreSQL row timestamp
`09:30:06.591Z`. The test now uses the serializer's millisecond precision and
retains API/readback/PostgreSQL/audit/token-redaction assertions, with sanitized
engine counters on failure. The synchronous and queued paths both pass.
No TSan, physical-interface fuzzing, or 30/60-minute sanitizer soak was run.

## 10. Soak-test methodology

`intriqo-state-soak` uses one checksummed raw TCP fixture at a time through the
real parser/pipeline/registry/detector/file sink. Every four packets repeat a
flow; alternating admitted-source/high-cardinality epochs exercise both detector
caps, varied ports, expiration and flow churn. Logical time jumps beyond both
timeouts between epochs, separate from the paced **wall-clock duration**.
This is a state stress fixture, not live capture or packet-latency measurement.

Its bounded correctness precheck sends two windows × ten ports × five rounds:
exactly **2 events**, distinct valid UUID v4 IDs, expected millisecond timestamps
`2023-11-14T22:13:20.009Z` / `40.009Z`, serialized fields and repeat suppression.
The Python reader independently parses/checks those two records. Long-run
generated/acknowledged event counts are checked; every long-run UUID is not
retained or independently duplicate-checked. This avoids an unbounded test set.

`reliability_benchmark.py` sends ordinary loopback UDP (64-byte payloads) plus
ten ordinary TCP connections to reserved local ports. BPF selects only that
UDP port and TCP SYNs. Successful `sendto` calls define offered traffic, not
receiver consumption or `ps_recv`. A receiving-thread count separately exposes
UDP receiver loss. Benchmark capture includes startup/drain time; offered rate
uses workload time. No raw injection, remote scan, privileged service, or metrics
infrastructure is introduced. Docker is an optional existing local NET_RAW
launcher with read-only executable/public-library mounts, not a deployment.

Memory/CPU/state samples stream every **1 second**, retaining only bounded
first/last/peak summaries. `/proc/<actual-engine-PID>` is used even with Docker;
PID reuse is checked. Process CPU is user + system / elapsed, not whole-host CPU.
State fixture RSS is sampled in-process; capture buffer mappings are included in
live RSS. `getrusage.ru_maxrss` can inherit launcher peaks and is kept separate,
not substituted for sampled engine RSS. Subsecond offline processes have too few
external samples for a trend; final engine CPU/RSS is reported separately.

Both five-minute soaks completed again on the final C++ code. State and live
soaks overlapped on a shared, unpinned developer host; these are not isolated
capacity measurements. Earlier interrupted/failed results remain on disk and
are not counted as successful runs. **1800/3600 seconds are supported but not run.**

### Reproducible commands

```bash
cmake -S . -B build/hardening-final-release -DCMAKE_BUILD_TYPE=Release \
  -DINTRIQO_BUILD_TESTS=ON
cmake --build build/hardening-final-release --parallel 4
ctest --test-dir build/hardening-final-release --output-on-failure
# No-libpcap: fresh build directory with -DINTRIQO_ENABLE_PCAP=OFF.
# ASan+UBSan: fresh Debug build directory with -DINTRIQO_ENABLE_ASAN=ON.

# Select ONE duration: 300 (5 min), 1800 (30 min), or 3600 (60 min).
seconds=300
stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p benchmarks/engine/results
build/hardening-final-release/engine/intriqo-state-soak \
  --duration-seconds "$seconds" --rate 10000 --ports 1000 \
  --max-active-flows 256 --max-tracked-sources 64 \
  --max-tracked-observations 128 --flow-idle-timeout 2 \
  --sample-interval-ms 1000 \
  --output "benchmarks/engine/results/state-${seconds}s-${stamp}.jsonl"

# Retain a pre-change Release build before editing; never rebuild that baseline
# from changed sources. Without --baseline-report, baseline runs before candidate.
python3 scripts/benchmark/reliability_benchmark.py \
  --build build/hardening-final-release --baseline-build build/hardening-baseline \
  --offline --live-overload --overload-duration-seconds 3 \
  --sample-interval-ms 100 --docker-image ubuntu:26.04 \
  --output "benchmarks/engine/results/comparison-${stamp}.json" \
  --baseline-output "benchmarks/engine/results/baseline-${stamp}.json"

# Five/30/60-minute local live soak. This reuses the completed short baseline,
# verifies its executable hash, and does NOT imply a matched-duration baseline.
python3 scripts/benchmark/reliability_benchmark.py \
  --build build/hardening-final-release --baseline-build build/hardening-baseline \
  --baseline-report benchmarks/engine/results/hardening-final-matched-baseline-v2.json \
  --live-soak --duration-seconds "$seconds" --soak-rate 10000 \
  --flow-idle-timeout 2 --sample-interval-ms 1000 --docker-image ubuntu:26.04 \
  --output "benchmarks/engine/results/live-${seconds}s-${stamp}.json"

# Controlled HTTP fixture, not a PostgreSQL throughput benchmark:
python3 scripts/benchmark/sink_stall_probe.py --build build/hardening-final-release \
  --docker-image ubuntu:26.04 --event-queue-capacity 256 \
  --output "benchmarks/engine/results/sink-stall-${stamp}.json"
```

Normal libpcap-dev installations need no dependency overrides. This host used
extracted headers at `/tmp/opencode/intriqo-hardening-deps/root/usr/include`,
system `/usr/lib/x86_64-linux-gnu/libpcap.so.0.8`, and existing GoogleTest source
via `PCAP_INCLUDE_DIR`, `PCAP_LIBRARY`, `FETCHCONTENT_SOURCE_DIR_GOOGLETEST`.
Never reuse old CMake caches after relocating the checkout. Result paths are
exclusive; choose fresh names rather than overwrite failed or previous evidence.

## 11. Memory and sustained-operation results

| Final five-minute run | State fixture | Live loopback/file sink |
|---|---:|---:|
| Wall seconds | 300.005100 | 300.515000 |
| Offered packets | 3000000 fixture packets | 3000000 UDP + 10 TCP SYNs |
| Achieved offered rate/s | 9999.830 | 10000.001 UDP |
| Captured / parsed / processed | 3000000 / 3000000 / 3000000 | 3000010 / 3000010 / 3000010 |
| Capture / interface drops / parser rejects | 0 / 0 / 0 (finite source) | 0 / 0 / 0 |
| Events generated / acknowledged | 23232 / 23232 | 1 / 1 |
| Flows created / expired / evicted / flushed | 750000 / 92928 / 656816 / 256 | 11 / 10 / 0 / 1 |
| Peak / final flows | 256 / 0 | 11 / 0 |
| Detector peak sources / IDs; final live state | 64 / 128; both 0 | 1 / 10; both 0 |
| Detector state rejections / errors | 1851664 / 0 | 0 / 0 |
| Initial / peak sampled / final RSS KiB | 4628 / 5028 / 5028 | 5760 / 22660 / 6412 |
| CPU user / system seconds | 18.651288 / 6.679608 | 3.635977 / 0.341888 |
| CPU utilization | 8.443488% | 1.323683% |
| Sample count | 301 | 301 |

State RSS was **4900 KiB** throughout the final 30 pre-flush samples, compared
with 4628..4900 KiB in the first 30. The 5028 KiB peak/final includes shutdown
temporary flow output/allocator retention. Live warmed RSS was **22660 KiB**
throughout first/last 30 external samples; releasing capture mappings lowered
post-flush RSS to 6412 KiB. No continuous RSS rise was observed in these runs.
This does **not** prove no leak, a universal byte bound, or stability for an hour.
ASan/UBSan passes are additional finite-test evidence, not such a guarantee.

Early/late ~29-second processing windows: state **10000.013 / 9999.984 pps**;
live **10008.584 / 9997.931 pps**. No sustained offered-rate shortfall was seen.
State CPU varied **7.415% / 10.614%** over those windows; fixed pacing does not
establish unchanged saturation throughput. Live effective whole-window processing
was **9982.896 pps**, with raw `ps_recv=6000020`; callback-time derived rate was
**1070259.901 pps**, not its live capture capacity. Its only event latency sample
was **4.916698 ms**; packet P99 is **N/A**.

Evidence: `benchmarks/engine/results/state-soak-300s-queue-phase-v2.jsonl`,
`benchmarks/engine/results/hardening-final-measurements-v2.json`, and its
`hardening-final-measurements-v2-raw/candidate/live-soak/` sample/stdout files.
The earlier successful state/live five-minute repeats are retained as
`state-soak-300s-final-v2.jsonl` and `live-soak-300s-complete-v2.json`.

## 12. Overload results

Final matched baseline-first comparison: **3 seconds offered traffic per stage**,
~3.52 seconds capture including startup/drain; same filter, 64-byte UDP, known
ten-port TCP scan and real FileEventSink(`/dev/null`). Legacy baseline exposes
only combined drops and callback/parse counts; its completed-processing count
and raw receive/drop breakdown are **N/A**, not reconstructed.

| Build/load | Achieved offered UDP/s | Captured callbacks | Whole-window capture/s | Completed processing/s | Reported drops | Events | CPU % | Sampled peak / final RSS KiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline low | 100.327 | 310 | 88.120 | N/A | 0 combined | 1 | 0.769 | 38796 / 6164 |
| Baseline medium | 1000.282 | 3010 | 856.922 | N/A | 0 combined | 1 | 1.778 | 38988 / 6356 |
| Baseline high | 10000.135 | 7658 | 2172.651 | N/A | **44679 combined** | 1 | 2.102 | 38884 / 6252 |
| Baseline unpaced | 201252.544 | 8316 | 2364.771 | N/A | **1190860 combined** | **0** | 0.778 | 38896 / 6392 |
| Buffered low | 100.330 | 310 | 87.849 | 87.849 | 0 capture + 0 interface | 1 | 0.499 | 22676 / 6428 |
| Buffered medium | 1000.302 | 3010 | 854.349 | 854.349 | 0 + 0 | 1 | 0.629 | 22664 / 6416 |
| Buffered high | 10000.052 | 30010 | 8525.950 | 8525.950 | 0 + 0 | 1 | 1.476 | 22600 / 6352 |
| Buffered unpaced | 184197.922 | 552604 | 157141.165 | 157141.165 | 0 + 0 | 1 | 10.063 | 22580 / 6332 |

Offered rates exclude the ten TCP SYNs; callback totals include them. All
candidate callbacks parsed and completed processing, with no sink/parser errors.
Baseline loss begins materially between the 1000/s and 10000/s stages. Its
unpaced run loses the known detection: no delivery success is inferred.
Buffered candidate saturation was **not reached** by this generator. A separate
final repeat reached **224788.539 UDP/s**, capturing/processing **674376** callbacks
with zero reported capture/interface drops and one event. This is only a tested
low-cardinality operating point, not line rate or a maximum capacity.

At that unpaced point the UDP receiver consumed **665255** of **674366** offered
datagrams while IDS captured all selected packets. Receiver/socket loss is not
IDS capture loss. The final matched candidate receiver similarly consumed
**530663** of **552594** offered datagrams. No receiver count is used to calculate
IDS drops: `workload.receiver_udp_datagrams_after_drain` remains a distinct field.

Each live stage produced at most one latency sample: buffered matched samples
**39.949440 / 38.599190 / 11.691228 / 2.549633 ms**. The tool's single-event P99
equals that sample, but is not a meaningful packet-P99 distribution. Packet P99
is **N/A**; low load pays buffering latency. Detection rates are approximately
**0.28 events/s**, reflecting one scan and idle/drain time, not detector capacity.

The explicit immediate-mode candidate comparison confirms the tunable tradeoff:
at 100/1000 target UDP/s, 310/3010 callbacks, zero drops, one event, latencies
**0.135193 / 0.167895 ms**; at 10000/s, **6577 callbacks / 46840 capture drops /
0 events**; unpaced, **10222 / 1119807 / 0**. It was measured before optional
queue integration with the same capture implementation, not silently discarded.

Evidence: `benchmarks/engine/results/hardening-final-matched-baseline-v2.json`,
`hardening-final-matched-v2.json`, their `hardening-final-matched-v2-raw/` files,
`hardening-final-measurements-v2.json`, and `hardening-immediate-complete-v2.json`.

## 13. Capture-loss results and remaining backpressure

Historical burst **867 captured / 265 reported drops** remains in
`runtime-validation.md` and `runtime.json`. Fresh pre-change burst **863 / 272**
remains in `hardening-baseline-v2.json`. The earlier matched candidate comparison
captured **310 / 3010 / 30010 / 401603** callbacks across increasing loads with
zero reported drops; corresponding baseline **310 / 3010 / 9643 / 7807** and
**0 / 0 / 40710 / 788498** combined drops remain in the comparison-v2 files.
No historical result is replaced with the newest faster host run.

Controlled sink-stall probe uses the real CLI + real HttpEventSink and a local
HTTP responder, not a mock sink and not the FastAPI/PostgreSQL throughput path.
Each 3-second run offered ~100000 UDP/s plus one scan; the responder delays a
single event acknowledgment. Same final executable in both delivery modes:

| Ack delay | Synchronous offered UDP / captured | Synchronous capture drops | Queued offered UDP / captured | Queued capture drops | Ack events sync / queued |
|---|---:|---:|---:|---:|---:|
| 0 s | 300000 / 300010 | 0 | 299999 / 300009 | 0 | 1 / 1 |
| 0.5 s | 299996 / 291942 | **16128** | 299609 / 299619 | 0 | 1 / 1 |
| 1 s | 300000 / 241272 | **117476** | 299997 / 300007 | 0 | 1 / 1 |

Queued capacity was 256, peak pending depth **1**, final depth **0**, overflows
**0**. Actual queued sink time was **0.000918 / 0.500881 / 1.000910 seconds**;
generation/acknowledgment counts match. Both modes had zero parser/interface
errors. This removes the measured bounded stall from callback processing; it
does not prove a permanently slow endpoint can be absorbed. Synchronous mode
remains the compatible default, with these losses explicitly documented.
The first probe's **16254 / 117686** delayed-ack drops are also retained.

Evidence: `benchmarks/engine/results/sink-stall-synchronous-final-v2.json`,
`sink-stall-queued-v2.json`, `sink-stall-probe-v2.json`, and matching raw folders.
Live E2E separately verified both modes through authenticated FastAPI, an actual
PostgreSQL row, API readback and successful audit records for SIGINT and SIGTERM.

## 14. Updated throughput results

Environment: Intel Core 5 210H, ~22.6 GiB RAM, Ubuntu 26.04.1, kernel
`7.0.0-34-generic`, GCC **15.2.0**, C++20 Release, libpcap **1.10.6**. CPU affinity
0..11, not pinned; shared host, dirty working tree based on `765b19d`.
The harness records executable hashes, environment, configuration, per-run raw
stdout/stderr/samples and fixture hash. Saved baseline metadata is current host
metadata; the **retained executable hash** identifies the pre-change binary.

Offline fixture: **100000 raw packets, 1000 ports/flows, one source**, fixed
historical timestamps; real serialization/file transport included. Each mode
has three runs. Generation/checksums and PCAP I/O are inside their timings.
All 100000 packets parsed; all candidate packets processed; each run emitted
one event, flushed 1000 flows and ended with zero active state/rejections/drops.

| Mode | Baseline three rates, packets/s | Baseline median | Final candidate three rates | Candidate median |
|---|---|---:|---|---:|
| Synthetic | 444094.10 / 453549.39 / 422081.03 | **444094.10** | 1632097.35 / 1559702.87 / 1750919.67 | **1632097.35** |
| PCAP | 459896.70 / 483196.18 / 492545.95 | **483196.18** | 1767229.16 / 1825352.67 / 1695569.17 | **1767229.16** |

Synthetic candidate wall times **0.061271 / 0.064115 / 0.057113 s**, CPU
~100.09..100.13%, final RSS **6484 / 6544 / 6456 KiB**. PCAP times
**0.056586 / 0.054784 / 0.058977 s**, CPU ~99.66..100.21%, final RSS
**6392 / 6412 / 6460 KiB**. These short tests do not establish peak memory.
At the medians, flow/event rates are **16320.97 / 16.32 per second** synthetic
and **17672.29 / 17.67 per second** PCAP: workload rates, not maximum event load.
Offline wall-clock latency is **N/A**, not the age of the historical fixture.

The earlier same-workload comparison remains: baseline medians
**301667.81 / 302604.31**, candidate **1134038.42 / 1069600.33**. Host frequency/
load variance is substantial; do not present a cross-run best-value ratio as a
universal improvement. Removing full-table expiry scans changes the measured
offline work cost; buffered libpcap changes live loss behavior. Neither offline
number is a live capture guarantee. Historical pre-parsed **285405 pps** uses
different input/settings and remains preserved, not directly compared.

PCAP fixture SHA256:
`7d5ce6d0d50098892c5478b208be2b645101f4ce3cfdc27431c736ef0f990a9e`.
Final benchmark SHA256:
`b565990802444401e6a465fb8de73afb0190846f85f194e5b1210e64c090775d`.
Baseline benchmark SHA256:
`8362e8a000aeb0fa9e2fc5f5dfc8ef82c380a27fd48955dcad1fcf8d5b5531f9`.
CLI used for both sink probes SHA256:
`07b895b1a0ec99c038c5754aaf9c5f2acb61143bcaf34b4164cdb19699d2368d`.

## 15. Known limitations

- Buffered capture saturation is not established. Highest achieved offered rate
  was ~225k UDP/s for three seconds, on loopback with only 11 flows. No physical
  NIC/SPAN/TAP, production network, line-rate, or universal zero-loss claim.
- Five-minute state and live soaks completed; 30/60-minute procedures are
  supported, **not executed**. No all-duration leak/race certification. Sustained
  low-rate performance does not measure end-of-soak saturation capacity.
- Capacity eviction and detector admission rejection reduce coverage. State
  counts are finite, but are not byte-level memory guarantees: per-source ports
  can reach 65535 within a window, and large configured limits cost memory.
  The 256/64/128-cap fixture is not default-cap worst-case sizing.
- Synchronous default HTTP/file delivery can stall capture. Optional queue
  absorbs bounded event bursts only; overflow stops capture and loses that
  explicitly counted event. It is not durable and cannot survive process death.
- HTTP remains plain HTTP, one synchronous request per worker event, no TLS,
  persistent connection or retries. Blocking DNS is outside the socket deadline;
  slow DNS/file I/O can delay drain indefinitely. File flush is not `fsync`.
- `ps_recv`/`ps_drop`/`ps_ifdrop` differ by OS/interface/filter; interface zero may
  mean unsupported. No exact wire-loss percentage is inferred. Buffered timeout
  increases detection latency at low load; packet P99 was not measured.
- Long-run event counts and bounded known-scan UUID/JSON/timestamps were checked;
  all long-run UUIDs are not stored for global collision checking. TSan and
  systematic fuzzing were not run. Only the existing deterministic detector is
  enabled; thresholds can flag benign connections.
- Existing IPv4-only/no VLAN/fragment or TCP-stream reassembly/classic PCAP
  restrictions remain. FIN/RST are not immediate flow termination. Source and
  engine instances remain single-use; restart uses fresh instances.
- Shared development DB test fixtures delete records and require serial suites.
  Unrelated frontend whitespace remains outside this task. No deployment/auth/
  Control Plane/agent implementation changes or commits were made here.

## 16. Recommended next phase

Keep the same architecture: run 30/60-minute release soaks, add end-of-soak
fixed-workload capacity probes and bounded all-event validation, then test an
**explicitly authorized physical NIC/mirror/TAP** with a stronger controlled
generator and varied flow/source cardinality. Establish the buffered saturation
boundary and packet-latency distribution before making capacity claims. Size
flow/source/port/queue memory from the actual workload and exercise sustained
slow/failing authenticated ingestion plus queue overflow/drain deadlines.
Consider TSan/fuzzing and DNS/shutdown deadline hardening next. Do not add
detectors, agents, ML, Kafka/Redis, microservices or UI features to obscure the
remaining capture/transport limitations.
