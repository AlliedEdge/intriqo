# Flow-feature boundary — implementation and measured validation report

Validated 2026-10-05 (Asia/Calcutta), starting from clean `main` at
`049c214`. This phase implements a data boundary, **not ML capability**.
No commits/pushes, models, detectors, frontend, auth implementation, brokers,
services or unrelated architecture changes were made.

## 1. Files added

- `contracts/features/flow_features_v1.json`
- `docs/engine/flow-feature-contract.md`
- `docs/engine/flow-feature-validation.md`
- `engine/include/intriqo/features/flow_feature_record.hpp`
- `engine/src/features/flow_feature_record.cpp`
- `engine/include/intriqo/transport/flow_feature_sink.hpp`
- `engine/src/transport/flow_feature_sink.cpp`
- `engine/tests/unit/test_flow_feature_record.cpp`
- `engine/tests/integration/test_flow_feature_sink.cpp`
- `engine/tests/integration/test_flow_feature_pipeline.cpp`
- `engine/tests/integration/test_flow_feature_lifecycle.cpp`
- `engine/tests/fixtures/flow_feature_fixture.py`
- `ml/src/intriqo_ml/__init__.py`
- `ml/src/intriqo_ml/flow_features.py`
- `ml/src/intriqo_ml/consumer.py`
- `ml/tests/unit/test_flow_features.py`
- `ml/tests/integration/test_cpp_feature_stream.py`
- `tests/e2e/test_flow_feature_boundary.py`
- `scripts/benchmark/flow_feature_benchmark.py`

Generated builds, the local swarm board and benchmark outputs are ignored
coordination/evidence, not committed source files. Original successful partial
work was preserved after interruption; a duplicated CMake test registration was
removed and both distinct lifecycle test sets retained.

## 2. Files modified

- `README.md`
- `.github/workflows/ci.yml`
- `contracts/README.md`
- `docs/engine/ids-engine.md`
- `engine/CMakeLists.txt`
- `engine/tests/unit/CMakeLists.txt`
- `engine/tests/integration/CMakeLists.txt`
- `engine/include/intriqo/pipeline/pipeline.hpp`
- `engine/include/intriqo/pipeline/pipeline_impl.hpp`
- `engine/src/pipeline/pipeline_impl.cpp`
- `engine/include/intriqo/metrics/metrics.hpp`
- `engine/src/runtime/engine_impl.cpp`
- `engine/tools/engine_main.cpp`
- `engine/tools/runtime_reporting.hpp`
- `engine/tools/benchmark_runtime.cpp`
- `ml/pyproject.toml`

The parser, flow table, feature extractor, PortScanDetector, SynFloodDetector,
SecurityEvent serializer, Control Plane, agents, existing auth fixes and frontend
implementation are unchanged.

The existing engine CI job now also runs the typed consumer and real boundary
tests with only Pydantic/pytest installed. This is a test dependency, not a C++
runtime dependency. The hosted workflow itself was not executed from this session;
the corresponding local commands were executed successfully.

## 3. Existing measurements discovered

The audit found 15 trustworthy FlowFeatures measurements: total packet/IPv4-byte
counts; duration; mean bytes/packet; packet and byte rates; six TCP flag counts;
and three ordered handshake-evidence booleans. NetworkFlow additionally supports
four direction-specific counters. Its existing ID, first/last packet times and
five-tuple supply metadata. The legacy `connection_attempts` field is a uint32
cast of packet count and is **excluded** rather than misrepresented as attempts.
No RTT, interarrival distribution, payload measurements, retransmission estimate,
labels, normalized features or anomaly scores were invented.

## 4. Final schema

`flow_features.v1` requires exactly three top-level keys:

```text
schema_version: "flow_features.v1"
metadata:
  engine_instance_id, flow_id, first_seen, timestamp, export_reason
  network: src_ip, dst_ip, src_port, dst_port, protocol
features:
  packet_count, byte_count, duration_seconds, bytes_per_packet
  packets_per_second, bytes_per_second
  fwd_packet_count, rev_packet_count, fwd_byte_count, rev_byte_count
  syn_count, fin_count, rst_count, initial_syn_count, syn_ack_count, ack_count
  tcp_handshake_started, tcp_syn_ack_seen, tcp_handshake_completed
```

No field may be null; no optional/unknown fields are accepted. Flow IDs are
canonical nonzero uint64 decimal strings scoped by the engine/pipeline UUID.
Version changes require an explicit new schema/parser, never silent v1 drift.

## 5. Field-by-field definitions

The complete normative [field table](flow-feature-contract.md#field-contract)
defines each name/type/unit/direction/range/calculation/raw-or-derived category,
with an actual C++ test example. Duration uses existing widened native clock
ticks, rates are zero at zero duration, and byte counts mean parsed IPv4 total
length—not Ethernet bytes or payload bytes. TCP ACK-only counts exclude
SYN/FIN/RST. First-observed orientation is preserved, not inferred client/server
roles. Nanosecond UTC timestamps are losslessly retained by Python.

## 6. Lifecycle decision

Emit one final record at actual idle expiry, oldest-flow capacity eviction or
EOF/signal/error/explicit flush. FIN/RST stay tracked counters, preserving existing
detector/flow behavior and trailing observations. Short, incomplete and midstream
flows are retained. Active long-lived flows do not continuously emit snapshots.
No per-packet export or raw packet delivery is added.

## 7. Serialization

Deterministic fixed-order UTF-8 JSONL, 8192-byte body bound plus LF; checked UTC
timestamps, canonical IPv4, complete escaping, exact integer spelling,
locale-independent round-trip binary64 precision and no NaN/Infinity. No extra
JSON library was added. Construction now checks timestamps without formatting;
the worker alone renders JSON/timestamp strings. SecurityEvent v1 is untouched.

## 8. Stream abstraction

FlowFeatureSink has submit/flush/statistics. FileFlowFeatureSink has one worker,
one persistent secure local descriptor and a preallocated bounded ring. CLI
`--feature-output` enables it; `--feature-queue-capacity` defaults to 4096 and
permits 1..65536. Disabled streaming does not allocate/start a feature worker.

## 9. Python validation model

Frozen strict Pydantic v2 record/metadata/network/features models; explicit v1
dispatch; typed nanosecond timestamps; bounded binary JSONL reader; payload-free
errors and per-line continuation. No feature calculation, preprocessing or model
is performed. Draft-07 schema parity is tested; runtime parser additionally
enforces transport, token and cross-field constraints JSON Schema cannot express.

## 10. Failure/backpressure

Drop newest at queue capacity, count every rejection/loss, keep deterministic
capture running. Bad records do not disable subsequent valid records; fatal
file/worker failure disables the stream and accounts for all pending/future
records. Shutdown closes admission, drains or counts loss, joins and closes.
No mutex spans serialization/I/O. File I/O has no hard shutdown deadline, no
fsync durability/retry guarantee, and a partial failure may leave a damaged tail.
Final submitted = written + dropped; queue depth is zero. Generation/setup
failures have separate counters. Feature loss warns but is not an IDS stop/exit
failure; operators must monitor feature counters separately.

## 11. Security

Only extracted measurements and network/time correlation metadata are sent;
never payloads, JWTs, secrets, credentials or unrelated logs. Closed/escaped
strings and bounded parsing prevent arbitrary log/payload injection. Files are
created mode 0600, regular/local-only, with pinned parent directories and no
symlinks; existing permissions require operator review. Metadata is separated
from future model inputs. Off-host integration must require TLS/authentication/
authorization. No remote ML endpoint is implemented.

## 12. C++ and Python unit/integration results

| Check | Actual result |
|---|---|
| Release CTest, feature-enabled | **141/141 passed** |
| Release CTest, `INTRIQO_ENABLE_PCAP=OFF` | **141/141 passed** |
| Debug ASan + UBSan CTest | **141/141 passed** |
| Debug TSAN CTest | **141/141 passed** |
| Python `ml/tests` | **412 passed** |
| Python Ruff scoped boundary files | passed |
| Python mypy `ml/src/intriqo_ml --strict` | passed |
| Targeted feature record/sink checks | **18/18 record**, **10/10 sink**; integrated in CTest |

The tests cover exact deterministic JSON, rates/zero-duration, timestamps,
IPv4/protocols, TCP/UDP/incomplete records, multiple-flow independence, bounded
overflow/failed writes/partial writes/concurrent flush, lifecycle reasons and
detector parity. Python covers valid/missing/wrong-type/range/nonfinite/
unsupported-version/unknown-field/depth/duplicate-key/oversized-line handling.

## 13. Real end-to-end feature-stream results

The controlled path was real generated/PCAP traffic only:

```text
PCAP -> C++ replay/parser/flow table/extractor -> FlowFeatureRecord v1
     -> bounded FileFlowFeatureSink JSONL -> Python Pydantic validation
```

The C++ binary emitted untouched JSONL; Python parsed exact bytes and compared
model dumps against every JSON object. Synthetic 30 packets produced 10 records;
completed-handshake PCAP produced 4 exact directional records; nanosecond UDP
PCAP preserved exact timestamps/rates; incomplete flows exported at idle,
capacity and shutdown; SIGINT/SIGTERM drained 10 shutdown records. The dedicated
Python integration suite is included in 412 tests. Existing plus new E2E passed
**13/13**, including local-only Docker/loopback live validation. Feature output
used no Control Plane endpoint; existing event/auth/live tests verified that path.

## 14. Performance comparison (actual controlled measurement)

```bash
python3 scripts/benchmark/flow_feature_benchmark.py \
  --build build/flow-release --baseline-build build/flow-baseline \
  --packets 1000000 --flows-per-cycle 1000 --packets-per-flow 50 \
  --repeats 5 --output benchmarks/engine/results/flow-features-v1-final.json
```

Release builds used the same one-million-packet historical PCAP/20,000 flows,
same detectors and file event sink, CPU affinity `[0,1]`, five medians, and
Intel Core 5 210H / Linux 7.0.0-34-generic / GCC 15.2.0. All variants parsed
and processed one million packets with zero drops/rejections.

| Variant | packets/s | flows/s | CPU util. | records | written/dropped | post-flush RSS |
|---|---:|---:|---:|---:|---:|---:|
| A existing baseline | 955,496 | 19,110 | 100.06% | N/A | N/A | 6,868 KiB |
| candidate disabled | 918,973 | 18,379 | 100.07% | 0 | N/A | 6,940 KiB |
| B generate/admit only | 932,071 | 18,641 | 100.06% | 20,000 | 0/0 | 6,956 KiB |
| C bounded JSONL file | 816,131 | 16,323 | 125.98% | 20,000 | 20,000/0 | 7,936 KiB |

Against the same-build disabled candidate, B measured **+1.43%** packet
throughput (within run variance), while C measured **-11.19%**; against the
historical A baseline C measured **-14.59%**. C spent 0.207 seconds serializing
and 0.345 seconds writing 20,000 records; JSONL was 16,328,754 bytes (~816
bytes/record). The file sink is a validation sink, not a production line-rate
claim. Deterministic event counts remained 4 in all variants.

Deliberate pressure (`100,000` packets/flows, capacity 8, one packet/flow)
measured disabled **445,036 packets/s**, file **361,061 packets/s**; the file
sink wrote **4,368**, dropped **95,632**, and counted **95,632 queue overflows**.
This demonstrates visible bounded loss under excessive record production.

Raw evidence is in ignored artifacts
`benchmarks/engine/results/flow-features-v1-final.json` and
`flow-features-v1-pressure.json`; each records input hash, host, affinity,
revision/dirty state, medians and every run. No traffic was sent.

## 15. Memory impact

For the one-million-packet run, post-flush RSS was 6,940 KiB disabled, 6,956
KiB generation-only (**+16 KiB**), and 7,936 KiB JSONL (**+996 KiB**). Process
high-water `ru_maxrss` was 24,460 KiB in all candidates and is not a heap-only
measurement. A feature record object is 192 bytes in this build; sink state is
bounded by configured capacity. Capacity-8 pressure post-flush RSS was 6,960
KiB. No unbounded feature queue was observed.

## 16. Regression results

| Existing validation | Actual result |
|---|---|
| Control Plane Alembic upgrade + tests | migration succeeded; **131 passed** |
| Agents tests | **81 passed + 4 subtests** |
| Frontend Vitest + TypeScript typecheck | **11 passed**, typecheck passed |
| Existing vertical slice and opt-in live E2E | included in **13/13 passed** |
| Authentication-token regression | existing HTTP/live tests passed; token stayed environment-only and absent from output |
| `git diff --check` | passed |

One initial frontend command was accidentally invoked from the repository root
(which has no `package.json`); the exact command was rerun from
`frontend/dashboard` and passed. This was not a project test failure.

## 17. Known limitations

The contract is IPv4-only and Linux file-sink checks are platform-specific.
FIN/RST do not close flows immediately. Native clock range and file stalls limit
operational behavior. JSONL has no rotation/fsync/durable retry; partial tails
require operator handling. Queue capacity is records, not bytes. Existing event
records do not gain the feature correlation key. No production remote transport,
normalization, model worker, score/result schema or anomaly event exists.

## 18. Exact future ML integration point

The future worker starts only after `intriqo_ml.consumer.iter_flow_feature_records()`
returns a validated record:

```python
for item in iter_flow_feature_records(binary_jsonl_stream):
    if item.record is None:
        continue
    metadata = item.record.metadata  # correlation only
    vector = item.record.features     # future preprocessing/model input
```

C++ continues packet capture, flow tracking and deterministic detection when the
worker is absent/slow. A future sink can implement the same bounded interface;
off-host transport must add TLS/authentication/authorization and a versioned
result contract.

## 19. Explicit non-claims

**Implemented:** C++ → `flow_features.v1` → bounded local JSONL → Python typed
validation, with tests and measured overhead/backpressure. **Not implemented:**
Isolation Forest, XGBoost, Random Forest, neural network, training, inference,
anomaly scoring, normalization, model selection, Kafka, Redis, schema registry,
ML API, LLM/agents, frontend changes, new detectors or IPv6.
