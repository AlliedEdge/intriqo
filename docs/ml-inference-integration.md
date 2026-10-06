# Optional Isolation Forest v2 Inference Integration

## 1. Architecture

The integration keeps the packet-processing architecture split:

```text
PCAP/live capture
    ↓
C++ Engine: flow tracking + deterministic detectors
    ↓ bounded asynchronous local JSONL feature sink
flow_features.v2 (native FlowFeatureRecord v2)
    ↓ operator-managed Python worker
locked Isolation Forest v2
    ↓ existing bearer-authenticated POST /api/v1/events
FastAPI Control Plane → PostgreSQL → existing event/incident workflow
```

The Python worker is a separate process. It does not run in the C++ packet
callback, does not start or control capture, and does not feed decisions back
into flow tracking, `PortScanDetector`, or `SynFloodDetector`. The existing C++
feature sink is bounded and uses drop-newest admission. Python input parsing,
inference, and delivery are therefore ML-only work.

The initial boundary is an ordinary local JSONL file, not Kafka, Redis, or a
new broker. Flow records are emitted on idle expiry, capacity eviction, or
shutdown flush, as defined by the existing engine feature lifecycle.

## 2. Model artifact

Only this already-locked artifact is admitted:

```text
ml/artifacts/models/controlled-v2/isolation-forest-v2/model.joblib
```

The loader reads and hashes the exact bytes, verifies the hash before
deserializing with joblib, then verifies that the loaded fitted estimator is
the expected `sklearn.ensemble.IsolationForest` with the locked parameters:

```text
n_estimators=300
max_samples=auto
contamination=auto
random_state=42
n_jobs=-1
bootstrap=false
max_features=1.0
warm_start=false
verbose=0
```

Expected model SHA-256:

```text
69d7df6a027eebcaa64c227c3ab34d8a9fd44d4a0158264e86c3fb93db960cb5
```

The integration never fits, refits, regenerates, or mutates this artifact.

## 3. Threshold

The threshold artifact is:

```text
ml/artifacts/models/controlled-v2/isolation-forest-v2/threshold.json
```

Expected threshold SHA-256:

```text
28ebd68f65e255e9c32aa433b609c4dc969402605d936b8d49c357c5979058b2
```

The locked value is exactly `0.5153855054112947`. The rule is inclusive:

```text
anomaly_score = -model.score_samples(features)
is_anomaly = anomaly_score >= 0.5153855054112947
```

The loader verifies both the threshold file hash and the threshold metadata,
including its binding to the verified model hash and its score convention. It
does not select or tune a second threshold at runtime.

## 4. Feature contract

The native record is parsed only with the strict v2 parser and projected only
from its validated `features` object. The frozen contract is:

```text
contracts/features/flow_features_v2.json
```

The exact ordered model inputs are:

1. `duration_seconds`
2. `packet_count`
3. `packets_per_second`
4. `minor_direction_packet_fraction`
5. `mean_ipv4_packet_bytes`
6. `ipv4_direction_byte_imbalance`
7. `syn_packet_fraction`
8. `fin_packet_fraction`
9. `flow_iat_std_seconds`

The contract SHA-256 is
`67b96b59fce896ba33fdfd93cb445eeab901a2cee2c5b3347267622e0a140924`.
The loader verifies the contract hash, schema artifact version, count, order,
`preprocessing=NONE`, and float64-loaded/float32-model-input declarations.
Missing, extra, reordered, non-finite, negative, or wrong-version records are
rejected. Arbitrary dictionaries are not an inference API. Python does not
recompute native measurements for the model vector.

## 5. Inference API

The implementation is in `ml/src/intriqo_ml/inference_v2.py`:

```python
config = MLConfig.from_env()
detector = MLDetector(config)
result = detector.detect(validated_flow_feature_record_v2)
```

The detector states are `STARTING`, `READY`, `DEGRADED`, and `FAILED`. It can
become `READY` only after all artifact, schema, parameter, and fitted-model
checks pass. A disabled detector is `DEGRADED` with the stable reason
`disabled_by_configuration`; load or inference failures fail closed with
payload-free status reasons.

`MLDetectionResult.to_dict()` contains only:

- detector name and model version;
- engine instance ID and flow ID;
- anomaly score and locked threshold;
- boolean decision;
- feature schema version;
- inference timestamp;
- model and threshold hashes.

It contains no labels, training metadata, controller-owned ground truth, raw
feature vectors, ports, or IP addresses.

## 6. Configuration

ML is disabled unless explicitly enabled:

```text
INTRIQO_ML_ENABLED=false
INTRIQO_ML_MODEL_PATH=
INTRIQO_ML_THRESHOLD_PATH=
INTRIQO_ML_EXPECTED_MODEL_SHA256=
INTRIQO_ML_EXPECTED_THRESHOLD_SHA256=
INTRIQO_ML_FEATURE_SCHEMA_PATH=
INTRIQO_ML_FEATURE_CONTRACT_PATH=contracts/features/flow_features_v2.json
```

When enabled, model, threshold, and model feature-schema paths are required.
Expected hashes default to the locked constants but may only be set to those
same locked values. `INTRIQO_ML_MODEL_METADATA_PATH` is optional and otherwise
defaults beside `model.joblib`.

The worker also supports:

```text
INTRIQO_ML_MAX_DEDUP_ENTRIES=100000
INTRIQO_CONTROL_PLANE_URL=http://127.0.0.1:8000
INTRIQO_CONTROL_PLANE_ENDPOINT=/api/v1/events
INTRIQO_CONTROL_PLANE_TOKEN=<service token, supplied outside source control>
INTRIQO_ML_TRANSPORT_TIMEOUT_SECONDS=5
INTRIQO_ML_TRANSPORT_MAX_ATTEMPTS=1
```

Tokens are sent only as bearer authentication and are never logged. The
worker's `--output`, `--ledger`, and optional `--stats` files must be new and
distinct from the input and all artifacts.

Example operator flow:

```bash
INTRIQO_ML_ENABLED=true \
INTRIQO_ML_MODEL_PATH=ml/artifacts/models/controlled-v2/isolation-forest-v2/model.joblib \
INTRIQO_ML_THRESHOLD_PATH=ml/artifacts/models/controlled-v2/isolation-forest-v2/threshold.json \
INTRIQO_ML_FEATURE_SCHEMA_PATH=ml/artifacts/models/controlled-v2/isolation-forest-v2/feature_schema.json \
python -m intriqo_ml.ml_worker features.v2.jsonl \
  --output /tmp/intriqo-ml-anomalies.jsonl \
  --ledger /tmp/intriqo-ml-decisions.sqlite \
  --stats /tmp/intriqo-ml-stats.json
```

The C++ side remains independently runnable, for example with
`--feature-output features.v2.jsonl --feature-schema flow_features.v2`.

## 7. Failure isolation

If ML is disabled, unavailable, slow, malformed, crashed, unable to load its
artifacts, unable to score, or unable to reach the Control Plane, only ML
results are lost. The C++ engine continues packet capture, flow tracking,
feature generation accounting, and deterministic detector evaluation. The
Python worker records payload-free counters for rejected records, inference
failures, queue overflow, ledger failures, output failures, and delivery
failures.

The worker never blocks the C++ engine: it consumes a local file rather than a
synchronous pipe. A worker shutdown has a finite drain deadline. A malformed
or incomplete JSONL line is not passed to inference; in follow mode, a final
partial line is held until a newline or discarded during finite shutdown.

## 8. Event semantics

An anomaly is emitted as a separate `SecurityEvent` v1 payload:

```text
event_type=ML_ANOMALY
details.detection_source=ML, details.detector=isolation_forest_v2
severity=MEDIUM
```

The existing v1 event contract requires `source_address` and
`destination_address`; the worker copies those required addresses from the
validated native record. No ports, labels, training data, or native feature
vector is added. `PORT_SCAN` and `SYN_FLOOD` remain separate deterministic
event types. The agent adapter preserves `ML_ANOMALY` and validates its ML
provenance without collapsing it into a deterministic signature.

## 9. Deduplication

The durable SQLite decision ledger keys one decision by:

```text
engine_instance_id + flow_id + detector + model_sha256
```

The reservation is atomic and occurs before event output or delivery. The
ledger is bounded and non-evicting; at capacity it refuses new ML decisions
instead of growing without limit. A stable UUID derived from that identity is
used as `event_id`, so a Control Plane retry is idempotent. This is at-most-once
ML decision recording with best-effort delivery, not an unlimited replay
queue. A duplicate HTTP 409 is accepted only after authenticated GET
verification of the same event ID and details.

## 10. Control Plane integration

The worker reuses the existing `/api/v1/events` endpoint and bearer-token
authorization. No new authentication mechanism or role is introduced. The
Control Plane validates and persists `ML_ANOMALY` using the existing
`SecurityEventCreate`, repository, audit, and `security_events` table paths.

Existing incident management is unchanged. An analyst may link an ML event to
an incident using the existing incident endpoint; an agent cannot create an
incident merely because the event came from ML. ML does not trigger response
actions or automatic remediation.

## 11. Performance

Inference is intentionally not in the C++ packet benchmark. Measure the
separate worker with a representative native-v2 JSONL fixture and report:

- model load time (`MLDetector.load_seconds`);
- single-record latency and records/second;
- bounded queue overflow count;
- worker process RSS from the operating system;
- delivery latency separately from model latency.

The current integration has no batch inference path. The worker queue is
bounded by `--queue-capacity` (default 256), uses drop-newest overflow, and
never backpressures deterministic evidence. It does not claim production
throughput or memory characteristics from the small controlled experiment.

One local measurement on 2026-10-06 used the existing 26-record native-v2
JSONL artifact, with no Control Plane transport: model load was 0.055 s,
single-record inference median was 19.6 ms (p95 19.9 ms), the repeated
single-record scorer rate was 49.6 records/s, and the one-pass worker rate was
51.1 records/s. The process peak RSS was 229,711,872 bytes (approximately
219 MiB). This is an environment-specific integration measurement, not a
capacity target or production benchmark.

## 12. Testing

Focused inference tests cover artifact and threshold hashes, schema/order,
contract binding, model parameters, typed-record revalidation, missing/extra
fields, non-finite and negative values, score parity, inclusive thresholding,
serialization, disabled configuration, and failure states.

Worker tests cover bounded parsing, malformed/oversized/partial records,
bounded queue overflow, inference exceptions, durable duplicate decisions,
ledger capacity, disabled no-op behavior, and finite slow-delivery shutdown.
Transport tests cover bearer auth, strict 201 verification, request errors,
retry bounds, redirects, arbitrary 409 rejection, and authenticated duplicate
verification.

The native replay integration consumes existing enrolled native-v2 records and
existing controlled-lab PCAP files when available. It does not acquire data or
regenerate the controlled corpus. Control Plane tests verify authenticated
persistence, read-back, duplicate handling, deterministic/ML coexistence, and
the existing analyst-only incident link gate.

## 13. Verification commands and results

The checks used for this integration are:

```bash
PYTHONPATH=ml/src:engine/tests/fixtures \
control-plane/.venv/bin/python -m pytest -q ml/tests -c ml/pyproject.toml

PYTHONPATH=agents/src control-plane/.venv/bin/python -m pytest -q agents/tests
control-plane/.venv/bin/python -m pytest -q control-plane/tests

cmake -S . -B build/runtime-release-ml-integration \
  -DCMAKE_BUILD_TYPE=Release -DINTRIQO_BUILD_TESTS=ON
cmake --build build/runtime-release-ml-integration --parallel 2
ctest --test-dir build/runtime-release-ml-integration --output-on-failure

control-plane/.venv/bin/ruff check <new-and-modified-python-files>
PYTHONPATH=ml/src control-plane/.venv/bin/python -m mypy --strict <new-ml-source-files>
git diff --check
```

At the time of writing, the ML suite passes `610 passed, 1 skipped`, agents
pass `87 passed, 6 subtests passed`, Control Plane passes `134 passed`, and the
C++ Release suite passes `156/156`. The controlled-v2 end-to-end test is
environment-gated when PostgreSQL, the existing PCAP, or the build is absent.
The repository's full strict mypy run still contains pre-existing errors; the
new ML source and modified agent source have no strict mypy errors.

## 14. Operational limitations

The current Isolation Forest v2 model was trained and evaluated only on the
controlled 26-flow corpus: six benign training flows, ten validation flows,
and ten test flows. The experiment is tiny and controlled. Its test result is
descriptive only; it is not a production benchmark.

Therefore this integration is experimental, not production-ready, has no
external-generalization evidence, and uses a threshold that is not calibrated
for real-world traffic. ML remains disabled by default. Future model,
threshold, schema, or artifact changes must be a new experiment/integration
version; the locked run must not be mutated.

No external dataset, public PCAP, external target, network acquisition, or raw
PCAP copy in Git is used by the integration.
