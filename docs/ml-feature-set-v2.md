# Native Feature Set v2

## Status and stop point

**Native v2 contract and controlled PCAP prototype are implemented and verified. Real CIC-IDS2017 reconstruction, v2 model fitting, and validation comparison are blocked on capture availability and verified native-flow labels. No v2 model was trained. The held-out test set was not opened or evaluated.**

V1's wire model, schema, serializer, parser, fixtures, prepared data, baseline implementation, checkpoint, threshold, validation results, and documentation remain frozen. The new opt-in stream is `flow_features.v2`; v1 is still the default. No ML inference or new fields were added to SecurityEvent. Packet acceptance, canonical flow direction, FIN/RST behavior, and deterministic detectors are unchanged.

This phase implements the user's **population** IAT standard deviation requirement. The investigation's earlier sample-standard-deviation proposal and CICFlowMeter sample statistics are not substituted into this contract.

## Exact nine-dimensional feature vector

Feature order is fixed by `intriqo_ml.flow_features_v2.FEATURES_V2`:

| Feature | Formula | Unit / range |
| --- | --- | --- |
| `duration_seconds` | Existing native `last_seen - first_seen` | seconds, ≥0 |
| `packet_count` | Number of accepted packets in this native flow | integer packets |
| `packets_per_second` | n/d if d>0, otherwise 0 | packets/second, ≥0 |
| `minor_direction_packet_fraction` | min(n_f,n_r)/(n_f+n_r), otherwise 0 | dimensionless [0,0.5] |
| `mean_ipv4_packet_bytes` | b/n if n>0, otherwise 0 | IPv4 bytes/packet, ≥0 |
| `ipv4_direction_byte_imbalance` | abs(b_f-b_r)/(b_f+b_r), otherwise 0 | dimensionless [0,1] |
| `syn_packet_fraction` | SYN-bearing accepted TCP packets / n, otherwise 0 | dimensionless [0,1] |
| `fin_packet_fraction` | FIN-bearing accepted TCP packets / n, otherwise 0 | dimensionless [0,1] |
| `flow_iat_std_seconds` | Population std of consecutive valid native capture-time gaps | seconds, ≥0 |

Here `n=n_f+n_r`, `b=b_f+b_r`, and d is native duration. Direction fractions are invariant to exchanging the entire forward/reverse pair. Byte subtraction is done on ordered unsigned counters before conversion, avoiding unsigned underflow. The first eight features are native copies or projections of already supported packet/flow measurements.

`packet_count` is uint64 on the wire; the eight continuous features are finite nonnegative doubles, with explicit ratio bounds. Python validates strict integer JSON tokens for counters and finite real values for continuous measurements. Projection to float64 matrices rejects packet counts above 2^53 rather than silently losing integer precision. No metadata, IPs, ports, labels, attack names, or raw measurement-evidence fields enter the nine-dimensional matrix.

## Packet, byte, TCP, and lifecycle accounting

- **Timestamp source:** capture header time. Classic PCAP replay recognizes microsecond and nanosecond magic values, validates the subsecond fraction, and converts to `Clock::duration` ticks. The tested Linux x86-64 clock has nanosecond ticks. A microsecond PCAP supplies microsecond precision; no submicrosecond information is invented. JSON timestamps retain the existing canonical nine fractional digits and UTC convention.
- **Packet acceptance/accounting:** unchanged IPv4 parser and flow tracker. Only accepted parsed packets increment counters. The parser requires the complete declared IPv4 total length, validates relevant L4 header lengths, and classifies unsupported/truncated inputs through existing metrics. There is no capture-loss reconstruction, deduplication, retransmission removal, or payload-based relabelling.
- **Bytes:** sum the IPv4 total-length header field across accepted packets. Ethernet/L2 headers and Ethernet padding are excluded; IPv4 and transport headers are included. This is not TCP/UDP application payload and not the CICFlowMeter byte vocabulary.
- **Direction:** creation packet's observed five-tuple is canonical forward. Reverse-tuple matches accumulate reverse counters. No client/server, attacker/victim, or handshake-based reorientation is performed.
- **TCP bits:** SYN+ACK **does count** as SYN-bearing. Every accepted TCP packet with FIN set counts as FIN-bearing, including FIN+ACK. The denominator includes all packets in the flow, not just TCP control packets. UDP/ICMP/OTHER flows have zero TCP fractions. Existing masked ACK/initial-SYN/handshake evidence remains available only as native audit evidence, with its original definitions.
- **Flow expiration:** unchanged configured idle budget, capacity eviction, and shutdown flush. FIN/RST do not retire flows. Native `last_seen` remains the maximum accepted timestamp; first_seen remains the creation packet's timestamp. Export metadata timestamp is last_seen, not wall-clock export time.
- **Replay ordering:** process records in file order, without sorting or timestamp repair. A globally earlier timestamp belonging to a different flow is not automatically an invalid per-flow gap. A decreasing timestamp within an existing flow invalidates that flow's v2 timing/export.

## Additive IAT measurement contract

Policy identifier: `capture_order_nondecreasing_population.v1`.

For one flow, let t_0…t_(n-1) be its accepted capture timestamps in **observed/file order**, required to be nondecreasing. Equal timestamps are valid. The first packet creates no sample. Define:

```
g_i = t_i - t_(i-1), i = 1…n-1
m = max(n-1, 0)
mean_g = sum(g_i) / m
population_variance = sum((g_i - mean_g)^2) / m
flow_iat_std_seconds = sqrt(population_variance), expressed in seconds
```

For no gaps or a single gap, the standard deviation is **0**. Thus one-packet and two-packet flows both have std 0; multiple equal timestamps also yield 0. The divisor is m, never m-1.

`FlowIAT` adds only constant-size state per flow: enable/valid flags, previous observed timestamp, gap count, and Welford mean/M2 accumulators. It is opt-in when a v2 pipeline is selected. No packet timestamp list or second flow tracker was introduced. Integral clock ticks are widened **before** subtraction so epoch magnitude does not swallow nanosecond gaps or overflow signed subtraction. Moments remain in clock-tick units as long doubles; conversion to seconds and double occurs at extraction.

On a decreasing timestamp, mark the entire timing measurement invalid. Continue existing native packet/byte/flag accounting, preserve v1 last_seen and detector behavior, and refuse v2 extraction for that flow. Do not sort, take absolute gaps, drop only the negative sample, clip it, or fabricate std 0. The pipeline reports `feature_generation_failures`; the controlled dataset prototype rejects any such replay rather than silently training on a selectively incomplete stream. Invalid PCAP timestamp fractions fail at the existing capture boundary.

Missing timing instrumentation, invalid/negative/nonfinite moments, inconsistent gap counts, or nonfinite output cannot be serialized as a valid v2 record. Finite nonnegative std must be zero with fewer than two gaps and cannot exceed native lifespan. Validators do not pretend to independently reconstruct gap variance from only count and duration.

Welford update order and `max_digits10` output are deterministic for the same capture, clock precision, compiler/floating ABI, and configuration. Bit-for-bit identity across different floating ABIs is not claimed; the boundary checks use `rtol=1e-12, atol=1e-15`, with tighter fixture tolerances where appropriate. The large-epoch nanosecond test verifies precision on the supported build.

## Versioned C++ → Python stream

New implementation files:

- `engine/include/intriqo/flow/iat.hpp`, `engine/src/flow/iat.cpp`.
- `engine/include/intriqo/features/flow_feature_record_v2.hpp`, `engine/src/features/flow_feature_record_v2.cpp`.
- `ml/src/intriqo_ml/flow_features_v2.py`.
- `contracts/features/flow_features_v2.json`, generated from the explicit Python models.

Small additive hooks in FlowTable, PipelineImpl, the existing bounded file sink, CLI, and CMake select v2. The file sink fixes its record version on creation and rejects cross-version submissions; the existing asynchronous worker, queue/loss accounting, private local-file policy, and shutdown drain are reused. Stream failure does not affect deterministic detector processing.

Wire envelope:

```json
{
  "schema_version": "flow_features.v2",
  "metadata": "existing native metadata shape",
  "measurements": "existing native counters/rates/handshake evidence",
  "timing": {"policy": "capture_order_nondecreasing_population.v1", "gap_count": 2},
  "features": "the nine explicit model fields"
}
```

The strings above illustrate the envelope shape, not a valid sample record. `measurements` preserves native audit evidence; it is not an extra model feature set. Native counters/rates/size means and the projected formulas are checked, along with timestamp duration, protocol/handshake invariants, finite values, and timing population bounds.

The new `FlowFeatureRecordV2` and `parse_flow_feature_record_v2` are imported explicitly from `intriqo_ml.flow_features_v2`. The old parser stays v1-only and rejects v2. The v2 parser rejects v1/unsupported versions, extra fields, duplicate keys, nonfinite numbers, invalid integer tokens, malformed dates, and invalid native evidence. It reuses existing strict bounded transport guards: 8192 bytes and 16 nested containers. It never normalizes accepted numeric values or routes v2 through a modified v1 parser.

Opt-in engine example:

```sh
build/flow-release/engine/intriqo-engine --pcap CONTROLLED.pcap \
  --feature-schema flow_features.v2 --feature-output NEW-v2.jsonl \
  --output NEW-events.jsonl
```

Feature files append under the existing sink contract. Use a fresh destination per reconstruction run and do not point it at v1 artifacts. Omitting `--feature-schema` preserves v1 output. Unsupported versions, or a schema flag without a feature destination, are CLI errors.

## Controlled native dataset prototype

`ml/src/intriqo_ml/datasets/native_pcap_v2.py` is a separate gated preparation entry point. The existing CIC CSV/Parquet preparation module and its duplicate/rejection policy are unchanged.

The prototype accepts one classic `.pcap` of at most 1 MiB, replays through the real C++ engine, validates every v2 JSONL record, and writes a nine-column `features.csv`, evaluation/provenance `metadata.csv`, original native JSONL, and hashed `dataset_manifest.json`. It uses a one-second idle budget specifically to exercise retirement in the small fixture; capacity is 100000. This is **not** a replacement real-data training/preparation configuration.

All emitted fixture flows are retained without deduplication, repair, or new labels. Labels are `UNLABELLED`; `training_ready=false` and `official_cic_flow_alignment_established=false` are explicit. The manifest includes feature order, IAT policy, engine/PCAP hashes, configuration, artifact hashes, and the label gate. The original three-feature fit CLI does not accept this different manifest/feature contract. No nine-feature trainer or automatic label association was improvised.

The prototype refuses pre-existing output directories, unsupported inputs, oversized captures, obvious held-out paths before opening them, generation/write/validation loss, rejected/truncated packets, empty output, and stream/count mismatches. It has no test-split or label-inference API.

Actual proof artifact: `ml/artifacts/feature-analysis/v2/verified-prototype/`. It contains **five native flow rows from 13 controlled packets**, generated with the unchanged existing flow-feature PCAP fixture. The v2 boundary test checks all nine numerical fields for every flow, including IPv4 UDP bytes, asymmetric directions, SYN+ACK/FIN, nanosecond timing, idle retirement, and EOF flush.

Reproduce into a fresh directory:

```sh
control-plane/.venv/bin/python engine/tests/fixtures/flow_feature_fixture.py \
  /tmp/opencode/native-v2-controlled.pcap
PYTHONPATH=ml/src control-plane/.venv/bin/python \
  -m intriqo_ml.datasets.native_pcap_v2 \
  --pcap /tmp/opencode/native-v2-controlled.pcap \
  --engine build/flow-release/engine/intriqo-engine \
  --output-dir ml/artifacts/feature-analysis/v2/NEW-prototype
```

The source PCAP is synthetic and is not presented as CIC-IDS2017 evidence. Earlier scratch prototype receipts remain separate from the final verified receipt.

## Real CIC-IDS2017 reconstruction and label gates

Local inventory under `/run/media/rayan/Workspace/08_Datasets` found Monday/Tuesday **Parquet**, not the raw PCAPs. No real capture was processed. The [official dataset page](https://www.unb.ca/cic/datasets/ids-2017.html) confirms roughly 11 GB each for Monday and Tuesday and links to [the download surface](http://cicresearch.ca/CICDataset/CIC-IDS-2017/), which currently displays a registration form/server-error message. No personal information was fabricated or submitted and no complete collection was downloaded.

The official Monday BENIGN context and Tuesday FTP/SSH attack schedules are potential **label metadata**, not model inputs. Native labelling still requires verified capture timezone, NAT-visible endpoint interpretation, protocol/service context, and a policy for native flows overlapping attack windows or spanning multiple labels. Day/time alone must not turn every contemporaneous flow into an attack. Header identifiers may support reviewed label association but must never enter the feature matrix.

Intriqo idle/capacity/shutdown boundaries differ from CICFlowMeter FIN/duration segmentation. Official CSV flow labels do not automatically label a differently segmented native flow. If exact association cannot be established, explicitly version an Intriqo-derived CIC representation, retain ambiguous/unmatched provenance, and stop fitting until the evaluation-label policy is resolved. Packet loss, partial capture, truncation, parser scope, and v2 invalid-timing exclusions must be audited rather than repaired with legacy summaries.

The original CICFlowMeter byte, packet-size, TCP, and timing columns are **not** accepted substitutes. In particular CIC IAT sample std is not the newly specified native population statistic. The held-out Wednesday source/features/labels remain sealed.

## Gated training and validation procedure

No v2 fitting or scores exist. `ml/artifacts/models/cicids2017/isolation-forest-v2/experiment_status.json` records this gate, not a model or threshold.

After authentic native Monday/Tuesday data and trustworthy labels exist, retain the explicit capture-day split: Monday BENIGN training only, Tuesday validation only. Initial preprocessing is none. Reuse the existing Isolation Forest algorithm/configuration: `n_estimators=300`, `max_samples="auto"`, `contamination="auto"`, `random_state=42`, `n_jobs=-1`; do not introduce another model.

Threshold selection remains validation unique scores plus no-alert, `score=-score_samples`, decision `score>=threshold`, primary FPR cap 1%; ties prefer recall, F1, lower FPR, then higher threshold. Reuse the original fallback policy. Do not modify the v1 locked threshold or use any held-out data.

Report validation ROC-AUC, PR-AUC/AP, recall at 0.5%, 1%, 2%, and 5% FPR caps, actual FPR, precision, F1, balanced accuracy, and FTP/SSH family recall under shared thresholds. Success requires material low-FPR recall improvement with reasonable false positives; ROC-AUC alone is insufficient.

For an honest **representation-only** comparison, the three- and nine-dimensional inputs must refer to the same native flows, label associations, split membership, observation coverage, and row policy. A native-PCAP v2 cohort cannot simply be compared causally with differently segmented official-CIC v1 rows and declared to change only representation. Establish that comparison policy before fitting; preserve the frozen historical baseline rather than retraining or overwriting it to hide cohort changes.

| Historical frozen v1 measurement | Value |
| --- | ---: |
| ROC-AUC | 0.7648450670096443 |
| PR-AUC | 0.04709945026378298 |
| Locked threshold | 0.7407202799602526 |
| Recall at ≤1% FPR | 0.021858% |

V2 validation metrics and family recall are **unavailable**, not zero or improvements. The prototype is unlabelled and must not be used to manufacture them.

## Regression evidence

- CMake Release build passed with native live/PCAP support. The initial missing-header build failure was a stale cached `/tmp/opencode/intriqo-pcap-dev/usr/include` path. Matching `libpcap0.8-dev` 1.10.6 headers were downloaded/extracted locally to restore that path; no system install or source workaround was applied.
- **154 C++ tests passed**, including 13 v2 tests and all existing suites. V2-enabled and disabled pipelines produce identical deterministic SecurityEvent evidence (apart from independent event UUIDs), and late-timestamp v1 serialization is identical with timing disabled/enabled.
- **573 ML tests passed, 1 existing real-data opt-in test skipped.** All 59 v2 wire tests and 6 real-process v2 integration/prototype cases passed. The real-data smoke test remained disabled because its full preparation would touch the held-out set.
- **7 existing E2E tests passed, 6 existing opt-in live-capture cases skipped** under their normal capability/opt-in gate. No xfails were introduced.
- **131 Control Plane tests passed.** **81 Agent tests and 4 Agent subtests passed.** Neither system's production code was changed.
- Strict mypy passed for all 13 ML source files; Ruff passed for ML source/tests; `git diff --check` passed.
- Before/after SHA-256 checks cover 24 frozen v1 files, including all original external fit/diagnostic artifacts, serializer/schema/parser, preparation/mapping, model implementation, fixtures, and baseline documentation. No held-out data were opened for hashing.
- `/tmp/opencode/native-v2-ml-open.trace` and `/tmp/opencode/native-v2-prototype-verified-open.trace` record the real test/prototype file accesses; no real held-out dataset access occurred. Full receipts are retained in `ml/artifacts/feature-analysis/v2/native_v2_implementation_status.json`.

Commands used:

```sh
cmake --build build/flow-release --parallel 4
ctest --test-dir build/flow-release --output-on-failure --quiet \
  --output-junit /tmp/opencode/native-v2-cpp-tests.xml
INTRIQO_RUN_REAL_CICIDS2017=0 control-plane/.venv/bin/python -m pytest -q \
  ml/tests -c ml/pyproject.toml --strict-markers
control-plane/.venv/bin/python -m mypy ml/src/intriqo_ml --strict --python-version 3.10
control-plane/.venv/bin/python -m ruff check --config ml/pyproject.toml ml/src ml/tests
PYTHONPATH=ml/src:engine/tests/fixtures:agents/src \
  INTRIQO_ENGINE_BINARY="$PWD/build/flow-release/engine/intriqo-engine" \
  INTRIQO_ENGINE_DEMO="$PWD/build/flow-release/engine/intriqo_port_scan_demo" \
  APP_ENV=test REQUIRE_EMAIL_VERIFICATION=false \
  control-plane/.venv/bin/python -m pytest -q tests/e2e
control-plane/.venv/bin/python -m pytest -q agents/tests -c agents/pyproject.toml
git diff --check
```

Control Plane tests were run as `.venv/bin/python -m pytest -q tests -c pyproject.toml` from `control-plane/`, using its existing local development PostgreSQL fixtures. JUnit receipts are `/tmp/opencode/native-v2-{cpp,ml,e2e,control,agent}-tests.xml`.

**Stop:** native contract and controlled stream/dataset artifact verified; real labelled CIC reconstruction and v2 validation experiment remain blocked. No v1 contract/artifact/result changes, CICFlowMeter substitutions, ML/SecurityEvent integration, or held-out evaluation were performed.
