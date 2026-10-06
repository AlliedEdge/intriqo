# Intriqo Isolation Forest v2 Controlled-Corpus Experiment

**Status: `V2_MODEL_EVALUATED`**

This document records a separate feasibility experiment. It does not alter the
controlled corpus, the v1 model, the production engine, deterministic
detectors, or `SecurityEvent` v1.

## 1. Objective

Measure whether the frozen native Intriqo v2 representation produces an
anomaly-ranking signal for independently labelled traffic in the completed
controlled corpus. The experiment is not a production-readiness or external
generalization study.

## 2. Corpus provenance

Only the enrolled artifacts under
`ml/artifacts/feature-analysis/controlled-v2/` and the completed run
`run-complete-20261006/` were used. The authoritative labels came from
`completed_experiment_manifest.json`; they were not derived from model scores,
detectors, or `SecurityEvent` output.

The pre-training quality gate was verified before fitting:

| Gate | Verified value |
|---|---:|
| Corpus status | `READY_FOR_V2_MODEL_TRAINING` |
| Enrolled captures | 12 |
| Enrolled native flows | 26 |
| BENIGN / ATTACK | 8 / 18 |
| Alignment | 26/26 `EXACT` |
| `PARTIAL` / `AMBIGUOUS` / `UNKNOWN` | 0 / 0 / 0 |
| Packets replayed | 525 |
| Rejected / dropped / unsupported / truncated | 0 / 0 / 0 / 0 |
| Finite nine-feature rows | 26/26 |
| Capture-level leakage checks | PASS |

The original PCAPs remain outside Git under
`/tmp/opencode/intriqo-controlled-v2/raw/`. This experiment consumed the
derived feature corpus and provenance receipts; it did not copy or reacquire
PCAPs.

## 3. Why the corpus is controlled

The corpus was captured in the already completed disconnected lab using the
fixed private topology (`10.77.0.10`, `10.77.0.20`, `10.77.0.0/24`) and explicit
bidirectional TAP visibility. It contains authorized traffic only. It is useful
for validating the feature-to-model pipeline and lock/evaluation controls, but
it is intentionally too small and too narrow to represent general network
traffic.

No CIC-IDS2017, CSE-CIC-IDS2018, IoT-23, public PCAP, external target, or other
external dataset was used.

## 4. Frozen native v2 features

The authoritative `contracts/features/flow_features_v2.json` contract was
loaded and checked. The model input is exactly these nine features, in this
order:

1. `duration_seconds`
2. `packet_count`
3. `packets_per_second`
4. `minor_direction_packet_fraction`
5. `mean_ipv4_packet_bytes`
6. `ipv4_direction_byte_imbalance`
7. `syn_packet_fraction`
8. `fin_packet_fraction`
9. `flow_iat_std_seconds`

No address, port, protocol, timestamp, ID, label, attack family, or derived
feature was included. Source values were checked as finite/non-negative
`float64` and converted only at the sklearn boundary to `float32`.

The persisted model schema is
`ml/artifacts/models/controlled-v2/isolation-forest-v2/feature_schema.json`.

## 5. Train / validation / test design

The enrolled capture-level split was honoured exactly; no random row split was
created:

| Split | Flows | BENIGN | ATTACK | Use |
|---|---:|---:|---:|---|
| `train_normal` | 6 | 6 | 0 | Fit only |
| `validation` | 10 | 1 | 9 | Threshold selection and diagnostics |
| `test` | 10 | 1 | 9 | One locked evaluation |

The test split was not used for fitting, preprocessing, threshold selection,
or model selection. The output contains an explicit
`experiment_lock.json`; test scoring was permitted only after its hashes
verified.

## 6. Isolation Forest configuration

The existing sklearn-based Intriqo Isolation Forest scoring convention was
reused: anomaly score is `-model.score_samples(features)`, with higher values
more anomalous.

```text
n_estimators: 300
max_samples: auto
contamination: auto
random_state: 42
n_jobs: -1
bootstrap: false
max_features: 1.0
warm_start: false
preprocessing: NONE
```

Runtime metadata records Python 3.14.4, NumPy 2.5.3, scikit-learn 1.9.1,
platform, training duration, peak RSS, model size, source hashes, and feature
contract hash.

## 7. Threshold selection

Every unique validation score plus a no-alert threshold was evaluated in
`validation_threshold_candidates.csv`. Each candidate records TP, TN, FP, FN,
precision, recall/TPR, FPR, specificity, F1, and balanced accuracy.

The fixed selection rule was:

1. choose zero validation false positives if any such threshold detects an
   attack;
2. maximize validation recall;
3. break ties with the highest threshold;
4. if zero-FP thresholds detect no attacks, use maximum F1, then lower FPR,
   then higher threshold.

The selected locked threshold was **0.5153855054112947**, with inclusive
comparison `score >= threshold`.

## 8. Validation results

The locked validation result was:

| Metric | Value |
|---|---:|
| TP / TN / FP / FN | 9 / 1 / 0 / 0 |
| Precision | 1.000 |
| Recall / TPR | 1.000 |
| FPR | 0.000 |
| Specificity | 1.000 |
| F1 | 1.000 |
| Balanced accuracy | 1.000 |
| PR-AUC | 1.000 |
| ROC-AUC | 1.000 |

There was only one benign validation flow. Therefore the zero FPR value is a
descriptive result, not a precise estimate of a 1% operating point.

## 9. Locked experiment receipt

`experiment_lock.json` records the model, threshold, feature schema, training
manifest, validation manifest, split-definition, and source dataset hashes. It
states `test_data_accessed: false` at lock creation. The locked hashes include:

```text
model.joblib       69d7df6a027eebcaa64c227c3ab34d8a9fd44d4a0158264e86c3fb93db960cb5
threshold.json     28ebd68f65e255e9c32aa433b609c4dc969402605d936b8d49c357c5979058b2
feature_schema.json 12f4e2f60efa9d8b1324598c5a9ca398ea6940374ed1a93d0d0a0f570a829521
```

The model artifact is 409,037 bytes. The final
`artifact_manifest.json` records hashes for all experiment artifacts and the
source corpus receipts.

## 10. Test results

The test set was evaluated once after lock verification:

| Metric | Value |
|---|---:|
| TP / TN / FP / FN | 9 / 1 / 0 / 0 |
| Precision | 1.000 |
| Recall / TPR | 1.000 |
| FPR | 0.000 |
| Specificity | 1.000 |
| F1 | 1.000 |
| Balanced accuracy | 1.000 |
| PR-AUC | 1.000 |
| ROC-AUC | 1.000 |

This means **9 attack flows detected and 1 benign flow not alerted in this
10-flow controlled test split**. It does not mean 100% detection capability.

## 11. Per-scenario results

Ground truth is controller-owned. Each test scenario has one native flow, so
the rows below are descriptive only:

| Scenario | Capture | Ground truth | Family | Score | Prediction | Correct |
|---|---|---|---|---:|---|---|
| `test-benign-mixed` | `cap-test-benign-mixed-64af578ae077` | BENIGN | — | 0.470230 | BENIGN | yes |
| `test-syn-flood` | `cap-test-syn-flood-0ac956bce637` | ATTACK | SYN_FLOOD | 0.537703 | ATTACK | yes |
| `test-port-scan-flow-001` through `007` | `cap-test-port-scan-e229ac0b5a61` | ATTACK | PORT_SCAN | 0.516266 | ATTACK | yes |
| `test-port-scan-flow-008` | `cap-test-port-scan-e229ac0b5a61` | ATTACK | PORT_SCAN | 0.515386 | ATTACK | yes |

BENIGN summary: 1 total, 0 detected as anomalous, FPR 0/1. ATTACK summary:
9 total, 9 detected, 0 missed, recall 9/9. The closest operating margin was
`test-port-scan-flow-008`, whose score was equal to the inclusive threshold;
it was correctly detected but is the least separated scenario by score margin.

The complete per-flow table is
`test_predictions.jsonl`; the complete scenario table is
`test_scenario_metrics.json`.

## 12. Per-attack-family results

| Attack family | Total | Detected | Missed | Recall | Note |
|---|---:|---:|---:|---:|---|
| `PORT_SCAN` | 8 | 8 | 0 | 1.000 | One capture episode expanded to eight flows |
| `SYN_FLOOD` | 1 | 1 | 0 | 1.000 | Single test flow; descriptive only |

The machine-readable result is `test_attack_family_metrics.json`.

## 13. v1 comparison

The frozen v1 artifacts use three features and a different prepared-dataset
protocol. This experiment uses nine native v2 features, a different controlled
corpus, and a different input/provenance contract. Retraining v1 was
forbidden, and running the v1 model on this v2 corpus would not preserve the
historical semantics. Therefore:

> Direct v1-v2 performance comparison is not valid for this corpus.

No v1 artifact or threshold was modified.

## 14. Limitations and small-sample honesty

- Training contains only 6 flows, all BENIGN.
- Validation contains 10 flows, including only 1 BENIGN flow.
- Test contains 10 flows, including only 1 BENIGN flow.
- Several test flows are expansions of one port-scan episode; row counts are
  not fully independent sample counts.
- Metrics have extremely high variance at this sample size.
- The result is a controlled feasibility experiment, not production detection
  performance.
- It does not establish external generalization or robustness against unseen
  network environments.
- It does not justify deploying the model as a production detector.

## 15. Reproducibility

The implementation is
`ml/src/intriqo_ml/models/isolation_forest_v2.py`. From the repository root,
the two-phase workflow is:

```bash
PYTHONPATH=ml/src python -m intriqo_ml.models.isolation_forest_v2 \
  --run-dir ml/artifacts/feature-analysis/controlled-v2/run-complete-20261006 \
  --enrolled-dir ml/artifacts/feature-analysis/controlled-v2 \
  --output-dir ml/artifacts/models/controlled-v2/isolation-forest-v2 \
  --fit

PYTHONPATH=ml/src python -m intriqo_ml.models.isolation_forest_v2 \
  --run-dir ml/artifacts/feature-analysis/controlled-v2/run-complete-20261006 \
  --enrolled-dir ml/artifacts/feature-analysis/controlled-v2 \
  --output-dir ml/artifacts/models/controlled-v2/isolation-forest-v2 \
  --evaluate
```

The output directory refuses to replace a locked run or repeat test
evaluation. A new experiment version is required for any changed choice.

## 16. Security and ethical scope

All attack traffic was already generated inside the disconnected controlled
lab. No external system was scanned or targeted. This artifact is an internal
research receipt and must not be used as evidence of real-world attack
detection accuracy.

## 17. Final conclusion

**Pipeline validation:** passed. The frozen nine-feature input, benign-only fit,
validation-only threshold selection, explicit lock, one-time test evaluation,
independent labels, per-scenario/family aggregation, and artifact hashing all
completed reproducibly.

**Model performance:** v2 shows a **measurable signal** on this controlled
corpus: the locked threshold separated 9/9 validation attacks from 1/1 benign
and 9/9 test attacks from 1/1 benign. The tiny denominators and repeated
controlled scenario structure make that signal highly uncertain.

**Production readiness:** not established. The result does not demonstrate
production-grade anomaly detection, generalized network detection, external
dataset performance, or deployment suitability.
