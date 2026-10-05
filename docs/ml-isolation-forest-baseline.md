# Isolation Forest baseline

## Objective and boundaries

This is Intriqo's **first standalone diagnostic baseline**, not production-grade
intrusion detection. It has no serving, SecurityEvent integration, hybrid fusion,
or C++ engine changes. It consumes the existing prepared CIC-IDS2017 artifacts
read-only; no preparation, duplicate, rejection, or split policy is changed.

The model uses only three flow-level features. It cannot identify attacks whose
distinguishing characteristics are absent from those features, and cannot assign
different scores to identical vectors with benign/attack labels.

## Dataset and representation

Prepared input directory:

```text
/run/media/rayan/Workspace/08_Datasets/cicids2017/prepared/intriqo-cicids2017-monday-wednesday
```

| Split | Capture | Composition |
|---|---|---|
| train_normal | Monday | 502,635 BENIGN |
| validation | Tuesday | 412,460 BENIGN; 5,931 FTP-Patator; 3,219 SSH-Patator |
| test | Wednesday | 416,715 BENIGN; 172,846 DoS Hulk; 10,286 DoS GoldenEye; 5,385 DoS slowloris; 5,228 DoS Slowhttptest; 11 Heartbleed |

Feature order is enforced exactly:

1. `duration_seconds`: source `Flow Duration` in microseconds / 1,000,000.
2. `packet_count`: forward + backward packets.
3. `packets_per_second`: source `Flow Packets/s`, unchanged.

Preprocessing is **none**: no standardization, normalization, or log transform.
CSV values are validated as float64; sklearn receives float32 (its tree input
type). Maximum absolute/relative conversion error and packet-count rounding are
recorded per split. Exact-vector collision analysis uses original float64 values.

The dataset-specific duplicate policy `exact_row_within_source_file.v1` removed
131,763 repeated complete source records, including labels. Flow identifiers,
timestamps, and IP addresses are absent from this 79-column source subset, so
the repetitions cannot conclusively be attributed to repeated independent flows
versus export duplication. Removal is strongly class-dependent (SSH-Patator
45.413%, FTP-Patator 25.255%, DoS Hulk 24.890%). The audit also found 47
label-agnostic conflicting groups on Wednesday and severe feature-only
collisions. The 1,998 zero-duration/nonfinite rows and 53 negative-duration rows
were rejected during preparation, not repaired by this experiment. See
`docs/ml-dataset-pipeline.md` for the quality audit.

## Fixed model and score semantics

Implementation: `sklearn.ensemble.IsolationForest`.

```python
IsolationForest(
    n_estimators=300,
    max_samples="auto",
    contamination="auto",
    random_state=42,
    n_jobs=-1,
)
```

Other resolved defaults are recorded in `model_metadata.json` using
`model.get_params()`. No test-driven hyperparameter selection is permitted.
`max_samples="auto"` means 256 training rows per tree for this dataset, not
downsampling the dataset before fitting. All 502,635 benign rows are supplied.

**Higher score = more anomalous**:

```python
anomaly_score = -model.score_samples(features)
is_anomaly = anomaly_score >= locked_threshold
```

There is no additional offset, clipping, calibration, or score normalization.
Neither `predict()` nor sklearn's contamination-derived cutoff is used for
alerts. `contamination="auto"` stays fixed; only the operating threshold is
selected with validation labels.

## Validation-only threshold selection

The operational budget is fixed **before evaluation** at validation benign
false-positive rate <= **1%**. This is a baseline budget, not a production SLA.

1. Fit the model on BENIGN training rows only; reject a mixed training split.
2. Score validation once. Enumerate every unique score plus the next float above
   its maximum (the no-alert candidate); tied scores are indivisible groups.
3. Among candidates within the FPR budget, choose highest attack recall, then
   highest F1, then lower FPR, then higher threshold. The no-alert candidate
   ensures feasibility. No attack-family-specific thresholds are used.
4. Store the full candidate metrics in `validation_threshold_candidates.csv`,
   selected metrics in `validation_metrics.json`, and the threshold in
   `threshold.json`, bound to the fitted model SHA-256.
5. Complete `fit_manifest.json` before any test CSV is opened or hashed.

`--fit` performs training **and validation threshold locking** only. `--evaluate`
verifies the saved lock and fit-artifact hashes before loading the trusted local
joblib model, then scores test exactly once using that threshold. It does not
read validation inputs, select another threshold, or refit. Previously evaluated
output directories are refused unless explicitly replaced with `--force`.

Test metrics include confusion counts, precision/recall/F1, FPR/TPR,
specificity, balanced accuracy, Average Precision (reported as PR-AUC, not
trapezoidal PR area), ROC-AUC, and score distributions. Per-family binary
metrics compare that attack family against all test BENIGN rows, excluding other
attack families; BENIGN-only results report false alerts and specificity.
Zero denominators are defined as zero; ROC-AUC without both classes is zero.

## Validation Operating-Point Analysis

### Scope and immutable primary lock

This diagnostic concerns the external **fit-only** artifact directory:

```text
/run/media/rayan/Workspace/08_Datasets/cicids2017/prepared/intriqo-cicids2017-isolation-forest
```

The primary locked threshold remains **0.7407202799602526**. This is diagnostic
only: no retraining, model changes, feature-mapping changes, preprocessing changes,
or replacement of `threshold.json`. The held-out test feature and label CSVs remain
untouched by this external run and its diagnostic. Historical evaluation tables
elsewhere in this document concern separate artifact directories and are not
inputs to this analysis.

The existing candidate CSV does not retain row-to-family score associations.
The diagnostic therefore recovers the same validation scores with the unchanged
checkpoint, verifies **every candidate and every saved validation metric exactly**,
and only then associates those verified scores with the existing validation labels.
No training or test feature matrix is loaded by the diagnostic.

### Operating-point method

Targets **0.01%, 0.05%, 0.10%, 0.25%, 0.50%, 1.00%, 2.00%, 5.00%, and 10.00%**
are FPR caps, not interpolated points or promises to exhaust each budget. Each
point uses an actual unique validation score or the no-alert threshold. Tied
scores are indivisible. Select maximum achievable validation recall under the
cap, then highest F1, lower FPR, and higher threshold. The reported maximum
recall and corresponding threshold describe that same selected diagnostic point.
FTP-Patator and SSH-Patator recall use the **same shared threshold** at each point;
there are no family-specific cutoffs.

The following are **maximum-recall points under each cap**, with the tie-break
rules above. Low-cap points use the no-alert candidate because all feasible
points have zero recall/F1; lower FPR then wins. Values displayed below are
rounded; CSV/JSON preserve full numeric precision. Recall is also the maximum
achievable recall at that cap, and the threshold column is its corresponding
available threshold.

| FPR cap | Threshold | Actual FPR | Recall / TPR | Precision | F1 | TP | TN | FP | FN | Balanced accuracy |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.01% | 0.8092563546141611 | 0% | 0% | 0% | 0 | 0 | 412,460 | 0 | 9,150 | 0.5000000000 |
| 0.05% | 0.8092563546141611 | 0% | 0% | 0% | 0 | 0 | 412,460 | 0 | 9,150 | 0.5000000000 |
| 0.10% | 0.8092563546141611 | 0% | 0% | 0% | 0 | 0 | 412,460 | 0 | 9,150 | 0.5000000000 |
| 0.25% | 0.8092563546141611 | 0% | 0% | 0% | 0 | 0 | 412,460 | 0 | 9,150 | 0.5000000000 |
| 0.50% | 0.7407202799602526 | 0.454347% | 0.021858% | 0.106610% | 0.0003627789 | 2 | 410,586 | 1,874 | 9,148 | 0.4978375542 |
| 1.00% | 0.7407202799602526 | 0.454347% | 0.021858% | 0.106610% | 0.0003627789 | 2 | 410,586 | 1,874 | 9,148 | 0.4978375542 |
| 2.00% | 0.6877590603115109 | 1.762838% | 0.065574% | 0.082452% | 0.0007305047 | 6 | 405,189 | 7,271 | 9,144 | 0.4915136808 |
| 5.00% | 0.5938946950381243 | 4.924356% | 0.327869% | 0.147485% | 0.0020345190 | 30 | 392,149 | 20,311 | 9,120 | 0.4770175628 |
| 10.00% | 0.5408836648136991 | 9.552199% | 32.163934% | 6.950546% | 0.1143090189 | 2,943 | 373,061 | 39,399 | 6,207 | 0.6130586771 |

| FPR cap | FTP-Patator recall (5,931 rows) | SSH-Patator recall (3,219 rows) |
|---:|---:|---:|
| 0.01% | 0% (0 detected) | 0% (0 detected) |
| 0.05% | 0% (0 detected) | 0% (0 detected) |
| 0.10% | 0% (0 detected) | 0% (0 detected) |
| 0.25% | 0% (0 detected) | 0% (0 detected) |
| 0.50% | 0.033721% (2 detected) | 0% (0 detected) |
| 1.00% | 0.033721% (2 detected) | 0% (0 detected) |
| 2.00% | 0.084303% (5 detected) | 0.031066% (1 detected) |
| 5.00% | 0.118024% (7 detected) | 0.714508% (23 detected) |
| 10.00% | 0.118024% (7 detected) | 91.208450% (2,936 detected) |

The 1%-FPR primary operating point detects **2 / 9,150 attacks**: recall
**0.0218579%**, FPR **0.454347%**, precision **0.106610%**, and F1
**0.00036277888626881915**. This is extremely poor operational detection.
ROC-AUC **0.7648450670096443** indicates measurable validation ranking signal,
but does not imply acceptable detection in the low-FPR tail. Average Precision
(the reported PR-AUC summary) remains **0.04709945026378298**.

At 10% FPR cap the improved overall recall is dominated by SSH-Patator; FTP-Patator
remains almost entirely missed. Up to 5% FPR cap, maximum recall remains below
0.33%. Higher ranking AUC therefore does not demonstrate usable low-FPR detection,
and these diagnostics do not justify replacing the primary lock.

| Validation score percentile | BENIGN | Attacks |
|---|---:|---:|
| min | 0.31871026639810107 | 0.3201857291307099 |
| p1 | 0.31871026639810107 | 0.34063760288902417 |
| p5 | 0.3191069113900041 | 0.3433665003776239 |
| p25 | 0.3240612581676466 | 0.44750166199986524 |
| median | 0.34252264325430315 | 0.4545561933805137 |
| p75 | 0.41139355433596364 | 0.5548457964852024 |
| p95 | 0.5929727054041187 | 0.5630304491984522 |
| p99 | 0.7226835171215891 | 0.5680150349643579 |
| p99.9 | 0.784180650457308 | 0.6160065277888606 |
| max | 0.809256354614161 | 0.7407202799602526 |

For the inclusive alert rule, attack fraction **at or above** the primary lock is
0.0002185792349726776 (0.0218579%); BENIGN fraction is 0.0045434708820249236
(0.454347%). **Strictly above** it, attack fraction is 0 and BENIGN fraction is
0.0044125490956698835 (0.441255%): the two detected attacks sit exactly on the lock.

### Representation limitations and provenance

The existing preparation audit reports **388 mixed-label three-feature groups
affecting 86,002 valid validation source rows before exact-row deduplication**.
The diagnostic also measures collisions on the prepared validation rows, retaining
float64 values for raw-vector auditing and recording float32 model-input collisions
separately. Pre-dedup and prepared-row counts must not be conflated.

On the **421,610 prepared validation rows**, **388 mixed-label groups cover
71,607 rows**. All of those groups mix BENIGN with attack labels. **2,186 attack
rows (23.890710%)** share their exact float64 vector with BENIGN: **1,944
FTP-Patator** and **242 SSH-Patator** rows. Float32 model input has the same
388 mixed-label groups / 71,607 affected rows. Its total unique vector count is
222,406 versus 222,544 for float64; input conversion is recorded, not changed.

The three-feature representation is a **major known limitation**. Attack rows
sharing exactly the same vector as BENIGN rows produce identical model inputs and
scores. A shared threshold cannot separate those labels. This does not establish
that collisions cause all missed attacks or fully explain the low-FPR performance;
distinct feature vectors can also receive tied Isolation Forest scores.

Outputs are `validation_operating_points.csv` and `validation_operating_points.json`
in the fit-only directory. JSON includes full counts and metrics, family recall,
ranking summaries, score percentiles through p99.9, inclusive and strict-above-lock
fractions, collision scopes, and original-artifact SHA-256 snapshots. The CSV hash
is recorded in JSON. All original fit files, including `fit_manifest.json`, remain
unchanged: its fixed fitted-artifact contract does not require diagnostic additions.

Reproduce only this diagnostic:

```bash
PYTHONPATH=ml/src control-plane/.venv/bin/python \
  -m intriqo_ml.models.validation_operating_points \
  --dataset-dir /run/media/rayan/Workspace/08_Datasets/cicids2017/prepared/intriqo-cicids2017-monday-wednesday \
  --artifact-dir /run/media/rayan/Workspace/08_Datasets/cicids2017/prepared/intriqo-cicids2017-isolation-forest
```

Existing diagnostic files are refused unless `--force` explicitly replaces only
those two files; the checkpoint, lock, and original fit artifacts are never replaced.

The real diagnostic file-open trace is
`/tmp/opencode/cicids2017-validation-operating-points-open.trace`. It recorded
validation CSV opens and **no train or test CSV opens**. Independent verification
matched every original artifact hash against the pre-diagnostic fit report and
verified CSV/JSON agreement for all nine operating points.

## Observed baseline results (2026-10-05)

The validation lock is **0.7407202799602526**, selected from **38,492** candidates.
The cap is not a requirement to exhaust the full budget: tie-breaking selected a
point with validation FPR 0.454347%. Scores at a threshold are included.

| Metric | Validation | Held-out test |
|---|---:|---:|
| Samples | 421,610 | 610,471 |
| TP | 2 | 20 |
| TN | 410,586 | 414,723 |
| FP | 1,874 | 1,992 |
| FN | 9,148 | 193,736 |
| Precision | 0.0010660980810234541 | 0.009940357852882704 |
| Recall / TPR | 0.0002185792349726776 | 0.00010322260988046821 |
| F1 | 0.00036277888626881915 | 0.00020432348494135917 |
| FPR | 0.0045434708820249236 | 0.004780245491522984 |
| Specificity | 0.9954565291179751 | 0.995219754508477 |
| Balanced accuracy | 0.4978375541764739 | 0.49766148855917874 |
| PR-AUC / Average Precision | 0.04709945026378298 | 0.6209959514459962 |
| ROC-AUC | 0.7648450670096443 | 0.8390730169076064 |

**The locked operating point is ineffective for detecting most attacks.** Test
recall is only **0.0103223%**; most alerts are false positives. Ranking summaries
(AP/ROC-AUC) do not imply acceptable detection at this operating point. Neither
the threshold nor model was changed in response to these results.

### Per-label test results

Each attack family's precision/F1 below uses that family versus all 416,715 test
BENIGN rows (the same 1,992 FP / 414,723 TN); these metrics are not additive.

| Label | Support | Detected TP | Missed FN | Recall | Precision | F1 |
|---|---:|---:|---:|---:|---:|---:|
| DoS Hulk | 172,846 | 9 | 172,837 | 0.00005206947224697129 | 0.004497751124437781 | 0.00010294714807803393 |
| DoS GoldenEye | 10,286 | 0 | 10,286 | 0 | 0 | 0 |
| DoS slowloris | 5,385 | 0 | 5,385 | 0 | 0 | 0 |
| DoS Slowhttptest | 5,228 | 0 | 5,228 | 0 | 0 | 0 |
| Heartbleed | 11 | 11 | 0 | 1 | 0.0054917623564653024 | 0.01092353525322741 |

BENIGN: 414,723 correctly normal; 1,992 false alerts; FPR 0.004780245491522984;
specificity 0.995219754508477. Attack precision/recall are not meaningful for a
benign-only subset; its JSON uses the documented zero-denominator convention.
The 11 Heartbleed rows are far too few to support a generalization claim.

### Score distributions

These are normalized anomaly scores (higher = more anomalous). Full min/max,
mean, population standard deviation, p1/p5/p25/median/p75/p95/p99, and per-label
statistics are in `score_statistics.json`.

| Population | Min | Mean | Median | p95 | p99 | Max |
|---|---:|---:|---:|---:|---:|---:|
| Validation all | 0.318710266 | 0.392536052 | 0.343374257 | 0.591403388 | 0.722683517 | 0.809256355 |
| Validation BENIGN | 0.318710266 | 0.391006858 | 0.342522643 | 0.592972705 | 0.722683517 | 0.809256355 |
| Validation attacks | 0.320185729 | 0.461468403 | 0.454556193 | 0.563030449 | 0.568015035 | 0.740720280 |
| Test all | 0.318710266 | 0.431994027 | 0.374585309 | 0.577895410 | 0.708640929 | 0.809256355 |
| Test BENIGN | 0.318710266 | 0.391179956 | 0.343123007 | 0.585528152 | 0.722683517 | 0.809256355 |
| Test attacks | 0.318710266 | 0.519773687 | 0.554085172 | 0.577557110 | 0.594628645 | 0.802893629 |

### Representation limits on prepared test rows

- 610,471 rows have 401,633 distinct three-feature vectors (208,838 excess rows).
- **2,399 mixed-label groups cover 85,353 test rows**. These are post-preparation
  counts; the earlier audit's pre-dedup row counts are intentionally different.
- Of those, 2,380 groups / 85,256 rows mix BENIGN with attack labels.
- **5,116 attack rows (2.6404%) share their exact vector with BENIGN**: Hulk
  4,738; GoldenEye 40; Slowhttptest 127; slowloris 211; Heartbleed 0.

Such rows are fundamentally indistinguishable from the corresponding benign
rows under this representation, regardless of classifier. This limitation
alone does not explain all missed attacks; the locked FPR constraint, score
tails, raw feature distributions, and capture-day distribution shift also matter.
No claim is made that this model can recover missing information.

### Performance and numerical audit

First run, Linux, measured model operations (excluding CSV loading, hashing,
candidate metrics, plots, and artifact writing):

- Fit: **1.744715 s**.
- Validation scoring: **5.343755 s**.
- Test scoring: **6.641218 s**.
- Full CLI wall time: fit/lock **15.12 s**, evaluate **18.00 s**.
- Peak RSS: fit process **534,740 KiB**, evaluate process **441,124 KiB**.
- `model.joblib`: **2,155,869 bytes**.

Only one split's feature matrix is loaded at a time. Score arrays/statistics are
small and released independently. Packet counts convert to float32 exactly in
all three real splits. Maximum relative conversion error is below 5.96e-8;
maximum rate absolute errors are 0.041667 (train), 0.042 (validation), and
0.057 (test). This is sklearn input casting, not preprocessing.

## Artifacts and reproduction

Primary artifacts are local, Git-ignored:

```text
ml/artifacts/models/cicids2017/isolation-forest-baseline/
```

The identical verification experiment is at
`ml/artifacts/models/cicids2017/isolation-forest-baseline-reproduction/`.
Each contains the eight requested model/evaluation artifacts, plus
`fit_manifest.json` and `validation_threshold_candidates.csv`, and six plots:

- `validation_score_distribution.png`
- `test_score_distribution.png`
- `precision_recall_curve.png`
- `roc_curve.png`
- `confusion_matrix.png`
- `per_attack_family_recall.png`

`evaluation_manifest.json` hashes all generated files except itself (no circular
self-hash). `fit_manifest.json` binds the fitted outputs before test access;
its `score_statistics.json` hash covers the validation-only JSON projection,
since evaluation adds a test section. Evaluation's hashes cover final full files.
Timings, RSS, and UTC timestamps are observational manifest values, not part of
deterministic numeric metrics/statistics. Joblib files must be trusted local
artifacts; checksum verification is not an authenticity/signature guarantee.

Exact first-run environment:

| Component | Version |
|---|---|
| Python | 3.14.4 |
| scikit-learn | 1.9.1 |
| NumPy | 2.5.3 |
| SciPy | 1.18.1 |
| joblib | 1.6.0 |
| matplotlib | 3.11.2 |

The source supports Python >=3.10; installing current dependencies is sufficient
for a new baseline run, but does not promise equality with this recorded run.
Use the versions above and the same prepared artifact hashes for comparison.
Do not replace the repository's existing environments or global packages.

From the repository root, using an environment with `ml/pyproject.toml`
dependencies installed (the recorded run used `control-plane/.venv/bin/python`):

```bash
DATASET=/run/media/rayan/Workspace/08_Datasets/cicids2017/prepared/intriqo-cicids2017-monday-wednesday
OUTPUT=ml/artifacts/models/cicids2017/isolation-forest-baseline-new-run

PYTHONPATH=ml/src python -m intriqo_ml.models.isolation_forest \
  --dataset-dir "$DATASET" --output-dir "$OUTPUT" --fit

# This phase requires a completed, model-bound validation lock.
PYTHONPATH=ml/src python -m intriqo_ml.models.isolation_forest \
  --dataset-dir "$DATASET" --output-dir "$OUTPUT" --evaluate
```

Alternatively pass `--fit --evaluate` together for the same ordered phases.
Use fresh output directories for independent runs; `--force` is explicit
replacement, not permission to tune on test outcomes. Missing/changed inputs,
invalid feature order, nonfinite values, or a missing/mismatched lock fail
clearly. Train/validation inputs are checked against preparation SHA-256 hashes
during fit; test inputs are checked only after verifying the lock.

The model/threshold were fixed before either real test evaluation. Test was scored
once per locked experiment; the second identical experiment was solely the
requested reproducibility check, not threshold/hyperparameter selection.

Observed reproducibility:

- Both real fits produced identical model bytes, configuration, validation
  metrics, candidate CSV, and locked threshold.
- Both real evaluations produced byte-identical `test_metrics.json` and
  `score_statistics.json`, including confusion matrices, class metrics, and
  collision summaries. All final artifact hashes/sizes were verified.
- Metadata/threshold JSON differ only in UTC creation timestamps; manifests
  also contain different timings/RSS. No cross-version or cross-platform
  byte-equality guarantee is claimed for joblib serialization or plots.
- SHA-256 of `model.joblib`:
  `d5fd3fcd8913e7ccd77992de78405916cf98eda0fb34953bc228f94437860bba`.
- SHA-256 of input `dataset_manifest.json`:
  `058b30c536c2794db67cad21374921abf1137a4129297e35bc9ae27dfd61555f`.
- Git HEAD recorded: `049c21462cf82398bc45903a0be2b23ff6147eca`;
  implementation changes remain uncommitted, so HEAD alone does not identify
  the working-tree baseline code.
- Hash snapshots confirmed every prepared input/audit file remained unchanged.

## Limitations

This is a reproducible **negative operating-point result**, not a ready IDS.
The fixed low-FPR validation objective admits almost no attacks at the selected
cutoff. High ranking AUC and 11/11 Heartbleed recall must not mask that outcome.
Class prevalence differs between validation and test, so precision/AP are not
directly comparable across splits. The time-grouped split preserves chronology
but introduces benign and attack-family shift. Dataset-specific duplication,
non-identifiable repeated flows, missing features, feature collisions, and rare
classes limit validity and generalization. No synthetic production confidence
is inferred from this dataset. Further preprocessing/feature experiments would
be separate, predeclared experiments, not revisions to this locked baseline.

## Verification

Checks against the completed working tree:

- ML: **497 passed, 1 skipped** (opt-in raw-data preparation smoke).
- New baseline synthetic cases: **67 passed** within the ML total, covering
  score direction, deterministic selection and candidate confusion metrics,
  train-only fitting, validation locking, one test scoring call, artifact hashes,
  tamper/missing/nonfinite/order failures, and reproducibility.
- Strict mypy (`--strict --python-version 3.10`): no issues in 10 source files.
- Ruff: passed.
- C++ no-libpcap build and CTest: **141/141 passed**.
- Control Plane: **131 passed**; Agents: **81 passed, 4 subtests passed**.
- E2E including existing live checks: **13 passed** using existing Release binaries.
- `git diff --check`: passed.

Representative ML commands from repository root:

```bash
control-plane/.venv/bin/python -m pytest -q ml/tests -c ml/pyproject.toml
control-plane/.venv/bin/python -m mypy ml/src/intriqo_ml --strict --python-version 3.10
control-plane/.venv/bin/python -m ruff check --config ml/pyproject.toml ml/src ml/tests
```

No dataset preparation code, C++ source, event integration, or unrelated service
was changed by this baseline implementation.
