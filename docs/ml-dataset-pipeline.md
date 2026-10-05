# ML dataset preparation (no model)

## Objective

This phase prepares a leakage-safe flow-level anomaly-detection dataset. It
does not train a detector, calculate anomaly scores, choose a production
threshold, or emit ML security events. Future model input is the numeric rows in
`*_features.csv`; labels and provenance are in the separate `*_metadata.csv`
files and are never passed to preprocessing.

## Primary dataset

The primary source is **CIC-IDS2017**, using the original labelled flow files
from the Canadian Institute for Cybersecurity / University of New Brunswick:
<https://www.unb.ca/cic/datasets/ids-2017.html>. The preparation pipeline accepts
the original CSV files and Parquet files produced externally from them. Parquet
is scanned natively with PyArrow in bounded record batches; it is not converted
back to CSV. The source page describes five capture days, benign Monday traffic,
attacks on later days, CICFlowMeter-derived CSVs/PCAPs, and research-use citation
requirements. The dataset is not downloaded by this repository and no dataset
files are committed.
Users must obtain it from the official source, respect its usage terms, and
record the exact files in `dataset_manifest.json`.

### Alternatives considered

- **CSE-CIC-IDS2018**: compatible flow shape and CICFlowMeter lineage, with
  seven attack scenarios and an AWS distribution; deferred because the same
  extractor-family defects can apply and its larger multi-day layout needs a
  separate capture-group plan. Source: <https://www.unb.ca/cic/datasets/ids-2018.html>.
- **CIC-DDoS2019**: useful DDoS-focused follow-up with labelled CSV/PCAP flow
  data, but too narrow for the first general flow-anomaly baseline and also
  CICFlowMeter-derived. Source: <https://www.unb.ca/cic/datasets/ddos-2019.html>.
- **UNSW-NB15**: large, labelled flow CSV collection with nine attack types and
  a stated academic-use restriction; its Argus/Bro-derived vocabulary and
  supplied train/test partitions do not directly match Intriqo's v1 semantics.
  Source: <https://research.unsw.edu.au/projects/unsw-nb15-dataset>.
- **UGR'16**: considered as a NetFlow-oriented alternative, but its public
  access/provenance and field semantics require a separate audit before use.

These alternatives are not downloaded or included in the preparation artifact.

CIC-IDS2017 is a practical first compatibility target because it contains
labelled bidirectional flow CSVs and a benign-only day, but it is not treated as
ground truth without qualification. The documented CICFlowMeter issues include
TCP flag counts that are only 0/1 in the original CSVs, duplicated Fwd Header
Length, and flow-direction/timeout effects. See the troubleshooting notes at
<https://intrusion-detection.distrinet-research.be/WTMC2021/extended_doc.html>.

## Explicit mapping and exclusions

| Source column | Intriqo vocabulary | Transformation | Unit | Decision |
|---|---|---|---|---|
| `Flow Duration` | `duration_seconds` | divide microseconds by 1,000,000 | seconds | selected |
| `Total Fwd Packets` + `Total Backward Packets` | `packet_count` | exact integer sum | packets | selected |
| `Flow Packets/s` | `packets_per_second` | direct finite nonnegative value | packets/second | selected |
| `Total Length of Fwd/Bwd Packets` | `byte_count`, directional bytes | CICFlowMeter payload/flow-length semantics do not match Intriqo IPv4 total-length accounting | bytes | rejected |
| `Flow Bytes/s` | `bytes_per_second` | depends on rejected byte semantics | bytes/second | rejected |
| `SYN/FIN/RST Flag Count` | TCP counters | original CICFlowMeter-V3 count defect | packets | rejected |
| `Label`, attack category, IP/port identity | model feature | evaluation or identity metadata can leak scenario/answer | n/a | never selected |

The resulting initial model feature set is exactly:
`duration_seconds`, `packet_count`, `packets_per_second`. It is deliberately
small and contract-compatible. `FlowFeatureRecord` remains the source of truth;
the adapter does not fabricate missing v1 fields or rewrite the contract.
Public CSV rows are projections rather than complete `FlowFeatureRecord`
objects: the source CSV does not provide trustworthy Intriqo engine UUID/flow
IDs, nanosecond timestamps, IPv4 total-byte accounting, or ordered handshake
evidence.

## Quality and preprocessing

CSV and Parquet input are treated as untrusted data: only regular files below the
declared dataset root are accepted; archive contents are not executed; file, row,
batch and record limits are bounded. The preparation emits `quality.json` with total,
valid, invalid, duplicate, per-file, per-split, label, missing-value, rejection
reason, and bounded rejection-sample counts. Invalid rows are observable and are
not silently coerced. The duplicate policy is explicit:
`exact_row_within_source_file.v1`; a canonical fingerprint of the complete source
row rejects repeated rows within one source file. Rows are not deduplicated across
capture files.

`preprocessing: none` is the default. `standardize_train_only` fits mean and
population standard deviation on `train_normal` only, records parameters in
`preprocessing.json`, and applies those fixed parameters to validation and test.
Constant features use recorded scale 1.0. No labels or evaluation metadata
enter this transformation.

## Leakage-safe split

Splits are explicit capture groups, not row-wise random splits:

- `train_normal`: a benign capture day (the example config uses Monday)
- `validation`: a separate capture day and must contain benign plus attack rows
- `test`: a separate held-out capture day and must contain benign plus attack rows

The config records seed 42 for future group assignment compatibility, but the
current explicit-day strategy does not randomly distribute rows. A capture day
cannot be assigned to multiple splits. This prevents same-session flows from
crossing boundaries. `is_attack` and the original `label` remain metadata.

## Reproduction

```bash
PYTHONPATH=ml/src control-plane/.venv/bin/python -m intriqo_ml.datasets \
  --config ml/configs/datasets/cicids2017-dev.json \
  --dataset-root /path/to/CIC-IDS2017 \
  --output-dir ml/artifacts/cicids2017-dev
```

For the real externally prepared Parquet subset:

```bash
PYTHONPATH=ml/src control-plane/.venv/bin/python -m intriqo_ml.datasets \
  --config ml/configs/datasets/cicids2017-dev.json \
  --dataset-root /run/media/rayan/Workspace/08_Datasets/cicids2017/machine_learning \
  --output-dir /run/media/rayan/Workspace/08_Datasets/cicids2017/prepared/intriqo-cicids2017-monday-wednesday \
  --force
```

The absolute dataset root belongs on the command line, not in repository
configuration. Generated artifacts should remain outside Git or under an ignored
artifact directory. This command is the optional real-dataset smoke test; normal
CI uses tiny local Parquet fixtures.

Use `--force` only when intentionally replacing an existing artifact directory.
The output contains `train_normal_features.csv`, `validation_features.csv`,
`test_features.csv`, matching metadata files, `dataset_manifest.json`,
`quality.json`, `preprocessing.json`, and `statistics.json`. For byte-for-byte
reproduction, pin `timestamp_utc` in the config and record the same input files,
encoding, limits, and `INTRIQO_CODE_VERSION`. The manifest records source,
subset, selected files and capture groups, mapping/features, split strategy and
seed, preprocessing parameters, duplicate policy, counts, label composition,
source paths/SHA-256 provenance, finalized artifact hashes, limitations, and
`model_implementation: null`.

## CIC-IDS2017 quality audit before modeling

An independent audit of the raw Parquet inputs and prepared artifacts was run
without changing preparation policy, mapping, duplicate handling, or training.
The complete machine-readable report is `quality_audit.json` in the external
prepared-artifact directory; `quality_audit.md` is the readable report.

- The Parquet duplicate fingerprint uses the complete normalized source row: all
  79 available columns, including `Label`, plus the source filename. It is not a
  three-feature fingerprint. Mapping/validation happens first and the `seen` set
  is per source file. The available schema has a destination port but no
  timestamp, IP-address, or flow-identifier columns.
- Exact duplicate groups therefore have no conflicting labels. A separate
  label-agnostic audit found 47 same-78-column groups (739 rows) with conflicting
  labels on Wednesday only; these are not removed by the current exact-row policy.
- Exact duplicate multiplicities are highly skewed: the largest group has 3,070
  rows on Monday, 1,551 on Tuesday, and 9,329 on Wednesday. Removal changes
  validation `FTP-Patator` by 25.255% and `SSH-Patator` by 45.413%, and test
  `DoS Hulk` by 24.890%, so post-dedup counts must not be described as
  independent-flow counts.
- The three-feature audit found 852,798 unique vectors among 1,666,479 valid
  pre-dedup rows; 72,787 vector groups contain collisions and account for
  813,681 excess rows. There are 3,115 mixed-label vector groups covering
  298,613 rows globally. This is information loss from the intentionally tiny
  feature mapping, not a change to duplicate policy.
- The 2,051 non-duplicate rejections were 1,998 `impossible_duration` rows and
  53 `numeric_range` rows. Each raw nonfinite count was 1,998 for both
  `Flow Packets/s` and `Flow Bytes/s`; those same rows were rejected and none
  reached prepared features. Prepared feature files contain no null or nonfinite
  values.

Recommendation: **keep exact-row removal, but document it as a dataset-specific
preprocessing choice**. The prepared data is suitable for a first diagnostic
anomaly baseline, not a strong evaluation claim without reporting the duplicate
policy, label-agnostic conflicts, and severe three-feature collision limits.
No model was trained during this audit.

The fixture config and unit tests use tiny local CSVs only. They do not claim a
dataset size or model accuracy for CIC-IDS2017. No model is implemented in this
phase.

## Real Parquet preparation result

The external three-file subset was prepared on 2026-10-05 with:

```text
PYTHONPATH=ml/src control-plane/.venv/bin/python -m intriqo_ml.datasets \
  --config ml/configs/datasets/cicids2017-dev.json \
  --dataset-root /run/media/rayan/Workspace/08_Datasets/cicids2017/machine_learning \
  --output-dir /run/media/rayan/Workspace/08_Datasets/cicids2017/prepared/intriqo-cicids2017-monday-wednesday \
  --force
```

| Source | Raw rows | Valid | Invalid | Duplicates | Split |
|---|---:|---:|---:|---:|---|
| Monday | 529,918 | 502,635 | 27,283 | 26,831 | train_normal |
| Tuesday | 445,909 | 421,610 | 24,299 | 24,018 | validation |
| Wednesday | 692,703 | 610,471 | 82,232 | 80,914 | test |
| **Total** | **1,668,530** | **1,534,716** | **133,814** | **131,763** | |

The explicit duplicate policy is exact complete-row duplicates within each source
file; rows are not deduplicated across files. Invalid rows were not coerced. The
quality report recorded 1,998 `impossible_duration` rows and 53 `numeric_range`
rows. A direct PyArrow audit found no nulls in the selected columns. It also found
1,998 nonfinite `Flow Packets/s`/`Flow Bytes/s` observations and 53 negative
duration/rate observations; zero-duration rows are rejected first as impossible
when they contain packets, so their final reason is `impossible_duration`.

Final label distribution after validation/deduplication:

- train_normal: 502,635 BENIGN
- validation: 412,460 BENIGN; 5,931 FTP-Patator; 3,219 SSH-Patator
- test: 416,715 BENIGN; 172,846 DoS Hulk; 10,286 DoS GoldenEye; 5,385 DoS
  slowloris; 5,228 DoS Slowhttptest; 11 Heartbleed

Feature statistics are in `statistics.json`. Across all valid rows:

| Split | Feature | Min | Max | Mean | Median |
|---|---|---:|---:|---:|---:|
| train_normal | duration_seconds | 0.000001 | 119.999987 | 10.926873 | 0.376894 |
| train_normal | packet_count | 2 | 511,681 | 22.923630 | 4 |
| train_normal | packets_per_second | 0.016702 | 3,000,000 | 56,906.692415 | 21.083704 |
| validation | duration_seconds | 0.000001 | 119.999977 | 11.394995 | 0.4188295 |
| validation | packet_count | 2 | 482,518 | 27.014053 | 4 |
| validation | packets_per_second | 0.016709 | 3,000,000 | 50,915.723355 | 19.148286 |
| test | duration_seconds | 0.000001 | 119.999998 | 31.768669 | 0.4358045 |
| test | packet_count | 2 | 474,809 | 22.108788 | 6 |
| test | packets_per_second | 0.016718 | 3,000,000 | 36,164.489412 | 20.488963 |

Processing took **288.04 seconds wall time** with **647,520 KiB peak RSS**.
Generated artifacts remain outside the repository at the output directory above;
their sizes are recorded in `dataset_manifest.json` and range from 164 bytes for
`preprocessing.json` to 46,604,649 bytes for `test_metadata.csv`. The manifest
records all three source paths, formats, byte sizes, SHA-256 hashes, row counts,
mapping version, feature order, split assignments, preprocessing, and
`model_implementation: null`.
