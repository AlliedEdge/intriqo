# Controlled Native Intriqo v2 Evaluation

**Status: `READY_FOR_V2_MODEL_TRAINING` (quality gate only; no model was trained)**

This is the design for a narrow representation experiment, not a public
benchmark and not external real-world validation. It is intended to answer:

> Can the native Intriqo v2 representation distinguish controlled benign and
> malicious network-flow behavior when ground truth is known independently?

The controlled capture milestone completed on 2026-10-06. No additional
CIC-IDS2017, CSE-CIC-IDS2018, or IoT-23 acquisition was attempted. No model was
trained, no score was produced, and no v1, native-v2, or deterministic detector
semantics were changed. The readiness status means only that the pre-training
quality gate passed; it is not an external-generalization claim.

## 0. Actual lab run

The lab was run in a local `ubuntu:26.04` Docker container with
`--network none`. Four private network namespaces were created inside that
container: `iqv2-attacker`, `iqv2-victim`, `iqv2-switch`, and `iqv2-monitor`.
The switch namespace used `br-intriqo-v2` for the two endpoint veths and
`tc` ingress `matchall`/`mirred` filters on both endpoint ports. The mirrored
copy traversed a separate veth into `tap-intriqo-v2`; it was not a normal
third bridge endpoint. The topology verifier recorded exact interface
allowlists, no default/external routes, disabled IPv6/autoconfiguration,
forwarding off, permanent endpoint neighbors, both mirror actions, and no
host link operations. The host's pre-existing global IPv4 forwarding value
was `1`, but the lab container was `--network none` with no host-facing
interface; each lab namespace's public route lookup failed without a probe,
so there was no forwarding path from the lab to an external interface. This
host-boundary distinction is recorded in `host_boundary_receipt.json`.

The first `BENIGN_TCP_BASIC` episode passed before attack traffic was started:
10 monitor packets, 6 attacker-to-victim and 4 victim-to-attacker, equal to
both endpoint captures. Its native replay produced one v2 record and its
independent raw-PCAP/controller alignment was `EXACT`.

The completed corpus contains 12 immutable monitor captures, 26 native flows,
8 benign flows, and 18 attack flows. All 12 endpoint-vs-monitor visibility
receipts passed; every monitor receipt had bidirectional counts and zero
unexpected-IP or unsupported packets. The two initial failed long-flow
attempts are retained outside the corpus in `capture_failures.json` and were
not enrolled as captures.

All namespace probes used UTC, a shared time namespace, and the same
`CLOCK_MONOTONIC_RAW` source. PCAPs are classic Ethernet (`DLT_EN10MB`) with
nanosecond timestamps from kernel `SO_TIMESTAMPNS`; the original files remain
outside Git under `/tmp/opencode/intriqo-controlled-v2/raw/`.

| Episode | Capture bytes | Packets | Native flows |
|---|---:|---:|---:|
| `train-benign-tcp` | 926 | 10 | 1 |
| `train-benign-http` | 2,174 | 22 | 1 |
| `train-benign-udp` | 206 | 2 | 1 |
| `train-benign-dns` | 934 | 10 | 1 |
| `train-benign-long` | 1,862 | 19 | 1 |
| `train-benign-bursty` | 3,110 | 31 | 1 |
| `validation-benign-asymmetric` | 1,550 | 16 | 1 |
| `validation-syn-flood` | 11,224 | 160 | 1 |
| `validation-port-scan` | 2,264 | 32 | 8 |
| `test-benign-mixed` | 3,110 | 31 | 1 |
| `test-syn-flood` | 11,224 | 160 | 1 |
| `test-port-scan` | 2,264 | 32 | 8 |

The complete SHA-256 and provenance table is
[`ml/artifacts/feature-analysis/controlled-v2/capture_provenance_summary.json`](../ml/artifacts/feature-analysis/controlled-v2/capture_provenance_summary.json).

## 1. Controlled topology

The laboratory must be a private, disconnected network created specifically for
this corpus:

```text
  ATTACKER namespace/container                         VICTIM namespace/container
  10.77.0.10  ───── veth-attacker ┐        ┌─ veth-victim  10.77.0.20
                                   ├─ br-intriqo-v2 ── veth/tap monitor
                                   └──── mirrored ingress + egress ───┐
                                                                       ▼
                                                         MONITOR: tap-intriqo-v2
                                                         native capture point
```

The bridge mirror/TAP is a requirement, not an illustration. Ordinary Wi-Fi
capture or a monitor container attached as a third ordinary bridge endpoint is
not accepted as complete visibility. The monitor must receive both directions
of attacker-victim traffic, and the capture setup must record the mirror/TAP
configuration with the run.

| Field | Controlled value/design |
|---|---|
| Attacker IP | `10.77.0.10` |
| Victim IP | `10.77.0.20` |
| Subnet | `10.77.0.0/24` |
| Capture interface | `tap-intriqo-v2` on the monitor |
| Link type | Expected Ethernet (`DLT_EN10MB`); verify from the resulting PCAP |
| Timezone | UTC in the controller and capture host |
| Clock synchronization | Record chrony/PTP status and UTC offset before and after every run |
| Internet access | Disabled at the namespace/bridge boundary; no default route |
| Experiment ID | Controller-generated and written before traffic begins |

Each capture is one immutable experiment episode. The controller records the
experiment ID, scenario ID, exact traffic parameters, start/end timestamps,
attacker/victim identity, protocol and ports, expected flow scope, and the
independent ground-truth source before or while traffic is generated.

The existing `security-lab` Docker network is useful as a development
reference, but it is not automatically accepted for this corpus: an ordinary
bridge endpoint does not prove observation of unicast traffic, and its old
scenario scripts accept target parameters. The controlled-v2 run must use the
fixed addresses above and an explicit mirror/TAP verification.

## 2. Scenario matrix

The planned matrix is recorded in
[`ml/artifacts/feature-analysis/controlled-v2/scenario_matrix.json`](../ml/artifacts/feature-analysis/controlled-v2/scenario_matrix.json).

### Train: benign only

Separate captures exercise short TCP request/response, HTTP-like repeated
traffic, UDP request/response, DNS-like bursts, a long-lived bidirectional TCP
flow, and bursty concurrent flows with idle periods. These scenarios are
designed to exercise the nine native dimensions, not to imitate Internet
traffic.

### Validation: new benign plus controlled attacks

Validation contains an asymmetric benign TCP flow, an authorized SYN flood,
and an authorized TCP port scan. The flood is confined to the victim namespace;
the scan targets only `10.77.0.20` inside the isolated subnet.

### Test: new independent runs

Test contains a new mixed benign workload and independent SYN-flood and
port-scan runs. It is not a replay or slice of validation. A new run means a
new capture episode, controller seed/port allocation, experiment ID, and
capture hash.

No extra attack category is required for this milestone. A connection-rate,
asymmetric, burst, or unusual-flag anomaly may be added only if the controller
can state what v2 dimension it probes and it remains inside the same isolated
topology.

For floods and scans, one episode expands into multiple controller ground-truth
rows with the exact five-tuples observed/generated by the controller. A single
episode label is not used as a shortcut to label every native row.

## 3. Frozen v2 inputs

The replay uses the existing C++ engine with `--feature-schema
flow_features.v2`. The model projection is exactly:

1. `duration_seconds`
2. `packet_count`
3. `packets_per_second`
4. `minor_direction_packet_fraction`
5. `mean_ipv4_packet_bytes`
6. `ipv4_direction_byte_imbalance`
7. `syn_packet_fraction`
8. `fin_packet_fraction`
9. `flow_iat_std_seconds`

No formula, feature order, idle policy, flow tracker, packet parser, v1
contract, SecurityEvent contract, or deterministic detector is changed for this
evaluation.

## 4. Independent ground truth

`completed_experiment_manifest.json` is controller-owned for the enrolled run
(the pre-capture `experiment_manifest.json` remains as a regression/design
receipt). It does not read native
features, detector output, model output, or scores. Each row contains:

```text
experiment_id, scenario_id, split, label, attack_family,
attacker_ip, victim_ip, capture_interface, subnet, protocol,
source_port, destination_port, start_timestamp, end_timestamp,
expected_flow_scope, source_label_id, ground_truth_source
```

Allowed labels are only `BENIGN` and `ATTACK`. Attack families are explicit,
including `SYN_FLOOD` and `PORT_SCAN`. A benign row never carries an attack
family. For pre-capture design, timestamps are null; a completed controller
manifest must fill them before alignment.

Unknown, missing, and ambiguous observations remain unlabelled. In particular,
`UNKNOWN` is never normalized to `BENIGN`.

## 5. Capture provenance and integrity

The capture manifest is empty until a real authorized run exists. Every
`CAPTURED` entry must include:

- experiment ID and original filename;
- original immutable source path;
- byte size and SHA-256 of the original PCAP;
- capture start/end in UTC;
- interface, link type, timestamp resolution, and timezone;
- clock synchronization evidence;
- capture group/parent capture identity;
- a statement that the original PCAP was not modified.

The alignment and quality tools derive files in a separate output directory.
They never rewrite an input PCAP. `capture_hashes.json` intentionally contains
no placeholder digest while the corpus has no capture.

## 6. Native replay harness

After capture, the isolated harness invokes the existing engine, without
changing its semantics:

```text
PCAP
  -> existing native parser
  -> existing flow tracker
  -> existing native v2 extraction
  -> native_features_v2.jsonl
```

The replay receipt records the exact command, PCAP size/hash, engine binary
hash, packet received/parsed/rejected/dropped counters, unsupported and
truncated packets, flow creation/expiry/flush counts, emitted/submitted/written
v2 records, feature generation/validation/write failures, and parser errors.

The controlled quality gate requires no capture/truncation/unsupported or v2
stream failure and requires every emitted JSONL line to pass the existing strict
v2 parser. A replay receipt is not a success receipt unless the observed state
is verified from the shutdown counters and output stream.

Run the harness only against captured files declared in the capture manifest:

```bash
PYTHONPATH=ml/src python -m intriqo_ml.native_v2_eval build \
  --experiment-manifest ml/artifacts/feature-analysis/controlled-v2/completed_experiment_manifest.json \
  --capture-manifest ml/artifacts/feature-analysis/controlled-v2/completed_capture_manifest.json \
  --split-definition ml/artifacts/feature-analysis/controlled-v2/completed_split_definition.json \
  --engine build/flow-release/engine/intriqo-engine \
  --output-dir ml/artifacts/feature-analysis/controlled-v2/run-<experiment-id>
```

With the current empty capture manifest, the command can create a blocked
zero-row receipt, but it cannot create native flow evidence. It has no
`fit`, `score`, or threshold operation.

## 7. Label alignment

The isolated alignment layer consumes only:

- a parsed `FlowFeatureRecordV2` and its capture ID; and
- controller rows from the independent experiment manifest.

It matches in this order:

1. capture-to-experiment identity;
2. protocol and directional attacker-to-victim five-tuple;
3. positive temporal overlap using integer nanosecond timestamps.

The output retains the native tuple, flow ID, timestamps, source label ID,
candidate count, overlap, and reason. Statuses are:

| Status | Meaning | Eligibility |
|---|---|---|
| `EXACT` | one candidate, exact directional five-tuple and equal interval bounds | eligible |
| `PARTIAL` | one candidate with positive overlap but boundary or wildcard-port difference | retained, excluded from the conservative training/evaluation view |
| `AMBIGUOUS` | multiple overlapping candidates or conflicting controller rows | retained, never guessed |
| `UNKNOWN` | no defensible candidate, missing timestamps, or unsupported input | retained, never benign |

The conservative eligibility policy is `EXACT` only. It is intentionally
possible for a capture to be useful for diagnosing coverage while not being
eligible for model training.

## 8. Split and leakage policy

`split_definition.json` assigns complete capture episodes. It forbids random
row splits. Validation checks:

- every capture is assigned to exactly one split;
- capture groups and parent captures do not cross splits;
- a PCAP SHA-256 is not reused across splits;
- native row keys `(capture_id, engine_instance_id, flow_id)` are unique;
- an independent source label ID is not assigned to multiple splits;
- overlapping child time slices of one parent capture do not cross splits.

Repeated nine-dimensional vectors are not silently discarded. They are reported
as feature collisions, including their known labels and split locations. A
collision is a representation diagnostic, not automatically a leakage finding.

## 9. Dataset-quality report before any model

`quality_report.json` must be reviewed before the existing Isolation Forest v2
pipeline is even considered. It reports:

- total, benign, attack, per-family, and per-split flow counts;
- `EXACT`/`PARTIAL`/`AMBIGUOUS`/`UNKNOWN` coverage;
- native replay and parser counters;
- all nine feature distributions and finiteness;
- duplicate native rows and exact feature-vector collisions;
- split leakage violations;
- blockers and the `ready_for_model_training` gate.

The completed report has 26 flows, all 26 `EXACT`, finite nine-feature
distributions, zero duplicate native keys, zero feature-vector collisions,
zero split violations, and `ready_for_model_training: true`. This task did not
train a model and created no model artifact. The pre-capture design receipt is
preserved separately from the completed run receipts.

## 10. Files and implementation status

Added for this milestone:

- `docs/ml-controlled-evaluation.md` — design, safety boundary, and review gate.
- `ml/src/intriqo_ml/native_v2_eval/schema.py` — strict manifests and immutable
  provenance fields.
- `ml/src/intriqo_ml/native_v2_eval/replay.py` — exact existing-engine replay
  wrapper and counter receipt.
- `ml/src/intriqo_ml/native_v2_eval/alignment.py` — isolated conservative
  alignment with four explicit statuses.
- `ml/src/intriqo_ml/native_v2_eval/splits.py` — capture-level split checks.
- `ml/src/intriqo_ml/native_v2_eval/quality.py` — pre-training quality report.
- `ml/src/intriqo_ml/native_v2_eval/build.py` and `__main__.py` — corpus
  artifact builder; no training entry point.
- `ml/artifacts/feature-analysis/controlled-v2/` — scenario matrix, manifests,
  immutable capture/provenance receipts, replay/alignment/quality reports,
  split checks, and the lab isolation receipt.

Protected implementation boundaries were not changed by this design: v1,
native v2, deterministic detectors, SecurityEvent v1, and production engine
architecture remain outside this addition.

## 11. Next milestone

The controlled corpus now passes its conservative pre-training gate and is
`READY_FOR_V2_MODEL_TRAINING`. The next milestone may consider the existing
Isolation Forest v2 experiment, but that experiment is intentionally outside
this task. No external generalization claim may be made from this corpus.
