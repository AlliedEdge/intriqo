# Feature Set v2: contract and CIC-IDS2017 mapping investigation

**Decision:** propose a nine-feature **Intriqo-native target**, gated on measurement availability. The original CIC-IDS2017 Parquet cannot honestly supply all nine features. Four count/time dimensions can be calculated for a conditional CIC-row study; IPv4 sizes, genuine TCP counters, and native inter-arrival statistics need separately authorized extraction/contract work.

This is an investigation, dated 2026-10-06. **No real-data model was trained, loaded for inference, or scored. Feature Set v2 was not implemented. The held-out test set was not opened or evaluated.** Only the existing Tuesday validation rows were used for collision calculations. The v1 engine, contracts, preparation/duplicate policy, checkpoint, and locked threshold remain unchanged.

Machine-readable companion: [`ml/artifacts/feature-analysis/feature_set_v2_analysis.json`](../ml/artifacts/feature-analysis/feature_set_v2_analysis.json). It contains all 79 field audits, numeric diagnostics, proposal gates, rejected fields, float64/float32 collision statistics, source hashes, and protected-file hashes.

## 1. Current v1 limitations

The existing ML projection is `duration_seconds`, `packet_count`, and `packets_per_second`. This is a three-dimensional model input, **not** the complete FlowFeatureRecord v1 contract. On positive-duration flows the rate is determined by the other two measurements, so the representation carries essentially two independent measurement axes.

The unchanged validation lock is:

| Measurement | Value |
| --- | ---: |
| ROC-AUC | 0.7648450670096443 |
| PR-AUC / average precision | 0.04709945026378298 |
| Locked threshold | 0.7407202799602526 |
| Maximum recall at FPR cap ≤0.25% | 0% |
| Maximum recall at FPR cap 0.50% or 1% | 0.021858% |
| Maximum recall at FPR cap 2% | 0.065574% |
| Maximum recall at FPR cap 5% | 0.327869% |
| Maximum recall at FPR cap 10% | 32.163934% |

At the 10% cap, detection is dominated by SSH-Patator; FTP-Patator is almost entirely undetected. These values are existing validation evidence, not results of a new model experiment.

Prepared validation has 421,610 rows: 412,460 BENIGN, 5,931 FTP-Patator, and 3,219 SSH-Patator. V1 has 388 mixed-label feature groups containing 71,607 rows. Of the 9,150 attacks, 2,186 (23.8907%) share an exact three-feature vector with BENIGN: 1,944 FTP and 242 SSH.

These collisions limit label separability from the representation alone. They do not explain every missed attack, and removing collisions does not establish a useful low-FPR detector. The separate pre-dedup quality audit's 86,002 affected rows are **not** the prepared-validation denominator used here.

## 2. Authoritative Intriqo semantics

### Sources inspected

- `engine/include/intriqo/packet/packet.hpp` and `engine/src/packet/parser.cpp:9-29`: accepted IPv4/L4 packet measurements.
- `engine/include/intriqo/flow/flow.hpp` and `engine/src/flow/flow_table.cpp:38-194`: direction, counters, timestamps, retirement, and derived rates.
- `engine/include/intriqo/features/features.hpp` and `engine/src/features/extractor.cpp`: existing feature extraction.
- `engine/include/intriqo/features/flow_feature_record.hpp` and `engine/src/features/flow_feature_record.cpp:182-253`: immutable retirement snapshots and serialization.
- `contracts/features/flow_features_v1.json` and `ml/src/intriqo_ml/flow_features.py:199-269`: complete strict v1 contract, not a CICFlowMeter reinterpretation.
- `engine/src/capture/pcap_source.cpp:93-116`: microsecond/nanosecond capture timestamps.
- `engine/tests/integration/test_flow_feature_lifecycle.cpp`, `engine/tests/unit/test_flow_feature_record.cpp`, and `ml/tests/integration/test_cpp_feature_stream.py`: tested native flow behavior, including real-process JSONL export.
- `ml/src/intriqo_ml/datasets/mapping.py:21-50,130-192`: current conservative CIC projection and explicit exclusion of payload bytes and legacy flags.

### Contract inventory

V1 already exports packet/byte totals, duration, mean IPv4 bytes per packet, packet/byte rates, both directional packet/byte counts, SYN/FIN/RST counts, `initial_syn_count`, `syn_ack_count`, `ack_count`, and three observed-handshake booleans. It exports no packet-size variance, IAT moments, PSH/URG/CWR/ECE counters, TCP windows, bulk/subflow state, or active/idle statistics. Network identifiers and capture timestamps are metadata, not proposed model inputs.

The legacy C++ `connection_attempts` member is not exported; it must not be introduced as a fabricated connection feature. Native handshake evidence cannot be recovered from CIC summary counts or a single initial flag marker.

### Semantics that must remain authoritative

1. **Bytes:** `ParsedPacket.total_length` is the IPv4 header's total length. Flow byte counters sum it, excluding Ethernet/L2 but including IPv4 and transport headers. `bytes_per_packet = byte_count / packet_count`, or zero for no packets.
2. **The misleading payload name:** `ParsedPacket.payload_length = IPv4 total_length - IHL`; it includes TCP/UDP headers. It is **not** CICFlowMeter's TCP/UDP application-payload measurement. The flow does not currently aggregate this member.
3. **Direction:** the packet that creates a flow fixes its five-tuple. Subsequent packets match that tuple or its reverse. Forward does not mean attacker, TCP initiator, or guaranteed client. Late packets and mid-capture flows do not change orientation.
4. **Retirement:** idle expiry at the configured idle budget, bounded-capacity eviction, or shutdown flush. FIN/RST are counted; they do not retire a flow. The lifecycle test explicitly retains SYN, SYN-ACK, ACK, FIN-ACK, and RST-ACK in one flow until expiry.
5. **TCP:** SYN, FIN, and RST counts are per accepted TCP packet with the corresponding bit set, including combinations. `ack_count` requires ACK set and SYN/FIN/RST clear; PSH/URG do not exclude it. `initial_syn_count` requires SYN with ACK/FIN/RST clear; `syn_ack_count` requires SYN+ACK with FIN/RST clear. Handshake booleans also depend on direction and observation order. Non-TCP counters are zero.
6. **Time:** `first_seen` is the creation packet's capture timestamp, not the minimum of a reordered packet stream. `last_seen` is the maximum accepted timestamp; late packets still increment counters without rewinding it. Duration is `last_seen - first_seen`. Rates are zero at zero duration. Record `metadata.timestamp` is `last_seen`, not the wall time of export.
7. **Observation coverage:** counts describe accepted packets, not ground-truth wire traffic. Parser rejection, truncated capture, capture loss, and partial capture alter observed volume, flags, direction, and timing. Per-flow missing packets cannot be reconstructed from these CSV summaries. Global drop statistics are not an exact per-flow correction.
8. **IAT:** no consecutive-gap, moment, or directional endpoint state is currently aggregated. Count and duration cannot recover gap variance, minimum, maximum, or packet order. Adding an IAT measurement requires new state and an explicit additive contract; it must not change existing timestamp or flow-retirement rules.

The parser and Python wire models do not recalculate or normalize emitted rates. Future derived ML ratios must be separately named projections, not replacements for accepted v1 values.

## 3. CICFlowMeter evidence and compatibility rules

The exact generator commit used to create this dataset is absent from its provenance. The evidence combines:

- The published [CICIDS2017 case-study audit](https://intrusion-detection.distrinet-research.be/WTMC2021/extended_doc.html), which identifies defects in the original dataset, notably first-packet-only flag counts and TCP flow construction/appendices.
- Inspected, pinned historical CICFlowMeter source at commit [`6833ccd4ff2953fdd2ab703060d43e349494151e`](https://github.com/ahlashkari/CICFlowMeter/tree/6833ccd4ff2953fdd2ab703060d43e349494151e): [`PacketReader.java`](https://github.com/ahlashkari/CICFlowMeter/blob/6833ccd4ff2953fdd2ab703060d43e349494151e/src/main/java/cic/cs/unb/ca/jnetpcap/PacketReader.java), [`BasicFlow.java`](https://github.com/ahlashkari/CICFlowMeter/blob/6833ccd4ff2953fdd2ab703060d43e349494151e/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java), and [`FlowGenerator.java`](https://github.com/ahlashkari/CICFlowMeter/blob/6833ccd4ff2953fdd2ab703060d43e349494151e/src/main/java/cic/cs/unb/ca/jnetpcap/FlowGenerator.java). This is corroborating 2018 code, **not an attestation of the exact 2017 generator**. Newer master behavior must not be assumed for the original CSVs.
- The actual Tuesday Parquet's 79-column schema and retained-row numeric checks.
- The [dataset origin and collection description](https://www.unb.ca/cic/datasets/ids-2017.html).

### Issue keys used in the full audit

| Key | Finding and mapping consequence |
| --- | --- |
| W | CIC's published 120-second duration window and FIN-triggered termination differ from Intriqo idle/capacity/shutdown retirement. Even a mathematically compatible field is a measurement over a different window; identical flows on identical PCAPs are not established. In inspected `FlowGenerator:84-120`, timeout inherits endpoints, and FIN retires an existing flow. |
| O | CIC timeout flows can retain the previous orientation instead of the first packet's orientation. Historical `firstPacket` also uses byte-array reference equality while later packets use content equality. A symmetric ratio tolerates a complete direction swap, **not** an individual packet placed in the wrong direction. Counts used here are therefore conditional CIC-row observations, not certified native counters. |
| P | `PacketReader:141-147` uses transport `getPayloadLength()`, and BasicFlow accumulates it. CIC length/byte features exclude transport/IP headers; Intriqo byte features include them. |
| G | `BasicFlow:122,135,149` adds the first payload twice to global length statistics. Duplication does not change min/max, but does alter mean, variance, standard deviation, and average size. Global stats are also payload, not IPv4 lengths. |
| F | Original CICIDS2017 flag counts are first-packet 0/1 markers. Historical `firstPacket` checks flags, but `addPacket:169` comments out `checkFlags`. Directional PSH/URG counters are also only initialized from the first packet. A bit marker cannot be converted to an all-packet count. |
| A | CIC ACK-bit counts are not Intriqo ACK-without-SYN/FIN/RST counts, even with a fixed exporter. Marginal counts cannot reconstruct flag intersections, direction, or ordered handshake evidence. |
| T | CIC IPv4 timestamps are in microseconds; IAT summaries use consecutive arrival timestamps, not Intriqo's maximum-timestamp duration rule. Apache SummaryStatistics uses sample standard deviation. Empty/one-gap, reorder, quantization, directional assignment, and loss conventions require explicit agreement. |
| R | `BasicFlow:234-236` divides integer backward/forward sizes before converting to double; supplied Down/Up Ratio discards fractions. Recompute a bounded symmetric ratio from counts instead. |
| H | Header length means TCP/UDP header length, not IPv4 length or TCP MSS. A duplicate forward-header column exists. Negative/invalid observed header lengths make simple reconstruction especially indefensible. |
| B | Bulk thresholds/state are exporter-specific; historical updates after the first packet are commented out. Source also contains direction/reference issues and a backward-bytes/bulk export using the forward getter. No engine bulk measurements exist. |
| S | Historical subflow updates after the first packet are commented out, the gap expression has misplaced division, and exported values are integer averages per subflow, not defined whole-flow counters. Coincidental equality to totals does not establish semantic identity. |
| V | TCP window is the raw unscaled advertised-window field, with `-1` missing. Backward window is overwritten by later backward packets in inspected code. Neither window nor scaling state is retained by the current parser. |
| D | Historical active-data packet count omits first-packet accounting and uses positive L4 payload. Engine `payload_length > 0` would not be the same predicate. |
| I | Active/idle periods depend on an activity-gap policy and end-window handling, not flow export reason. The published absolute-timestamp bug concerns a newer re-extraction version; it is a risk to inspect, not proof that these original 2017 columns contain epoch timestamps. |

All candidate rows inherit **W** and observation-coverage caveats. A/B classifications below mean compatibility of the stated scalar/projection on retained CIC rows, subject to their gates; they are not unconditional PCAP equivalence or deployment approval.

### Why bytes cannot be repaired with a fixed offset

For packet-aligned IPv4 traffic, the required identity would be:

`native IPv4 bytes = CIC L4 payload bytes + sum(transport header lengths) + sum(IPv4 IHL)`.

The 79-column subset lacks per-packet IPv4 IHL, trustworthy packet/header observations, protocol provenance, and matched native windows. Header columns are present, but transport-only, partly invalid, and insufficient. Adding `20 × packets`, `40 × packets`, or assuming a constant TCP header is not an honest conversion. Standard deviation/variance additionally require per-packet header/payload covariance; totals do not recover it.

## 4. Full candidate feature audit / semantic compatibility table

The actual schema contains **79 columns including Label**, not 79 approved measurements. The duplicated header column is named `Fwd Header Length_duplicated_0` in this Parquet. Classification counts: **A=1, B=5, C=47, D=24, E=2**.

- **A:** safe scalar semantics on retained rows.
- **B:** compatible only with the specified conversion/projection and explicit gates.
- **C:** unsafe direct mapping, semantically different, or damaged legacy measurement.
- **D:** equivalent measurement unavailable in the current engine/export.
- **E:** potential leakage / identifier; excluded from model inputs.

Notation: `F/B` are CIC forward/backward packet counts; `N=F+B`; `d=Flow Duration/1e6`; `P_f/P_b` are CIC directional payload totals. `Y*` means the intended native all-packet counter exists, **not** that the supplied legacy value maps to it. `ML` denotes derivable from v1 without new packet state, but not an exported v1 field. `New` means additive measurements/state/export would be needed; v1 itself must remain frozen. "Add" answers whether a distinctly named measurement/projection can be introduced without changing packet acceptance, byte accounting, direction, or retirement semantics; it is not approval of the CIC column.

Leakage keys: **L** low direct identifier leakage, with capture/exporter shortcuts possible; **Q** substantial generator/tool/OS fingerprint shortcut risk; **X** identifier, attack schedule, or direct target leakage. Issue keys give the reason for each classification and are expanded above. Every row's full text and numeric coverage is in the companion JSON.

| CIC-IDS2017 field | Intriqo equivalent / closest intended target | CIC unit | Conversion / disposition | C++ computes | V1 exports | Add | Issues | Leakage | Class |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Destination Port | `metadata.network.dst_port`, orientation-gated | port | Integer; exclude model input | Y | Y, metadata | ML | O | X | E |
| Flow Duration | `duration_seconds` | µs | Divide by 1e6; require timestamp/window agreement | Y | Y | ML | T,W | L | B |
| Total Fwd Packets | Unordered `fwd_packet_count/rev_packet_count` pair | packets | Sum, or `min(F,B)/N`; no direct ordered identity | Y | Y | ML | O | L | B |
| Total Backward Packets | Unordered `fwd_packet_count/rev_packet_count` pair | packets | Sum, or `min(F,B)/N`; no direct ordered identity | Y | Y | ML | O | L | B |
| Total Length of Fwd Packets | None; NOT `fwd_byte_count` | L4 payload bytes | No reliable IPv4 conversion | N | N | New | P,O | L | C |
| Total Length of Bwd Packets | None; NOT `rev_byte_count` | L4 payload bytes | No reliable IPv4 conversion | N | N | New | P,O | L | C |
| Fwd Packet Length Max | None; directional payload maximum | bytes | No IPv4-moment conversion | N | N | New | P,O | L | C |
| Fwd Packet Length Min | None; directional payload minimum | bytes | No IPv4-moment conversion | N | N | New | P,O | L | C |
| Fwd Packet Length Mean | None; NOT native packet-byte mean | bytes | `P_f/F` is payload only | N | N | New | P,O | L | C |
| Fwd Packet Length Std | None; directional payload sample std | bytes | No IPv4-moment conversion | N | N | New | P,O,T | L | C |
| Bwd Packet Length Max | None; directional payload maximum | bytes | No IPv4-moment conversion | N | N | New | P,O | L | C |
| Bwd Packet Length Min | None; directional payload minimum | bytes | No IPv4-moment conversion | N | N | New | P,O | L | C |
| Bwd Packet Length Mean | None; NOT native packet-byte mean | bytes | `P_b/B` is payload only; zero if B=0 | N | N | New | P,O | L | C |
| Bwd Packet Length Std | None; directional payload sample std | bytes | No IPv4-moment conversion | N | N | New | P,O,T | L | C |
| Flow Bytes/s | None; NOT `bytes_per_second` | payload bytes/s | `(P_f+P_b)/d` is not IPv4 bytes/s | N | N | New | P | L | C |
| Flow Packets/s | `packets_per_second` | packets/s | Identity; validate against N/d on retained rows | Y | Y | ML | W,T | L | A |
| Flow IAT Mean | None; possible new all-packet gap mean | µs | Divide by 1e6, after gap-policy agreement | N | N | New | T | L | D |
| Flow IAT Std | None; proposed new gap sample std | µs | Divide by 1e6, after gap-policy agreement | N | N | New | T | L | D |
| Flow IAT Max | None; possible new maximum gap | µs | Divide by 1e6, after gap-policy agreement | N | N | New | T | L | D |
| Flow IAT Min | None; possible new minimum gap | µs | Divide by 1e6; do not silently clip negatives | N | N | New | T | L | D |
| Fwd IAT Total | None; possible directional gap sum | µs | Divide by 1e6; not total flow duration | N | N | New | T,O | L | D |
| Fwd IAT Mean | None; possible directional gap mean | µs | Divide by 1e6 | N | N | New | T,O | L | D |
| Fwd IAT Std | None; possible directional sample std | µs | Divide by 1e6 | N | N | New | T,O | L | D |
| Fwd IAT Max | None; possible directional maximum gap | µs | Divide by 1e6 | N | N | New | T,O | L | D |
| Fwd IAT Min | None; possible directional minimum gap | µs | Divide by 1e6 | N | N | New | T,O | L | D |
| Bwd IAT Total | None; possible directional gap sum | µs | Divide by 1e6; not total flow duration | N | N | New | T,O | L | D |
| Bwd IAT Mean | None; possible directional gap mean | µs | Divide by 1e6 | N | N | New | T,O | L | D |
| Bwd IAT Std | None; possible directional sample std | µs | Divide by 1e6 | N | N | New | T,O | L | D |
| Bwd IAT Max | None; possible directional maximum gap | µs | Divide by 1e6 | N | N | New | T,O | L | D |
| Bwd IAT Min | None; possible directional minimum gap | µs | Divide by 1e6 | N | N | New | T,O | L | D |
| Fwd PSH Flags | None; possible directional PSH count | legacy 0/1 | Cannot recover count from first packet | N | N | New | F,O | Q | C |
| Bwd PSH Flags | None; possible directional PSH count | legacy 0/1 | Cannot recover count from first packet | N | N | New | F,O | Q | C |
| Fwd URG Flags | None; possible directional URG count | legacy 0/1 | Cannot recover count from first packet | N | N | New | F,O | Q | C |
| Bwd URG Flags | None; possible directional URG count | legacy 0/1 | Cannot recover count from first packet | N | N | New | F,O | Q | C |
| Fwd Header Length | None; transport-header sum | bytes | Not IPv4 bytes; invalid negatives present | N | N | New | H,O | Q | C |
| Bwd Header Length | None; transport-header sum | bytes | Not IPv4 bytes; invalid negatives present | N | N | New | H,O | Q | C |
| Fwd Packets/s | Derived `fwd_packet_count/duration_seconds` | packets/s | Recompute pair, symmetrize; redundant | N | N | ML | O,W | L | B |
| Bwd Packets/s | Derived `rev_packet_count/duration_seconds` | packets/s | Recompute pair, symmetrize; redundant | N | N | ML | O,W | L | B |
| Min Packet Length | None; payload minimum | bytes | No IPv4 conversion; duplicate does not alter min | N | N | New | P,G | L | C |
| Max Packet Length | None; payload maximum | bytes | No IPv4 conversion; duplicate does not alter max | N | N | New | P,G | L | C |
| Packet Length Mean | None; NOT `bytes_per_packet` | bytes | No reliable correction to IPv4 mean | N | N | New | P,G | Q | C |
| Packet Length Std | None; global payload sample std | bytes | No reliable correction to IPv4 std | N | N | New | P,G,T | Q | C |
| Packet Length Variance | None; global payload sample variance | bytes² | No reliable correction to IPv4 variance | N | N | New | P,G,T | Q | C |
| FIN Flag Count | Intended `fin_count`, NOT legacy value | legacy 0/1 | Re-extract actual bit counts; no CSV conversion | Y* | Y* | ML* | F | Q | C |
| SYN Flag Count | Intended `syn_count`, NOT legacy value | legacy 0/1 | Re-extract actual bit counts; no CSV conversion | Y* | Y* | ML* | F | Q | C |
| RST Flag Count | Intended `rst_count`, NOT legacy value | legacy 0/1 | Re-extract actual bit counts; no CSV conversion | Y* | Y* | ML* | F | Q | C |
| PSH Flag Count | None; possible PSH bit count | legacy 0/1 | Re-extract actual bit counts | N | N | New | F | Q | C |
| ACK Flag Count | None; closest `ack_count` has exclusions | legacy 0/1 | Cannot recover masked ACK/handshake counts | N | N | New | F,A | Q | C |
| URG Flag Count | None; possible URG bit count | legacy 0/1 | Re-extract actual bit counts | N | N | New | F | Q | C |
| CWE Flag Count | None; possible CWR bit count | legacy 0/1 | Re-extract; name refers to CWR | N | N | New | F | Q | C |
| ECE Flag Count | None; possible ECE bit count | legacy 0/1 | Re-extract actual bit counts | N | N | New | F | Q | C |
| Down/Up Ratio | None; use new symmetric count ratio | dimensionless | Reject truncated value; use min(F,B)/N | N | N | ML | R,O | Q | C |
| Average Packet Size | None; NOT `bytes_per_packet` | bytes | Payload sum includes duplicated first packet | N | N | New | P,G | Q | C |
| Avg Fwd Segment Size | None; duplicates forward payload mean | bytes | Redundant, not IPv4 mean | N | N | New | P,O | L | C |
| Avg Bwd Segment Size | None; duplicates backward payload mean | bytes | Redundant, not IPv4 mean | N | N | New | P,O | L | C |
| Fwd Header Length_duplicated_0 | None; duplicate transport-header sum | bytes | Exclude duplicate | N | N | New | H | Q | C |
| Fwd Avg Bytes/Bulk | None; exporter-specific bulk average | payload bytes/bulk | No reliable conversion | N | N | New | B,P,O | Q | C |
| Fwd Avg Packets/Bulk | None; exporter-specific bulk average | packets/bulk | No reliable conversion | N | N | New | B,O | Q | C |
| Fwd Avg Bulk Rate | None; exporter-specific bulk rate | payload bytes/s | No reliable conversion | N | N | New | B,P,O | Q | C |
| Bwd Avg Bytes/Bulk | None; exporter-specific bulk average | payload bytes/bulk | Wrong getter risk; no reliable conversion | N | N | New | B,P,O | Q | C |
| Bwd Avg Packets/Bulk | None; exporter-specific bulk average | packets/bulk | No reliable conversion | N | N | New | B,O | Q | C |
| Bwd Avg Bulk Rate | None; exporter-specific bulk rate | payload bytes/s | No reliable conversion | N | N | New | B,P,O | Q | C |
| Subflow Fwd Packets | None; NOT whole-flow forward count | packets/subflow | Broken state/integer average | N | N | New | S,O | Q | C |
| Subflow Fwd Bytes | None; NOT native directional bytes | payload bytes/subflow | Broken state; no IPv4 conversion | N | N | New | S,P,O | Q | C |
| Subflow Bwd Packets | None; NOT whole-flow reverse count | packets/subflow | Broken state/integer average | N | N | New | S,O | Q | C |
| Subflow Bwd Bytes | None; NOT native directional bytes | payload bytes/subflow | Broken state; no IPv4 conversion | N | N | New | S,P,O | Q | C |
| Init_Win_bytes_forward | None; possible raw initial TCP window | unscaled window; -1 missing | New header retention/validity needed | N | N | New | V,O | Q | D |
| Init_Win_bytes_backward | None; purported initial TCP window | unscaled window; -1 missing | Historical last-window overwrite; defer | N | N | New | V,O | Q | D |
| act_data_pkt_fwd | None; positive L4-payload packet count | packets | Cannot repair missing first contribution | N | N | New | D,P,O | Q | C |
| min_seg_size_forward | None; min transport-header length, NOT MSS | bytes | Invalid negatives; no MSS conversion | N | N | New | H,O | Q | C |
| Active Mean | None; new policy-specific period mean | µs | Divide by 1e6 only after policy definition | N | N | New | I,T | Q | D |
| Active Std | None; new policy-specific sample std | µs | Divide by 1e6 only after policy definition | N | N | New | I,T | Q | D |
| Active Max | None; new policy-specific period maximum | µs | Divide by 1e6 only after policy definition | N | N | New | I,T | Q | D |
| Active Min | None; new policy-specific period minimum | µs | Divide by 1e6 only after policy definition | N | N | New | I,T | Q | D |
| Idle Mean | None; new policy-specific period mean | µs | Divide by 1e6 only after policy definition | N | N | New | I,T | Q | D |
| Idle Std | None; new policy-specific sample std | µs | Divide by 1e6 only after policy definition | N | N | New | I,T | Q | D |
| Idle Max | None; new policy-specific period maximum | µs | Divide by 1e6 only after policy definition | N | N | New | I,T | Q | D |
| Idle Min | None; new policy-specific period minimum | µs | Divide by 1e6 only after policy definition | N | N | New | I,T | Q | D |
| Label | No input equivalent; audit target only | category | Exclude model input | N | N | No | Labelling | X | E |

### Retained-validation consistency checks

These checks add no filtering, repair, imputation, or duplicate removal. Numeric comparisons use `rtol=1e-6, atol=1e-6` except the Down/Up difference check (`>1e-6`).

| Check | Rows |
| --- | ---: |
| Supplied Down/Up Ratio differs from exact B/F | 128,461 |
| Forward payload mean differs from P_f/F | 0 |
| Backward payload mean differs from P_b/B, zero at B=0 | 38 |
| Global Packet Length Mean differs from (P_f+P_b)/N | 312,897 |
| Average Packet Size differs from (P_f+P_b)/N | 216,229 |
| Duplicate forward-header column differs from original | 0 |
| Forward/backward packet-rate disagreement with directional count/d | 0 / 0 |
| Negative Flow IAT Min, minimum -13 µs | 487 |
| Negative Fwd Header Length / Bwd Header Length | 11 / 5 |
| Negative min_seg_size_forward | 11 |
| Missing (-1) forward / backward initial windows | 190,373 / 237,036 |

All eight global flag columns are restricted to 0/1 on retained validation, with CWE entirely zero. This corroborates the published original-dataset defect; it does not prove a correctly counted single flag on every flow. The 38 backward mean discrepancies may reflect published numeric precision or other source issues; no causal attribution or correction was made. Negative gaps prove a nonnegative-gap assumption would require a stated policy, rather than silent clipping.

## 5. Leakage analysis

- **Exclude actual identifiers:** Destination Port is a real header value, but offers an especially direct FTP/SSH service/simulation shortcut. Label is the target. Both are excluded.
- **Do not restore missing identifiers:** Flow ID, Source IP, Destination IP, Source Port, Protocol, and Timestamp are absent from this 79-column MachineLearning subset. Absolute timestamps/day/source filename/source ordinal would encode scenario or split information. Protocol is legitimate metadata in the engine, but not a recoverable column here; it must not be inferred from labels or service ports.
- **Audit metadata stays outside features:** validation `source_file`, `source_line`, label, capture day, model artifact directory, and export reason are provenance/diagnostic data, not model inputs.
- **Exporter leakage:** flag markers, duplicated size moments, appendices after premature FIN retirement, disabled bulk/subflow logic, and invalid header lengths can distinguish tool behavior instead of malicious behavior. Apparent collision gains from these fields do not approve them.
- **OS/application shortcuts:** raw TCP windows and advertised-header details can fingerprint the client/attack tool. They are not needed for the initial minimal proposal.
- **Timing risks:** relative gaps avoid absolute-time identity, but can still learn the lab attack cadence and capture/loss conditions. Preserve capture-day separation; do not use test evidence to select gap conventions or features.
- **Analysis labels are used only to count mixed groups.** No threshold, feature-ranking search, model selection, or predictive evaluation was performed. These design diagnostics belong to validation; they must not be presented as an unbiased held-out result.

## 6. Proposed Feature Set v2 — nine gated dimensions

The proposal is deliberately small. It retains the three v1 inputs for a controlled future comparison, adds one direction-count axis, two size/byte axes, two genuine TCP axes, and one timing-variability axis. It is an **engine-native design**, not approval to concatenate nine legacy CIC columns.

In the formulas below, `n`, `f`, `r`, `b`, `b_f`, and `b_r` are native total/directional packet and IPv4 byte counters. Zero denominators produce zero as explicitly specified; real v1 flows contain an observed creation packet.

| Proposed feature | Authoritative formula and unit | Why it belongs | Availability / gate |
| --- | --- | --- | --- |
| `duration_seconds` | Existing emitted duration, seconds | Lifespan/pacing; preserve v1 comparison | Native v1; CIC µs conversion applies only to its own row/window |
| `packet_count` | Existing n; CIC F+B, packets | Observed flow volume, robust to whole-direction reversal | Native v1 and current CIC projection |
| `packets_per_second` | Existing emitted rate, packets/s | Preserve baseline throughput axis for controlled comparison | Native v1 and current validated CIC projection; redundant with n/d |
| `minor_direction_packet_fraction` | min(f,r)/n, or 0; dimensionless [0,0.5] | Reply/bidirectionality balance without assuming client orientation | Derived from v1; conditional CIC min(F,B)/N; individual direction-assignment defects still need evidence |
| `mean_ipv4_packet_bytes` | Existing `bytes_per_packet`, IPv4 bytes/packet | Size behavior under native header-inclusive accounting | Already native v1; **not honestly recoverable from current Parquet** |
| `ipv4_direction_byte_imbalance` | abs(b_f-b_r)/b, or 0; dimensionless [0,1] | Directional volume asymmetry independent of endpoint reversal | Derived from native v1 bytes; **not honestly recoverable from current Parquet** |
| `syn_packet_fraction` | Existing syn_count/n, or 0; dimensionless [0,1] | Observed SYN-bearing traffic density, including SYN-ACK, not invented attempts | Derived from native v1; **legacy CIC marker unusable** |
| `fin_packet_fraction` | Existing fin_count/n, or 0; dimensionless [0,1] | Observed teardown-control traffic without changing termination | Derived from native v1; **legacy CIC marker unusable** |
| `flow_iat_std_seconds` | Sample std of consecutive accepted-packet capture-time gaps, seconds | Burstiness not determined by duration and count | **Not aggregated/exported**; independent additive contract required; CIC Flow IAT Std/1e6 only after convention/window verification |

Eight dimensions can be copied or derived from existing native v1 observations. Only the IAT dimension needs additional engine state/export, after separate authorization. None requires redefining IPv4 bytes, direction, packet acceptance, or flow retirement.

**Timing design gate:** define gaps `g_i=t_i-t_(i-1)` over accepted packets in observation order and distinguish their previous-arrival timestamp from existing `last_seen`. For `m` gaps, sample std is `sqrt(sum((g_i-mean(g))²)/(m-1))` for `m≥2`. Empty/one-gap behavior, signed late gaps versus invalidity, timestamp precision, non-TCP coverage, and a missing/validity representation must be settled before export or training. Do not clamp negative timestamps or sort packets silently. No IAT definition was added to production here.

The retained throughput dimension is explicitly correlated. This proposal avoids adding every directional rate, bytes/s, IAT mean, variance/std pair, or repeated payload/segment mean. A later authorized comparison should predeclare whether throughput is retained or ablated; this investigation makes no model-performance selection. Native RST density is a plausible future alternative to FIN density, but neither a replacement nor an additional dimension was selected using validation model scores.

### Expected benefit and present readiness

The intended benefit is independent information about response balance, packet size, directional volume, TCP control behavior, and burstiness. The only currently calculable count-only expansion offers a modest collision improvement; it is not sufficient evidence to claim useful low-FPR recall. Size/timing proxies suggest materially richer discrimination may be possible, but do not quantify a deployable native-v2 benefit.

There is no honest, fully compatible 8–15-dimensional training matrix in the available legacy Parquet. A complete engine-native feature set cannot be inferred from missing header information and broken flags. This is a measurement/provenance blocker, not permission to change the engine semantics to match CICFlowMeter.

## 7. Rejected and deferred features

- **All raw length/byte/rate columns as IPv4 measurements:** incompatible byte accounting; no fixed-offset conversion. Payload means may be useful as separately named future measurements, but are not aliases for native byte fields.
- **Global packet-size mean/std/variance and Average Packet Size:** duplicated first-packet contribution in historical source, empirical disagreements, and payload versus IP mismatch. Min/max avoid the duplication's numeric effect but still use the wrong byte vocabulary.
- **All supplied TCP flag columns, including directional PSH/URG:** broken legacy markers. ACK additionally has a different intended definition. PSH/URG/CWR/ECE have no native aggregate/export.
- **Down/Up Ratio:** truncated integer division, unverified orientation, unbounded ratio; use count-derived symmetric balance instead.
- **Fwd/Bwd Packets/s:** potentially compatible after gates, but already determined by n, d, and the count-balance feature; do not add redundant dimensions.
- **Directional IAT mean/std/min/max/totals:** no existing native state; additional orientation concerns; unnecessary expansion before one all-packet variability dimension is specified. Flow IAT mean is also largely determined by duration and count on ordered packets.
- **Active/idle moments:** policy-specific state and version/end-window uncertainty, with potential clock/schedule leakage; not equivalent to native duration or retirement reason.
- **Header lengths, duplicated column, minimum segment size:** transport-header vocabulary, invalid values, redundancy, and OS/tool fingerprints; not native byte measurements or TCP MSS.
- **Bulk/subflow features:** damaged/exporter-specific state and rounding; absent native definitions. Coincidentally equal packet totals do not establish semantic compatibility.
- **Initial TCP windows:** parser/export gaps, missing/scaling issues, backward overwrite, and OS/tool shortcuts; defer.
- **act_data_pkt_fwd:** first-packet omission and L4-payload mismatch; defer a distinctly defined measurement rather than reusing `payload_length`.
- **Identifiers/labels, derived attack labels, fabricated handshake/connection fields:** excluded. Do not infer protocol or TCP handshake completion from service/label information.

## 8. Validation-only collision analysis

### Population and calculation

Read only:

1. Prepared `dataset_manifest.json`.
2. Prepared `validation_features.csv` and `validation_metadata.csv`.
3. Raw `Tuesday-WorkingHours.pcap_ISCX.csv.parquet` (445,909 rows, 79 columns).

Prepared metadata's existing one-based `source_line` aligns each of the 421,610 retained rows to its raw Parquet ordinal. Every label and all three projected v1 values match. No re-preparation, row deletion, new keep-mask, re-deduplication, or repair was performed. Tuesday raw SHA-256 and prepared validation artifact hashes match the manifest.

For a feature matrix with N retained rows, a unique vector ignores labels; a collision group has multiplicity ≥2; excess rows are `N - unique_vectors`; mixed groups contain more than one label; mixed-label rows count **all** rows in those groups. Shared attack rows specifically require a BENIGN row with the same vector. Counts use exact float64 tuple equality, not tolerances or rounded bins. The companion also reports exact equality after casting the complete matrix to float32; no model is invoked.

### Matrices actually measured

Let `S4` be v1 plus `min(F,B)/N`.

- **V1 (3):** existing prepared matrix, unchanged.
- **Conditional count/time expansion (4):** S4. These are calculable count projections on CIC's existing rows; native window and within-flow orientation parity remain gated.
- **Payload proxy (6):** S4 plus `(P_f+P_b)/N` and `abs(P_f-P_b)/(P_f+P_b)` (zero at zero payload). These are explicitly L4-payload proxies, **not** the proposed IPv4 size features.
- **Payload + timing proxy (7):** payload proxy plus `Flow IAT Std/1e6`. This is a legacy CIC timing observation, not a currently exported native statistic.
- **Legacy-marker negative control (9):** timing proxy plus supplied `SYN Flag Count/N` and `FIN Flag Count/N`. This deliberately measures how damaged markers could make collisions look better. It is **rejected**, never an approved v2 matrix.

| Matrix, float64 | Features | Unique vectors | Collision groups | Excess rows | Mixed-label groups | Mixed-label rows | Attacks sharing BENIGN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| V1 prepared | 3 | 222,544 | 22,093 | 199,066 | 388 | 71,607 | 2,186 |
| Conditional count/time expansion | 4 | 226,484 | 22,582 | 195,126 | 396 | 64,444 | 2,135 |
| L4-payload proxy — not native v2 | 6 | 313,044 | 15,988 | 108,566 | 145 | 34,035 | 219 |
| L4-payload + CIC-IAT proxy — not native v2 | 7 | 339,731 | 10,447 | 81,879 | 141 | 33,968 | 213 |
| Rejected legacy-marker negative control | 9 | 340,196 | 10,455 | 81,414 | 141 | 33,834 | 213 |
| Genuine proposed engine-native v2 | 9 | Not measurable | Not measurable | Not measurable | Not measurable | Not measurable | Not measurable |

The genuine proposal's statistics are `null` in JSON with a missing-measurement explanation. **The proxy figures must not be relabelled as genuine Feature Set v2 collision counts or bounds.** IP headers, native windows, and all-packet flag counts can change the partitions in ways these summaries do not determine.

| Matrix, float32 | Unique vectors | Collision groups | Excess rows | Mixed-label groups | Mixed-label rows | Attacks sharing BENIGN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| V1 prepared | 222,406 | 22,201 | 199,204 | 388 | 71,607 | 2,186 |
| Conditional count/time expansion | 226,350 | 22,686 | 195,260 | 396 | 64,444 | 2,135 |
| L4-payload proxy | 312,931 | 16,074 | 108,679 | 145 | 34,035 | 219 |
| L4-payload + CIC-IAT proxy | 339,623 | 10,528 | 81,987 | 141 | 33,968 | 213 |
| Rejected legacy-marker negative control | 340,088 | 10,536 | 81,522 | 141 | 33,834 | 213 |

Shared attack rows by family, float64 (same counts for float32):

| Matrix | FTP-Patator | SSH-Patator | Fraction of all validation attacks |
| --- | ---: | ---: | ---: |
| V1 | 1,944 | 242 | 23.8907% |
| Conditional count/time expansion | 1,906 | 229 | 23.3333% |
| Payload proxy | 11 | 208 | 2.3934% |
| Payload + timing proxy | 10 | 203 | 2.3279% |
| Rejected legacy-marker negative control | 10 | 203 | 2.3279% |

**Interpretation:** the count-only addition reduces affected mixed rows by 7,163 (10.0%) and shared attack rows by only 51 (2.33%). Mixed-group count rises from 388 to 396 because an existing mixed group can split into several smaller mixed groups; this does not contradict the lower affected-row count. Total collision-group counts can similarly rise while excess rows fall.

The payload/timing proxy reduces shared attack rows from 2,186 to 213 and mixed-label rows to 33,968, suggesting value in genuinely richer observations. It also changes the remaining collision burden toward SSH. This is representation evidence only. It does not measure recall, FPR, ranking quality, native-engine parity, label correctness, or model generalization. The rejected flag markers remove a few more mixed rows but no additional shared attack rows; their cosmetic collision gain does not rehabilitate their semantics.

## 9. Provenance and unchanged-state evidence

- Prepared dataset: `/run/media/rayan/Workspace/08_Datasets/cicids2017/prepared/intriqo-cicids2017-monday-wednesday`.
- Manifest SHA-256: `058b30c536c2794db67cad21374921abf1137a4129297e35bc9ae27dfd61555f`.
- Validation source: `/run/media/rayan/Workspace/08_Datasets/cicids2017/machine_learning/Tuesday-WorkingHours.pcap_ISCX.csv.parquet`.
- Raw validation SHA-256: `9fda00044283648f09ce6257a6bddc39c4e3a967d7a609ff808247727a4fcabb`.
- V1 artifact directory: `/run/media/rayan/Workspace/08_Datasets/cicids2017/prepared/intriqo-cicids2017-isolation-forest`.
- One-off calculation evidence: `/tmp/opencode/intriqo-feature-v2-measure.py` and `/tmp/opencode/feature-v2-measurements.json`. These are investigation scratch files, not an installed feature pipeline or model implementation.
- File-open evidence: `/tmp/opencode/feature-v2-investigation-open.trace`. It records Tuesday Parquet, prepared validation CSVs, manifest, and read-only integrity hashing of original artifacts; it contains no Wednesday Parquet, real test feature CSV, or real test metadata/label CSV open. Hashing `model.joblib` for immutability is not deserializing or scoring a model.
- Before/after hashes match for 56 protected files: all existing external v1 artifacts/diagnostics, C++ extraction/runtime/header sources, v1 feature schema/parser, preparation/mapping code, and baseline model implementation. Full hashes and inspected external-source hashes are retained in JSON.

The manifest is shared split metadata; reading its declared filenames/hashes did not open test feature/label data. No training split data were needed. Existing unrelated workspace changes were preserved.

## 10. Existing tests and checks

No new production code or tests were added. Existing checks were run against the unchanged implementation:

```sh
control-plane/.venv/bin/python -m pytest -q \
  ml/tests/unit/test_flow_features.py \
  ml/tests/unit/test_dataset_pipeline.py \
  ml/tests/integration/test_cpp_feature_stream.py \
  -c ml/pyproject.toml --strict-markers \
  --junitxml=/tmp/opencode/feature-v2-existing-tests.xml

ctest --test-dir build/flow-release --output-on-failure \
  -R '^(FlowKey|NetworkFlow|FlowTable|FlowFeatures|FlowFeatureRecord|FlowFeatureSink|FlowFeaturePipeline|FlowFeatureLifecycle|IPv4Parser|Capture\.Pcap|HardeningFlow)\.'
```

- **430 Python tests passed**, no failures, skips, or xfails. These exercise strict v1 parsing/schema, synthetic dataset preparation, and synthetic PCAP C++→JSONL→Python integration, not the held-out CIC dataset.
- **54 existing C++ tests passed**, including native direction/late-time state, byte/flag extraction, serialization, retirement, sinks, and parser behavior. No failures.
- Deliverable validation passed: all 79 fields are covered exactly once, proposal/CSV population provenance agrees, collision identities hold, and all 56 protected hashes remain equal. `git diff --check` and whitespace checks of both new deliverables passed.

## 11. Recommended next implementation steps

1. Review and approve the nine target definitions, conditional mapping gates, and rejection decisions before authorizing implementation.
2. Establish separately stored, **validation-only Intriqo-native** observations from the original validation capture, if available, using the existing parser, direction, and retirement behavior. A CIC-row/native-flow label alignment policy must be explicit: existing CIC labels do not automatically label differently segmented native flows. Do not force 120-second/FIN retirement into C++ to obtain row identity.
3. Specify an independent additive contract for IAT sample statistics, missing/validity, empty/one-gap behavior, and late-packet handling. Keep FlowFeatureRecord v1 and SecurityEvent frozen. Do not silently alter byte accounting or existing `last_seen` behavior.
4. After separate authorization, build typed projections and native packet-level fixtures for IPv4 options, TCP header options, direction reversal, mixed flag combinations, short/zero-duration flows, reordered timestamps, loss/truncation, and all three retirement reasons. Record extractor/version/configuration provenance.
5. Preserve the existing prepared population/duplicate policy and all v1 artifacts. New native observations need their own explicit version/provenance, not an overwrite of v1 data. Report measurement coverage and actual native collision counts before model work.
6. Only after those gates, separately predeclare a validation-only model experiment, feature correlation/ablation policy, and operating-point objectives. No test-driven selection. Any held-out evaluation requires explicit later authorization.

**Stop point:** this investigation is complete. No Feature Set v2 implementation, model training, v1 threshold modification, or held-out test access was performed.
