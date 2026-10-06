# CIC-IDS2017 authoritative PCAP reconstruction

## CIC-IDS2017 Native-v2 Experiment: BLOCKED

**Frozen research state (2026-10-06):**

| gate | frozen state |
|---|---|
| **IMPLEMENTATION COMPLETE** | The native Intriqo v2 implementation and controlled PCAP prototype remain valid and independently tested. This freeze does not modify v1 or native v2. |
| **DATA ACQUISITION BLOCKED** | Authoritative Monday/Tuesday PCAPs could not be obtained from the currently available official CIC/UNB distribution surface. The available CIC-IDS2017 Parquet data remains for exploratory/legacy analysis only; it is not native-v2 packet evidence or a label source. |
| **MODEL TRAINING BLOCKED** | No CIC-IDS2017 v2 model was trained and no v2 validation metrics exist. |
| **TEST EVALUATION SEALED** | Wednesday remains sealed: it was not opened, reconstructed, used for feature generation, or evaluated. |

The exact official sources and findings are retained in the [Raw PCAP
Acquisition Investigation](#raw-pcap-acquisition-investigation):

- `https://www.unb.ca/cic/datasets/ids-2017.html` — authoritative landing
  page; documents the dataset and points to the official distribution surface,
  but publishes no raw-PCAP hash manifest.
- `https://cicresearch.ca/CICDataset/CIC-IDS-2017/` — authoritative download
  form; HTTP 200 HTML displaying `Server error. Please try again later`.
- `https://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/PCAPs/Monday-WorkingHours.pcap`
  and
  `https://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/PCAPs/Tuesday-WorkingHours.pcap`
  — both redirect HTTP 302 to the UNB dataset index and return HTML rather
  than packet data.

Unofficial and secondary PCAP mirrors were deliberately rejected: no
independently comparable official CIC/UNB hash or provenance chain was
available. Native Intriqo v2 reconstruction therefore cannot be scientifically
validated against CIC-IDS2017 at this time.

This research track may resume only when authoritative Monday/Tuesday PCAPs
become available, or when a binary artifact with verifiable provenance and an
independently comparable official hash is obtained. Until then, v1 remains
frozen, native v2 remains unchanged, and this track remains blocked.

## Decision gate

**BLOCKED_ON_DATA_ACQUISITION** (2026-10-06).

The local corpus contains eight CICFlowMeter-derived Parquet files and no
CIC-IDS2017 raw PCAP. The Parquet files remain available for exploratory and
legacy analysis only. The authoritative download surface is currently gated by
a form that displays `Server error. Please try again later`; direct Monday and
Tuesday PCAP paths redirect to the UNB dataset index. No raw capture was
downloaded, no third-party PCAP mirror was substituted, and no CIC-IDS2017
native-v2 dataset, labels, metrics, or model were produced.

## Local inventory

Inventory was collected from `/run/media/rayan/Workspace/08_Datasets/cicids2017`
using filesystem metadata, `file`, SHA-256, and Parquet footer metadata. The
Parquet files were not converted into native flows or used for label joins.

| filename | path | bytes | SHA-256 | type | native packet reconstruction |
|---|---|---:|---|---|---|
| `Monday-WorkingHours.pcap_ISCX.csv.parquet` | `machine_learning/Monday-WorkingHours.pcap_ISCX.csv.parquet` | 57011041 | `fd6f986b33712f1986e6057c60f88b729d6e39a93bd107a6b0a53ae33958a22e` | Apache Parquet; 79 CICFlowMeter columns; 529,918 rows | **No** |
| `Tuesday-WorkingHours.pcap_ISCX.csv.parquet` | `machine_learning/Tuesday-WorkingHours.pcap_ISCX.csv.parquet` | 45553171 | `9fda00044283648f09ce6257a6bddc39c4e3a967d7a609ff808247727a4fcabb` | Apache Parquet; 79 CICFlowMeter columns; 445,909 rows | **No** |
| `Wednesday-workingHours.pcap_ISCX.csv.parquet` | `machine_learning/Wednesday-workingHours.pcap_ISCX.csv.parquet` | 67414946 | `3dd43daf2148052d76c2b8daa742a911e066c4d3cd4ba4ce933e53ccd1544592` | Apache Parquet; 79 CICFlowMeter columns; 692,703 rows | **No** |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet` | `machine_learning/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet` | 17249369 | `86ccdefdcd9c85e5d8fa159412d7402a66e97b9d9453c17de0156ac0c6999cc7` | Apache Parquet; 79 CICFlowMeter columns; 170,366 rows | **No** |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv.parquet` | `machine_learning/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv.parquet` | 24090104 | `453bcb6400cf1cff4bd00404a3134f23e28b8541c7346566d984c733f3e62362` | Apache Parquet; 79 CICFlowMeter columns; 288,602 rows | **No** |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet` | `machine_learning/Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet` | 19352181 | `e3cb0a243142fca1cfe0cd69437fa930a047f550c71353d34afbf618bd120427` | Apache Parquet; 79 CICFlowMeter columns; 191,033 rows | **No** |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet` | `machine_learning/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet` | 15688379 | `a49a5f5230ef15fbd60079a93db12c5a549913dfed66a142592c27c7264b08d7` | Apache Parquet; 79 CICFlowMeter columns; 286,467 rows | **No** |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet` | `machine_learning/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet` | 22188516 | `022ab31ab239f07e11a6458ee771eea0317a001d68398242cb36f5a4be66f972` | Apache Parquet; 79 CICFlowMeter columns; 225,745 rows | **No** |

Total local machine-learning Parquet size is 268,547,707 bytes. The files
contain a `Label` column, but their schema has no timestamp, source IP,
destination IP, source port, flow identifier, or packet-level record. Their
columns include CICFlowMeter payload-byte, flow-boundary, and flag-derived
measurements; they cannot establish native Intriqo packet or flow identity.

No `.pcap`, `.pcapng`, `.cap`, or archive containing a raw capture exists under
the local CIC-IDS2017 dataset root. The repository contains only controlled or
benchmark PCAP fixtures, not CIC-IDS2017 captures.

The local Hugging Face cache contains an older tree metadata record that names
large `pcap/Monday-WorkingHours.pcap` and `pcap/Tuesday-WorkingHours.pcap`
objects, but those objects are absent from the filesystem. The current
Hugging Face tree API exposes CSV/ZIP files and direct guessed PCAP paths return
404. Cache metadata is therefore not treated as acquired packet data.

### Existing prepared artifacts

The frozen prepared artifact at
`/run/media/rayan/Workspace/08_Datasets/cicids2017/prepared/intriqo-cicids2017-monday-wednesday`
records the historical split Monday → `train_normal`, Tuesday → `validation`,
and Wednesday → held-out `test`. Its manifest explicitly records that the
three-feature projection does not map CICFlowMeter payload bytes to Intriqo
IPv4 totals. The existing Isolation Forest artifacts are v1/diagnostic
artifacts and remain untouched. These files are not native-v2 evidence.

## Required authoritative captures

The minimum captures for the intended experiment are:

- `Monday-WorkingHours.pcap` — 2017-07-03, normal activity, benign training.
- `Tuesday-WorkingHours.pcap` — 2017-07-04, FTP/SSH Patator plus normal activity,
  validation.

`Wednesday-workingHours.pcap` is the future held-out test capture, but it was
not acquired, opened, replayed, or evaluated in this milestone. Thursday and
Friday are not needed for the current Monday/Tuesday train/validation design.

The official page describes the complete daily captures as Monday through
Friday and identifies Monday as normal-only. It also documents the published
attack schedule, network topology, NAT path, and the fact that the CSV flows
were labeled using timestamp, source/destination IPs, ports, protocol, and
attack information. This establishes candidate alignment signals, not proof
that those CICFlowMeter flow rows are equivalent to Intriqo flows.

## Source verification

| source | authority | retrieval/status | use |
|---|---|---|---|
| [UNB CIC-IDS2017 page](https://www.unb.ca/cic/datasets/ids-2017.html) | **AUTHORITATIVE** | Retrieved successfully | Dataset identity, daily files/sizes, dates, schedules, topology, NAT details, label/CSV description |
| [CIC research download surface](https://cicresearch.ca/CICDataset/CIC-IDS-2017/) | **AUTHORITATIVE distribution surface** | HTTP 200, but form displays `Server error. Please try again later` | Official acquisition entry point; no file obtained |
| Direct official Monday PCAP path | **AUTHORITATIVE distribution surface** | Initial HTTP 302 to `https://www.unb.ca/cic/datasets/index.html`, final response is HTML, not PCAP | Acquisition attempt only |
| Direct official Tuesday PCAP path | **AUTHORITATIVE distribution surface** | Initial HTTP 302 to `https://www.unb.ca/cic/datasets/index.html`, final response is HTML, not PCAP | Acquisition attempt only |
| [CIC-IDS2017 paper](https://www.scitepress.org/papers/2018/66398/66398.pdf) | **AUTHORITATIVE publication** | Headers: HTTP 200, `application/pdf`, 436,523 bytes, `Last-Modified: Tue, 13 Aug 2019 08:29:47 GMT`; PDF was not downloaded | Dataset methodology/context |
| [Mireu-Lab Hugging Face dataset](https://huggingface.co/datasets/Mireu-Lab/CIC-IDS) and [current tree API](https://huggingface.co/api/datasets/Mireu-Lab/CIC-IDS/tree/main?recursive=true&expand=false) | **SECONDARY** | Retrieved; current tree exposes CSV/ZIP files, not raw PCAP; direct guessed PCAP paths return 404 | Explains local secondary tabular provenance; not accepted for native reconstruction |
| [CNS2022 improved dataset](https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/) and [labeling code](https://github.com/GintsEngelen/CNS2022_Code) | **SECONDARY** | Retrieved; improved CICFlowMeter flow data/labeling research, not an authoritative raw-PCAP source | Documents known flow/label caveats; not used as native labels |

No official SHA-256 manifest for the raw PCAPs was found on the authoritative
UNB page or download surface. Secondary hashes cannot independently authenticate
a raw capture against the official distribution. No questionable mirror was
downloaded.

## Raw PCAP Acquisition Investigation

Investigation retrieval date: **2026-10-06 UTC**. No registration form was
submitted and no binary PCAP was downloaded. The required outcome for this
milestone is **OFFICIAL_SOURCE_CURRENTLY_UNAVAILABLE**: the official source is
identified, but its current download path did not provide the files.

### Official endpoints and linked resources checked

| URL | source type / authority | observed HTTP/content behavior | result |
|---|---|---|---|
| `https://www.unb.ca/cic/datasets/ids-2017.html` | dataset landing page; **AUTHORITATIVE** | HTTP 200; `text/html; charset=UTF-8`; 75,847 bytes; `Last-Modified` observed as 25 Mar 2026 | Documentation only. The only dataset download link is the CIC research download surface; no direct file URLs or hashes are published here. |
| `https://www.unb.ca/cic/datasets/index.html` | official catalog/FAQ; **AUTHORITATIVE** | HTTP 200 HTML | Confirms the short registration form, says CIC has no file-level CSV/PCAP information, permits redistribution/mirroring with citation, and points users back to the dataset page. No alternative CIC-IDS2017 file endpoint is listed. |
| `https://cicresearch.ca/CICDataset/CIC-IDS-2017/` | official download form; **AUTHORITATIVE distribution surface** | HTTP 200; `text/html`; 10,535 bytes; `Last-Modified: Sat, 21 Feb 2026 23:06:02 GMT`; page displays `Server error. Please try again later`; form action is `insert.php` | Blocked before registration. The page exposes no files or checksums. |
| `https://cicresearch.ca/CICDataset/CIC-IDS-2017/browse.php` | post-registration browser; **AUTHORITATIVE distribution surface** | HTTP 403 to an unauthenticated GET | Not used; no session or credentials were supplied. |
| `https://cicresearch.ca/CICDataset/CIC-IDS-2017/insert.php` | registration handler; **AUTHORITATIVE distribution surface** | HTTP 405 to a GET | Not submitted; a POST would require personal registration fields and was intentionally not attempted. |
| `https://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/PCAPs/Monday-WorkingHours.pcap` | legacy official file URL | HTTPS request: HTTP 302 to `https://www.unb.ca/cic/datasets/index.html`; followed response HTTP 200 HTML, 108,784 bytes, not a PCAP | Unavailable. No file size or MIME for the desired binary was returned. |
| `https://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/PCAPs/Tuesday-WorkingHours.pcap` | legacy official file URL | Same HTTP 302 to the UNB index and final HTML response | Unavailable. |
| `http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/PCAPs/{Monday,Tuesday}-WorkingHours.pcap` | legacy IP form of official distribution URL | HTTP 301 to the HTTPS `cicresearch.ca` URL, then the same 302/HTML result | Not a distinct alternative source. |
| `https://www.unb.ca/cic/about/contact.html` | institutional contact; **AUTHORITATIVE** | HTTP 200 HTML | Explicit contact is `cic@unb.ca`; no contact request was sent. |
| `https://www.yorku.ca/research/bccc/ucs-technical/cybersecurity-datasets-cds/` | official-page-linked catalog; **OFFICIAL-LINKED** | HTTP 200 HTML | Links the derived BCCC-CIC-IDS2017 page; not an original PCAP endpoint. |
| [CICFlowMeter](https://github.com/ISCX/CICFlowMeter) | official-page-linked software | GitHub source repository | Not a PCAP source. |
| [BCCC-CIC-IDS2017](https://www.yorku.ca/research/bccc/ucs-technical/cybersecurity-datasets-cds/intrusion-detection-dataset-bccc-cic-ids2017/) | official-page-linked York University derived dataset; **OFFICIAL-LINKED**, not authoritative for original PCAPs | HTTP 200 HTML; offers a dataset request form | Explicitly describes a new CSV dataset generated with NLFlowLyzer from CIC-IDS2017 traffic, not the original Monday/Tuesday PCAPs. No request was submitted. |

The official page therefore identifies the original distribution but does not
currently expose a working unauthenticated binary endpoint or an official hash
manifest. The official catalog explicitly says that CIC does not have file-level
information beyond the released documents and recommends contacting researchers
when questions remain.

### Secondary and archival candidates

These candidates were checked only for provenance analysis. None was downloaded
or used for reconstruction, labels, or model work.

| candidate | classification | reported Monday/Tuesday evidence | why it is not an authenticated source |
|---|---|---|---|
| [bencorn/CICIDS2017](https://huggingface.co/datasets/bencorn/CICIDS2017) | **SECONDARY** (self-described unofficial mirror) | `pcaps/Monday-WorkingHours.pcap`: 10,822,507,416 bytes, reported LFS SHA-256 `f6eac599358f216b074338813a1cf7be3cc4e91d116e13efc0dc71f2cca11972`; `pcaps/Tuesday-WorkingHours.pcap`: 11,048,283,608 bytes, reported LFS SHA-256 `080c2250154c5a174c03660ed0f75a3858d41a27511ba716e780d7bcb1ec4c57`; HEAD redirects advertise `application/vnd.tcpdump.pcap` and the same sizes | README explicitly says “Unofficial mirror” and “not the original distribution.” No official hash comparison exists; no PCAP magic/header, packet count, timestamps, or structural validation was performed. |
| [bvsam/cic-ids-2017](https://huggingface.co/datasets/bvsam/cic-ids-2017) | **UNVERIFIED** mirror claim | PCAP tree reports the same Monday and Tuesday size/hash pairs as bencorn and exposes `pcap/Monday-WorkingHours.pcap` and `pcap/Tuesday-WorkingHours.pcap` | Repository claims “original PCAPs,” but provides no CIC-issued provenance or independent hash comparison. The files were not downloaded or structurally inspected. |
| [rokibulroni/CIC-IDS-2017-Dataset](https://github.com/rokibulroni/CIC-IDS-2017-Dataset) | **SECONDARY** documentation/mirror project | `PCAPs/readme.md` lists the exact names and rounded sizes and links the old 205.174.165.80 URLs plus `.md5` paths | Git tree contains README files only in `PCAPs`; no PCAP or checksum blobs were present. Its links resolve to the unavailable official endpoint, so it supplies no independent binary or hash. |
| [Zenodo 10.5281/zenodo.7258579](https://zenodo.org/records/7258579) | **SECONDARY** research derivative | Published record contains `Payload_data_CICIDS2017.csv` (4,910,831,729 bytes, MD5 `6344cc6af3e086cf0fe21af4299e9513`) | The record says PCAPs were processed and labeled, but the downloadable file is a payload-feature CSV, not raw PCAP. |
| [Harvard Dataverse CIC-IDS-2017 V2](https://doi.org/10.7910/DVN/CLOC6H) | **SECONDARY** derived dataset | File list contains `CIC-IDS-2017-V2.csv` (1,853,272,954 bytes, MD5 `270f1e93eadf2bd1e46f51f675687913`) and a scaler | It is a normalized/extended CSV dataset by Abluva, not the original PCAP distribution. |
| [CNS2022 improved dataset](https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/) / [extended documentation](https://intrusion-detection.distrinet-research.be/WTMC2021/extended_doc.html) | **SECONDARY** research derivative | Documents analysis of original PCAPs and corrected flow labeling | Offers regenerated flow data and methodology, not an authenticated copy of the original Monday/Tuesday binaries; its documented timing/flow corrections further disqualify direct label substitution. |
| [Arquivo.pt](https://arquivo.pt) | archival system | Exact official PCAP paths returned no CDX records; the UNB landing page has HTML captures (for example 2024-10-11, MIME `text/html`, indexed length about 10.8 KB) | Archive contains the landing page only for the checked evidence, not the binary PCAPs. |
| [Internet Archive Wayback](https://web.archive.org) | archival system | Exact Monday CDX query returned `[]` with HTTP 200; a Tuesday query encountered the service's “Temporarily Offline” page; an exact timestamp replay probe returned 404 | No binary snapshot was retrieved. The Tuesday result is inconclusive because the archive service was unavailable, not evidence that no snapshot ever existed. |

The secondary PCAP mirrors are useful leads for a future provenance request,
but their reported LFS hashes are hashes of mirror objects, not hashes issued
by CIC/UNB. A matching file size, filename, MIME label, or PCAP header would not
by itself establish identity with the official capture. Consequently both
Monday and Tuesday remain **PCAP_AVAILABLE_BUT_PROVENANCE_UNVERIFIED** only as
mirror claims, not acquired inputs.

### Acquisition conclusion

| required file | status | authority | provenance verified |
|---|---|---|---:|
| `Monday-WorkingHours.pcap` | `OFFICIAL_SOURCE_CURRENTLY_UNAVAILABLE`; secondary mirror claims exist but were not acquired | Official UNB/CIC endpoint identified; bencorn secondary; bvsam unverified | **false** |
| `Tuesday-WorkingHours.pcap` | `OFFICIAL_SOURCE_CURRENTLY_UNAVAILABLE`; secondary mirror claims exist but were not acquired | Official UNB/CIC endpoint identified; bencorn secondary; bvsam unverified | **false** |

No legitimate, provenance-verified PCAP was found in this bounded
investigation. The correct next step is to obtain a binary from the official
CIC/UNB distribution or a mirror with a verifiable chain to an official
artifact and an independently comparable hash. Until then, the scientific gate
remains **BLOCKED_ON_DATA_ACQUISITION**.

## Acquisition result

The authoritative surface was checked without submitting registration or
personal information. The root returned HTTP 200 and the form page contained
the server-error message. Direct requests for the minimum Monday and Tuesday
PCAPs returned HTTP 302 and redirected to the UNB dataset index; following the
redirect produced HTML rather than packet data. Therefore the required raw
captures are unavailable locally and acquisition is the blocking gate.

## Native replay and metadata audit

The existing engine can replay a classic PCAP through the real parser and flow
table with `--feature-schema flow_features.v2`. A v2 retirement record currently
provides:

- engine instance ID and native flow ID;
- first-seen and last-seen observation timestamps;
- export reason (`idle_expired`, `capacity_evicted`, or `shutdown_flush`);
- canonical creation-direction five-tuple: source/destination IPv4, ports, and
  protocol;
- native packet/byte totals, forward/reverse packet and IPv4-byte totals, TCP
  counters/handshake evidence, IAT policy/count, and the nine v2 features.

The native record does **not** provide packet-level timestamps, packet IDs,
capture filename/day, original link-layer identity, NAT translation evidence,
application/session identifiers, attack-label provenance, or a mapping to a
CICFlowMeter row. These missing fields are not needed to extract v2 features,
but they must be supplied or proven externally before label alignment can be
called reliable. Flow ID is engine-local and must not be joined across replay
processes without preserving the engine-instance ID and replay manifest.

## Label-alignment design (not executed)

No alignment tool was implemented because neither authoritative PCAPs nor an
independently verified packet-level label source is available. The design to
implement after acquisition is:

1. Replay one authoritative capture/day through the unchanged engine and retain
   every v2 JSONL record plus a replay manifest containing capture hash,
   parser/build hash, configuration, and engine instance ID.
2. Normalize authoritative label records to UTC only after the capture timezone
   and timestamp precision are verified. Preserve the original timestamp and
   source authority in every candidate.
3. Generate candidates using capture day, interval overlap/containment,
   protocol, both orientations of the native five-tuple, and verified NAT
   translation. Do not join on timestamp alone or on a five-tuple alone.
4. Treat a reused tuple as separate candidates according to native
   `first_seen`/`last_seen` and retirement boundaries. A native flow spanning an
   attack boundary, overlapping conflicting labels, or lacking a verified NAT
   interpretation is not auto-resolved.
5. Emit one of `BENIGN`, `ATTACK:<family>`, `UNKNOWN`, or `AMBIGUOUS`, together
   with `label_source`, `match_method`, `match_confidence/status`, and
   `ambiguity_reason`. `UNKNOWN` and `AMBIGUOUS` remain rows; they are never
   converted to `BENIGN`.

The authoritative UNB page's timestamp/IP/port/protocol labeling description is
useful as a candidate rule source, but it is still CICFlowMeter-derived flow
labeling. It cannot be copied onto native flows until the boundary, timezone,
direction, NAT, and label provenance are demonstrated on packet data.

Required controlled alignment tests before any dataset gate can advance:

- exact match and same tuple reused at different times;
- overlapping attack intervals and flows crossing an attack boundary;
- benign traffic during an attack window;
- missing, conflicting, duplicate, and unmatched label records;
- timezone offsets and timestamp precision differences;
- NAT/address translation ambiguity and reversed direction;
- retention of `UNKNOWN` and `AMBIGUOUS` without silent drops.

These tests are intentionally not claimed as passed: there is no authoritative
label input against which to run them.

## Split and scientific gate

The intended split remains unchanged:

- Monday: benign-only `TRAIN`;
- Tuesday: benign plus attacks `VALIDATION`;
- Wednesday: benign plus attacks sealed `TEST`.

No native-v2 train, validation, or test matrix was generated. No Wednesday
rows were opened for feature generation or metrics in this milestone. The
current scientific decision is **BLOCKED_ON_DATA_ACQUISITION**, not
`READY_FOR_NATIVE_V2_DATASET_BUILD` and not `BLOCKED_ON_LABEL_ALIGNMENT`.

The machine-readable receipt is
`ml/artifacts/feature-analysis/v2/cicids2017_reconstruction_status.json`.
It records the inventory, hashes, source authority, acquisition observations,
native metadata audit, alignment policy, and the sealed-test/model gates.

## 404 investigation

The previous broader E2E report included one HTTP 404 at the final task lookup
in the pre-existing C++ → Control Plane → Agents vertical-slice test. The v2
change set contains no Control Plane or Agents production changes. The failing
test was rerun in isolation and passed; the full E2E suite was then rerun and
passed **7 tests with 6 existing opt-in skips**. The observation was transient
and unrelated to native-v2 work, so no unrelated production behavior was
modified.

## Explicit stop conditions

Until the authoritative Monday/Tuesday PCAPs and a defensible native-flow label
source are available:

- no CICFlowMeter row is converted into a native v2 record;
- no native-v2 labels or matrices are created;
- no Isolation Forest v2, XGBoost model, threshold, ROC-AUC, PR-AUC, or other
  v2 validation metric is produced;
- the frozen v1 baseline and its artifacts remain unchanged;
- the held-out Wednesday test set remains sealed.
