# Native Intriqo v2 replacement dataset selection

**Selection date:** 2026-10-06
**Final status:** `BLOCKED_ON_IOT23_LABEL_ALIGNMENT`
**Primary:** CSE-CIC-IDS2018
**Fallback:** IoT-23
**Verification acquisition decision:** `BLOCKED_ON_IOT23_LABEL_ALIGNMENT`

## Scope and guardrails

This report selects a replacement dataset for a future experiment whose evidence
chain is:

```text
raw PCAP → Intriqo native packet parser → Intriqo flow tracker
          → native v2 features → independent ground truth → ML model
```

The primary CSE-CIC-IDS2018 remains metadata-only and blocked. One bounded
official-linked IoT-23 scenario was downloaded for the fallback integrity gate;
it was not unpacked, replayed, converted, labelled, or used for training. The
frozen CIC-IDS2017 track remains closed: its Parquet files are not used here,
Wednesday is not opened, and v1, native v2, and deterministic detectors are not
modified.

The grade is not a popularity score:

- **A — strong candidate:** public raw packets, independently documented truth,
  timestamps, research-use terms, and a defensible native-flow alignment plan.
- **B — usable with documented limitations:** the packet/truth chain is usable,
  but an important limitation remains in labels, topology, access, or scale.
- **C — poor fit:** useful for a narrower flow or anomaly study, but fails a
  central native-packet requirement.
- **D — reject:** cannot support this experiment without fabricating or
  importing a missing part of the evidence chain.

## Comparison

| Dataset | Raw PCAP | Independent labels | Timestamp quality | Label alignment feasibility | Attack diversity | Benign traffic | Provenance | License | Practical size | Intriqo compatibility | Grade |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **CSE-CIC-IDS2018** | Yes; official anonymous AWS S3 bucket contains daily `pcap.zip` archives | Schedule and machine logs are documented, but deterministic native alignment is currently blocked by missing clock, boundary, port, log, and negative-label semantics | PCAP capture time plus minute-resolution schedule; timezone/clock mapping is **UNRESOLVED** | **Blocked** until authoritative endpoint, time, protocol/port, archive, and benign-negative rules are available | Brute force, Heartbleed, botnet, DoS, DDoS, web attacks, infiltration | B-profile HTTP(S), SMTP, POP3, IMAP, SSH, FTP | CSE/CIC/UNB page plus official AWS Open Data registry and provider object metadata | Explicit redistribution/mirroring permission with citation and AWS link | Approx. 477 GB compressed original PCAP archives; daily archives observed at tens of GB | Classic PCAP, but Intriqo is IPv4-only; selective day/chunk replay is practical, full corpus is not | **A candidate / acquisition blocked** |
| **IoT-23** | Yes; 20 malicious and 3 benign scenario PCAPs; official Stratosphere/Zenodo archive | Partial: analyst-generated labels are in Zeek `conn.log.labeled`; not packet/interval truth independent of derived flows | Raw PCAP timestamps and Zeek timestamps; precision is available but capture clock needs audit | Medium: conservative overlap to labelled Zeek flow intervals is possible, but flow segmentation is not native Intriqo | Mirai, Torii, Okiru, Gagfyt, Hajime, Muhstik, Hide-and-Seek, IRCBot and related C&C/scan/DDoS behavior | Three real benign IoT devices: Hue, Echo, Somfy | Stratosphere page, Zenodo DOI/version, archive MD5, scenario manifests | CC BY 4.0 on the Zenodo record | 21.5 GB Zenodo full archive; individual scenarios are much smaller | Good for bounded IPv4 botnet replay; IoT scope and derived-flow labels limit generality | **B** |
| **UNSW-NB15** | Yes; official UNSW page links source PCAPs; capture described as 100 GB | Separate `UNSW-NB15_GT.csv` and event list exist, but their exact relation to packets and benign coverage needs verification | PCAP timestamps exist; official page does not fully specify clock/timezone semantics | Medium: five-tuple/time matching is plausible, but topology/NAT and ground-truth granularity are underdocumented | Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms | Hybrid real normal traffic plus synthetic attack traffic | UNSW first-party page and author-provided folder; no official PCAP hash manifest found | Academic research use granted in perpetuity; commercial use requires author agreement | About 100 GB raw traffic | Replayable classic PCAP candidate; access is a large SharePoint folder and native label audit is required | **B** |
| **CIC-DDoS2019** | Yes; official page states daily raw PCAPs and logs | Attack schedule is independent metadata; published CSV labels are explicitly CICFlowMeter-derived | PCAP timestamps plus schedule windows; exact capture boundaries/timezone require audit | Medium-high for DDoS interval/endpoint labels; spoofed reflection traffic complicates direction and replay | PortMap, NetBIOS, LDAP, MSSQL, UDP, UDP-Lag, SYN, NTP, DNS, SNMP, SSDP, WebDDoS, TFTP, PortScan | B-profile traffic from 25 users using HTTP(S), FTP, SSH, email | UNB/CIC project page and official download surface; no public hash manifest found | Explicit redistribution/mirroring permission with citation | Official page omits aggregate size; full two-day corpus is not assumed small | IPv4 replay likely practical in selected intervals; DDoS-only scope and spoofing are material limits | **B** |
| **TON_IoT** | Yes; official UNSW page states network PCAP, Zeek logs, and CSV | `SecurityEvents_GroundTruth_datasets` contains security events and timestamps; mapping to each raw PCAP must be verified | Event timestamps plus PCAP/Zeek timestamps; exact clock and timezone need audit | Medium-high if event records identify source IP/time for the same capture; ambiguity must remain explicit | Scanning, DoS, DDoS, ransomware, backdoor, data injection, XSS, password cracking, MITM | Normal IoT/IIoT, Windows, Linux, and service traffic | UNSW first-party page and SharePoint distribution; no published PCAP hash manifest found | Academic research use granted in perpetuity; commercial use requires author agreement | Size and per-capture inventory are not stated on the official page | Potentially good IPv4 testbed replay, but access, topology, and raw-event linkage require pre-download verification | **B** |
| **BoT-IoT** | Yes; official UNSW page states 69.3 GB PCAP and >72M records | Attack categories/subcategories are supplied with source files; independent packet/interval truth is not clearly published | PCAP timestamps available; official page does not specify clock semantics | Low-medium until category/file boundaries and capture schedule are independently tied to packets | DDoS, DoS, OS scan, service scan, keylogging, data exfiltration | Normal and botnet traffic in a cyber-range environment | UNSW first-party page and author-provided folder; no official PCAP hash manifest found | Academic research use granted in perpetuity; commercial use requires author agreement | 69.3 GB PCAP; 5% CSV subset is not a raw-packet substitute | Replayable, but labels risk collapsing into file/category metadata rather than independent truth | **C** |
| **CTU-13** | Only botnet-only PCAPs and truncated mixed PCAPs; complete mixed PCAPs are withheld for privacy | Manually labelled bidirectional Argus flows; not independent packet/interval truth for the public mixed capture | Scenario pages provide capture duration/times; public artifacts have packet timestamps | Low-medium: botnet-only packets can be replayed, but full benign/normal/background packet truth is unavailable | Neris, RBot, Virut, DonBot, Sogou, Murlo, NSIS.ay and botnet behaviors | Normal and background exist in labelled flows, not in a complete public mixed PCAP | Stratosphere/CTU first-party site; official CC BY and per-scenario metadata; no PCAP digest manifest found | CC BY 2.0 | 1.9 GB public bundle; not a complete mixed packet corpus | Useful botnet-only replay, not a defensible mixed benign/attack native experiment | **C** |
| **UGR'16** | No; official dataset is NetFlow v9, not raw PCAP | Interval/NetFlow labels and known injected attacks exist, but packets are absent | Long capture intervals and NetFlow timestamps are available | Native NetFlow alignment is possible; replay through packet parser is impossible | DoS, scans, botnet and other labelled ISP activity | Real ISP background traffic | University of Granada/NESG project and institutional repository; raw-data checksum/license is unclear | Paper record is CC BY-NC-ND 3.0 ES; raw-data terms are not clear | Large multi-month NetFlow archive; not a packet corpus | Cannot satisfy the raw PCAP → parser stage | **C** |
| **MAWI** | Yes; public tcpdump traces, usually payload-truncated and anonymized | MAWILab anomaly labels are detector-ensemble labels, not independent incident ground truth | Official trace metadata gives exact start/end and sub-ms target precision, with loss/asymmetry caveats | Low for ground-truth attack evaluation; packet-to-flow construction works, but labels are not authoritative attack truth | Open Internet anomalies rather than a stable attack-family taxonomy | Real backbone traffic, but not a clean benign control | WIDE/MAWI first-party archive and per-trace metadata; no published checksum manifest found | Research-only WIDE privacy terms | 15-minute examples are hundreds of MB compressed; archive is very large | Header replay is technically possible, but asymmetry, anonymization, payload removal, and IPv6 reduce fit | **C** |
| **CAIDA DDoS Attack 2007** | Yes; five-minute PCAPs, payload removed | Event-level curated DDoS window only; non-attack traffic was mostly removed and no clean benign truth exists | Exact UTC window 20:50:08–21:56:16, split into five-minute files | High for identifying the attack interval, low for benign/attack-family evaluation | One historical DDoS incident; vector taxonomy is not specified by the authoritative README | No useful benign baseline | CAIDA catalog, public README, and per-file MD5 manifest | CAIDA Acceptable Use Agreement; research/education/internal testing terms and publication reporting | 5.3 GB compressed / 21 GB uncompressed | Good parser smoke test, not a diverse native-v2 IDS experiment | **D** |

The table deliberately separates raw packet availability from label quality. A
PCAP plus a convenient CSV is not enough: the CSV must not be the only source of
truth for a native-flow experiment. Derived feature CSVs are neither labels nor
native v2 inputs.

## Primary recommendation: CSE-CIC-IDS2018 — Grade A

CSE-CIC-IDS2018 is selected because it is the strongest reviewed combination of

1. raw PCAPs from an official, publicly listable CIC/CSE AWS bucket;
2. an independently described attack schedule and per-machine logs rather than
   only a derived feature table;
3. a documented enterprise topology with attacker, department, server, and
   private/public address context;
4. seven materially different attack scenarios and substantial benign traffic;
5. explicit redistribution terms suitable for research; and
6. a bounded acquisition strategy: inspect S3 metadata, then acquire only a
   selected daily archive rather than synchronizing the corpus.

This is scientifically stronger than the current CIC-IDS2017 situation **not
because it is another CIC dataset**, but because the official raw-PCAP
distribution is currently publicly addressable through AWS, the attack schedule
and logs are available as independent metadata, and the raw source can be
hashed locally. CICFlowMeter CSV files would not be used as labels or features.

The selection is conditional on the verification gate below. It authorizes no
download, reconstruction, label generation, or ML work yet.

### Expected alignment policy

The future label adapter must consume only raw-PCAP evidence plus the official
schedule/log metadata:

- map packet timestamps to the verified capture clock and timezone;
- use the documented attacker/victim address mapping, without placing IPs,
  ports, attack names, or schedule identifiers in the v2 feature matrix;
- assign `ATTACK_FAMILY` only to a native flow whose accepted packet interval
  is wholly inside a verified attack interval and satisfies the verified
  endpoint/protocol rule;
- retain `BENIGN`, `ATTACK:<family>`, `UNKNOWN`, and `AMBIGUOUS` as separate
  provenance states; `UNKNOWN` is not a synonym for benign;
- do not force flows that span an attack boundary into one class;
- do not treat every flow outside an attack schedule as proven benign unless the
  selected capture/log evidence supports that claim; and
- hash and retain the raw archive, extracted PCAPs, metadata, adapter rules,
  and native replay receipts before any model fitting.

If the private/public mapping, clock basis, or interval policy cannot be
defended, downgrade CSE-CIC-IDS2018 to B and stop rather than manufacture
labels.

## CSE-CIC-IDS2018 Verification

**Verification date:** 2026-10-06
**Verification acquisition decision:** `BLOCKED_ON_LABEL_ALIGNMENT`

The primary remains selected at the dataset-selection stage, but this
verification does **not** approve acquisition. The authoritative material is
strong enough to identify the raw distribution, the daily objects, the attack
schedule, and a candidate pilot day. It is not yet strong enough to assign
authoritative labels to native Intriqo flows because the schedule timezone,
exact packet boundaries, attack-port rules, and benign-flow policy are not
published with sufficient precision. The direct S3 object is also 38.5 GB for
the smallest candidate PCAP day; there is no attack-specific small PCAP object.

### Source authority matrix

| Source | Classification | What it establishes | Boundary |
|---|---|---|---|
| [UNB/CIC IDS 2018 page](https://www.unb.ca/cic/datasets/ids-2018.html) | **AUTHORITATIVE** | Dataset identity, topology summary, attack schedule, raw PCAP/log availability, feature-labeling description, license, and AWS access instructions | Schedule times are minute-resolution; timezone, exact ports, and packet-level boundaries are not stated |
| [AWS Open Data registry](https://registry.opendata.aws/cse-cic-ids2018) | **OFFICIAL-LINKED** | CIC-managed bucket ARN, region `ca-central-1`, anonymous listing command, and link to the UNB documentation | Registry metadata does not define labels or packet semantics |
| [Canonical S3 listing](https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/?list-type=2&max-keys=1000) | **OFFICIAL-LINKED** | Current object keys, byte sizes, `LastModified`, ETags, and the two top-level prefixes; metadata-only request, no object body downloaded | Multipart ETags are not SHA-256; archive members remain uninspected |
| [CIC applications/CICFlowMeter page](https://www.unb.ca/cic/research/applications.html#CICFlowMeter) | **AUTHORITATIVE** | CICFlowMeter biflow direction, timeout description, and derived CSV behavior | It documents the feature extractor, not independent native-flow ground truth |
| [CIC official FAQ](https://cicresearch.ca/) | **AUTHORITATIVE** | CIC's statement that it has no file-level information, no data dictionary, and no documented CSV-to-PCAP relationship | It confirms a documentation gap; it does not provide missing labels or archive manifests |
| [Linked 2018 paper](https://www.scitepress.org/Papers/2018/66398/66398.pdf) | **OFFICIAL-LINKED** | Profile methodology and attack-tool descriptions linked from the official dataset page | The paper explicitly analyzes CICIDS2017, including 192.168.10.x, 205.174.165.x, and a July 3–7 five-day capture; it is not treated as CSE-CIC-IDS2018 topology or timing evidence |
| [Official CICFlowMeter repository](https://github.com/CanadianInstituteForCybersecurity/CICFlowMeter) | **OFFICIAL-LINKED** | Implementation reference for the derived flow extractor | GitHub is not used as a raw-data authority |
| [UTC/label analyses](https://intrusion-detection.distrinet-research.be/CNS2022/CSECICIDS2018.html) | **SECONDARY** | Independent commentary with more precise UTC windows and labeling examples | Not used to authorize labels or acquisition; must not replace an official timezone/ground-truth statement |
| GitHub, Hugging Face, Kaggle, and other copies | **UNVERIFIED** | None for this verification | Not used as authorities or downloaded |

The official UNB page links the AWS distribution, the CICFlowMeter reference,
and the cited paper, but no official supplementary schedule file, label script,
log schema, archive manifest, or packet-level annotation was linked or found.
The CIC FAQ explicitly says that no file-level information or CSV-to-PCAP
relationship is available.

### Official AWS distribution and metadata

The official registry identifies `arn:aws:s3:::cse-cic-ids2018` in
`ca-central-1` and documents anonymous listing with
`aws s3 ls --no-sign-request s3://cse-cic-ids2018/`. The direct ListObjectsV2
request returned 42 keys: 12 zero-byte directory markers and 30 non-zero
objects. The two top-level prefixes are:

```text
Original Network Traffic and Log data/
Processed Traffic Data for ML Algorithms/
```

Raw day objects use this pattern:

```text
Original Network Traffic and Log data/<day>/logs.zip
Original Network Traffic and Log data/<day>/pcap.zip
```

The exception is
`Original Network Traffic and Log data/Tuesday-20-02-2018/pcap.rar`.
Processed objects use:

```text
Processed Traffic Data for ML Algorithms/<day>_TrafficForML_CICFlowMeter.csv
```

The canonical key contains the spelling
`Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`; it is not normalized in
the receipt.

The ten raw PCAP archive sizes total **477,321,665,202 bytes** (477.32 GB
decimal, 444.54 GiB). The ten matching log archives total **1,932,428,474
bytes**. All raw objects total **479,254,093,676 bytes** (446.34 GiB). The
processed CSV objects total **6,886,649,507 bytes** (6.41 GiB). These are
metadata sums, not downloaded data.

S3 listing and HEAD metadata expose byte size, `LastModified`, content type,
and ETag. The selected PCAP HEAD response reports `Content-Length:
38535667707`, `Content-Type: application/zip`, and ETag
`7ef6f23385e8cafe3427e5c612e41eeb-2297`; the matching log reports 155242304
bytes and ETag `86d41cc2be34c131accfb716c73f987d-10`. The matching processed CSV
reports 333723605 bytes and ETag `e68ef27c09c98ba91fe3c6b1108a18b9-20`.
All selected ETags are multipart ETags. No SHA-256, MD5 manifest, archive
manifest, or object-level checksum was exposed by the listing/HEAD metadata.
The ETags must therefore be retained as provider metadata but never presented
as expected cryptographic hashes.

No object body, archive member, full PCAP, full log archive, or processed CSV
was downloaded in this verification.

### Minimum viable raw subset

The smallest official raw PCAP archive in the listing is the 16-Feb-2018 day:

| Role | Exact S3 key | Bytes | ETag | Officially documented role |
|---|---|---:|---|---|
| Raw packets | `Original Network Traffic and Log data/Friday-16-02-2018/pcap.zip` | 38,535,667,707 | `7ef6f23385e8cafe3427e5c612e41eeb-2297` | Daily raw PCAP archive |
| Machine logs | `Original Network Traffic and Log data/Friday-16-02-2018/logs.zip` | 155,242,304 | `86d41cc2be34c131accfb716c73f987d-10` | Daily Windows/Ubuntu event-log archive |
| Reference only, not a label source | `Processed Traffic Data for ML Algorithms/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | 333,723,605 | `e68ef27c09c98ba91fe3c6b1108a18b9-20` | Derived CICFlowMeter rows; forbidden as the primary label source |

The raw PCAP plus logs total **38,690,910,011 bytes**; including the derived
CSV would total **39,024,633,616 bytes** (36.34 GiB). The processed CSV is not
needed for the native experiment and will not be acquired for labeling. The
raw pair is still not a small safe acquisition for this workspace, and the S3
listing provides no smaller attack-only object. The 16-Feb day is the best
metadata candidate, not an acquisition authorization.

The official schedule identifies two attack windows on this day:

| Date | Attack | Official displayed time | Attacker identity | Victim identity |
|---|---|---|---|---|
| 2018-02-16 | `DoS-SlowHTTPTest` | 10:12–11:08 | private `172.31.70.23`, public `13.59.126.31` | public `18.217.21.148`, private `172.31.69.25` |
| 2018-02-16 | `DoS-Hulk` | 13:45–14:19 | private `172.31.70.16`, public `18.219.193.20` | public `18.217.21.148`, private `172.31.69.25` |

The day also contains documented B-profile background traffic, but the official
source does not publish a packet-level benign manifest or a benign-only time
interval. Therefore a future pilot may replay documented background traffic,
but it must not call every non-attack-schedule native flow `BENIGN` without an
approved negative-ground-truth rule.

### CSE-CIC-IDS2018 Ground-Truth Semantics

This section records the authoritative meaning of each available ground-truth
input and separates it from information supplied only by secondary analyses or
inference. The result remains `BLOCKED_ON_LABEL_ALIGNMENT`: the official page
describes how the released flow CSV was labeled, but it does not publish enough
clock, packet-boundary, port, log, or benign-negative detail to reproduce that
rule on native Intriqo flows without guessing.

#### Timestamp semantics

| Artifact | Officially established | Not established |
|---|---|---|
| Attack schedule | Date plus `HH:MM` fields named **Attack Start Time** and **Attack Finish Time** | Timezone, seconds, fractional precision, inclusive/exclusive boundary semantics, and whether the fields are tool-start/tool-stop or first/last malicious packet |
| PCAP packets | Raw network PCAPs exist in the official daily distribution | Timestamp epoch/timezone, precision, capture clock, clock synchronization, capture vantage point, and relation to schedule time |
| Machine logs | Windows and Ubuntu event logs are recorded per machine | Log schema, host timezone, clock source, precision, clock drift, event coverage, and relation to PCAP time |
| S3 metadata | `LastModified` and object metadata are available | These are object-publication metadata, not capture timestamps |

The schedule is therefore known only at minute resolution. No authoritative
source establishes that the two Friday windows map directly to packet timestamps
or that the packet and host-log clocks are comparable. Daylight-saving handling
is also **UNRESOLVED** because the dataset does not identify the schedule or
capture timezone; no offset may be guessed from the calendar date.

#### Attack interval semantics

| Scenario | Official schedule window | Boundary/tool semantics | Native-label consequence |
|---|---|---|---|
| `DoS-SlowHTTPTest` | 2018-02-16 10:12–11:08 | The official table supplies minute-resolution start/finish fields and names the tool; it does not say whether these are process execution times, attack packet first/last times, or inclusive/exclusive boundaries | A native flow at or across either boundary cannot receive `ATTACK:DoS-SlowHTTPTest` from the schedule alone |
| `DoS-Hulk` | 2018-02-16 13:45–14:19 | Same unresolved semantics; the page names Hulk but does not publish warm-up, cool-down, retries, teardown, or packet boundary rules | A native flow must remain `UNKNOWN` or `AMBIGUOUS` unless an authoritative clock and packet rule are supplied |

The official page does not establish whether packets outside a window can be
attack teardown, startup, retries, or failed attempts. It also does not provide
an overlap/precedence rule for attack traffic and B-profile traffic. A
secondary analysis reports different UTC packet windows and concludes that the
SlowHTTPTest attack was unsuccessful; that source is explicitly `SECONDARY` and
conflicts with the official schedule, so it is evidence of unresolved semantics,
not a replacement label source.

#### Attacker/victim mapping and address semantics

The official schedule supports these values as documented role/address pairs:

| Scenario | Attacker in official table | Victim in official table |
|---|---|---|
| `DoS-SlowHTTPTest` | private `172.31.70.23`; “Valid IP” `13.59.126.31` | `18.217.21.148` – `172.31.69.25` |
| `DoS-Hulk` | private `172.31.70.16`; “Valid IP” `18.219.193.20` | `18.217.21.148` – `172.31.69.25` |

The official page also says the attacks were executed from machines outside the
target network in an AWS LAN-style topology. It does **not** state whether the
public/private pairs are NAT translations, host aliases, documentation
shorthand, or addresses visible at the PCAP capture interface. It does not
state which side of each pair appears as the native packet source or
destination. The role mapping is authoritative as schedule metadata; the
capture-side mapping, NAT behavior, and packet direction are **UNRESOLVED**.

#### Protocol and port ground truth

The official page lists the B-profile protocols (HTTPS, HTTP, SMTP, POP3, IMAP,
SSH, and FTP), names the Friday tools, and says the released CSV labeling used
source IP, destination IP, source port, destination port, and protocol. It does
not publish the Friday attack protocol, destination port, source-port behavior,
multi-port set, or stability rule for either DoS scenario. Tool names are not a
substitute for a dataset-specific port/protocol manifest. Consequently the
protocol and port constraints required by a native label adapter are
**UNRESOLVED** and no values are inferred from the derived CSV.

#### Log semantics

The official dataset page establishes only that each day contains Windows and
Ubuntu event logs per machine. The official CIC FAQ further says CIC has no
file-level information, no data dictionary, and no documented relationship
between the CSV and PCAP files. Before extraction, the official material does
not establish any of the following:

| Requested log evidence | Status |
|---|---|
| Process execution records | **UNRESOLVED** |
| Attack start/end records | **UNRESOLVED** |
| Attacker/victim identity fields | **UNRESOLVED** |
| Port/protocol fields | **UNRESOLVED** |
| Host timezone/clock fields | **UNRESOLVED** |
| Network timestamps or connection records | **UNRESOLVED** |
| IDS labels or packet identifiers | **UNRESOLVED** |
| PCAP-to-log join key | **UNRESOLVED** |

The logs may be useful supporting evidence after an authorized bounded
acquisition, but they cannot currently be treated as independent ground truth
or as a known packet-label manifest.

#### Benign-negative semantics

The official page documents B-profile-generated benign background behavior and
states that the daily data includes the raw traffic and logs. It does **not**
state that every flow outside a listed attack interval is benign, provide a
benign-only interval, publish a complete negative manifest, or define treatment
of background traffic concurrent with an attack. The correct pre-acquisition
state is therefore:

```text
BENIGN:       not authoritatively assignable from the published schedule alone
ATTACK:       not assignable until clock, endpoint, protocol, and boundary rules are verified
UNKNOWN:      default for evidence insufficient to prove either class
AMBIGUOUS:    use when evidence conflicts or a native flow crosses an unresolved boundary
```

Outside an attack window means **NOT-LABELED**, not `BENIGN`.

#### Archive structure and file-level evidence

The official Friday prefix listing exposes exactly three outer S3 keys: the
zero-byte prefix marker, `logs.zip`, and `pcap.zip`. The object metadata exposes
outer-object size, `LastModified`, content type, and multipart ETag only. It
does not expose archive member names, member count, member sizes, PCAP
container/datalink types, log filenames, or member checksums. The official CIC
FAQ's “no file-level information” statement confirms that no official file
dictionary or CSV/PCAP relationship is available to fill this gap. No
`x-amz-checksum-*` header or official manifest was found in metadata-only
inspection. Therefore the archive structure is **UNRESOLVED** without reading
object bytes, and reading the 38.5 GB archive is outside this task's gate.

#### Official labeling statement and its limit

The authoritative UNB/CIC page says that, after feature extraction, flows were
labeled using the attack-scenario schedule together with source and destination
IP addresses, source and destination ports, and protocol. This is **not** a
packet-level label file. It is a documented flow-labeling rule whose inputs are
independent of CICFlowMeter feature values, but the released CSV labels are
still derived flow labels and cannot be copied onto native flows.

What is established:

- attack names, displayed start/finish times, and several attacker/victim
  public/private address pairs are published in the official schedule;
- the official page says the raw distribution includes network PCAPs and
  Windows/Ubuntu event logs per machine;
- the official page says the published CSV was labeled from schedule plus
  tuple/protocol information; and
- the raw PCAP path and the corresponding logs path are identifiable without
  acquiring the objects.

What is **not** established by the authoritative source:

- whether displayed times are UTC, local AWS time, or another timezone;
- exact attack start/end packet timestamps, rather than minute-resolution
  schedule times;
- a separately published packet-level ground-truth file;
- the exact attack ports and protocol constraints for each 16-Feb scenario;
- a public label-generation script or manifest with precedence for overlapping
  attacks, scans, background connections, and failed attempts;
- a complete host-to-IP/OS/interface inventory; or
- a rule proving that a flow outside a listed attack window is benign.

The official paper linked by the dataset page is useful for profile and tool
methodology, but its detailed evidence refers to CIC-IDS2017. It must not be
used to fill these missing CSE-CIC-IDS2018 fields. A secondary analysis reports
UTC windows, but its classification is `SECONDARY`; it is a lead for a future
source-reconciliation request, not authoritative ground truth.

The current feasibility result is therefore:

| Alignment tier | Evidence | Status |
|---|---|---|
| Packet-level labels | No official packet label object or packet annotation was found in the listing or documentation | **Unavailable** |
| Attack interval + verified identity | Schedule and public/private identities exist; timezone and exact boundaries are unresolved | **Conditionally feasible, blocked** |
| Interval + tuple/protocol/port constraints | The official labeling description names tuple/protocol inputs, but exact 16-Feb ports/rules are not published | **Conditionally feasible, blocked** |
| Derived CSV row → native flow | Would couple the experiment to CICFlowMeter segmentation/features | **Forbidden** |

### Proposed native-flow label policy (not yet executed)

The label adapter must consume raw-PCAP-derived native flow metadata plus an
authoritatively reconciled schedule/host rule. It must never consume the
CICFlowMeter CSV as a row-matching source. Until the missing fields are
verified, every flow remains `UNKNOWN` or `AMBIGUOUS`.

After verification, the policy should be:

1. Normalize all schedule times only after the source timezone and capture-clock
   relationship are documented.
2. Require a native flow's observed endpoints, protocol, and verified ports to
   match the attack rule. Public/private pairs must be resolved as capture-side
   identities, not guessed to be NAT translations.
3. Assign `ATTACK:<family>` only when the flow's accepted packet interval is
   wholly inside a verified attack interval and the verified identity rule
   matches. A flow crossing an attack boundary is `AMBIGUOUS`.
4. Assign `BENIGN` only for a separately verified benign interval/host rule.
   Being outside an attack schedule is not enough; all other flows are
   `UNKNOWN`.
5. Preserve `UNKNOWN` and `AMBIGUOUS` in metadata and exclude them from any
   future supervised fit unless a later review explicitly authorizes a policy.
6. Keep labels, schedule identifiers, IPs, ports, and attack names out of the
   nine-dimensional native v2 feature matrix. They remain provenance/audit
   fields only.

This policy is a design receipt, not a claim that the official data currently
supports all of its inputs.

### Native Intriqo compatibility gate

The existing native v2 contract and implementation were inspected but not
modified. CSE-CIC-IDS2018 can use the existing path only if extracted archive
members pass these checks:

- the member is classic PCAP 2.4 with a supported microsecond or nanosecond
  timestamp format; the S3 object name `pcap.zip` does not disclose the member
  container format;
- the link type is supported: Ethernet, raw IP, BSD loopback, Linux cooked v1,
  or Linux cooked v2. The archive's DLT is not known before extraction;
- accepted traffic is complete IPv4 with a valid IHL and fully captured
  `total_length`. Native bytes are the IPv4 total-length field, not Ethernet
  bytes or application payload;
- TCP, UDP, and ICMP headers are structurally complete. TCP SYN/FIN flags,
  packet timestamps, directional packet/byte counters, and accepted IPv4
  lengths are available to native v2;
- packets are not IPv6, VLAN-tagged Ethernet requiring VLAN decoding, malformed,
  truncated, or IPv4 fragments requiring reassembly. Unknown IPv4 protocols are
  retained only as `OTHER` with zero ports and without the original protocol
  number;
- both directions of a five-tuple are present when bidirectional flow features
  are expected. The first observed tuple defines native forward direction;
  attacker/victim semantics do not reorient it;
- per-flow capture timestamps are nondecreasing in file order for valid native
  IAT statistics. Replay does not sort or repair timestamps; and
- the selected replay configuration records unsupported, truncated, malformed,
  feature-generation, and capture errors. A scientifically clean pilot should
  show zero such failures, or stop for review.

The relevant implementation evidence is `engine/src/capture/pcap_source.cpp`,
`engine/src/capture/capture_internal.hpp`, `engine/src/packet/parser.cpp`,
`engine/src/flow/flow_table.cpp`, and `docs/ml-feature-set-v2.md`. The existing
controlled prototype's 1 MiB limit is not a declaration that a real daily
archive is safe to process; it remains a small unlabelled fixture gate.

### Smallest defensible experiment (candidate only)

There is no official attack-only object. The smallest possible acquisition is
therefore still the complete Friday pair:

```text
Original Network Traffic and Log data/Friday-16-02-2018/pcap.zip  38,535,667,707 bytes
Original Network Traffic and Log data/Friday-16-02-2018/logs.zip      155,242,304 bytes
```

The smallest future **labeled** experiment should select one official Friday
scenario—`DoS-Hulk` is the current candidate—and use only native flows that
pass the verified clock, capture-side endpoint, protocol/port, and wholly
inside-the-interval rules. It must also include a separately verified benign
control interval or negative manifest. `DoS-SlowHTTPTest` remains a documented
candidate, but secondary observations conflict with the official schedule and
cannot be used to resolve that conflict. Until the missing semantics are
answered, neither scenario is a defensible native-label experiment and neither
object may be downloaded.

### Verification conclusion and exact next action

`BLOCKED_ON_LABEL_ALIGNMENT` is the current acquisition decision. The official
source proves a reproducible raw distribution and a plausible interval/identity
labeling chain, but it does not yet prove the timezone, exact packet boundaries,
port rules, or benign-negative policy needed for deterministic native labels.
The smallest raw candidate is also a 38.69 GB PCAP-plus-log pair, not a safe
small slice. No download is approved.

The exact next action is to request from CIC/UNB, before any data transfer:

1. the timezone and clock basis for the published schedule and PCAP timestamps;
2. PCAP timestamp precision/epoch and its clock relationship to host logs;
3. the official 16-Feb attack protocol/port rules and whether public/private
   address pairs are NAT, host-side aliases, or both;
4. the label-generation script/manifest or an authoritative packet/interval
   ground-truth export, including boundary, warm-up/cool-down, failed-attempt,
   teardown, and overlap handling;
5. the log schema, host timestamps, process/connection fields, and PCAP join
   key;
6. archive member/interface/container/datalink information; and
7. a benign-only interval, complete negative manifest, or explicit
   negative-ground-truth rule for the selected day.

Until those answers are recorded, do not run an acquisition command. The
metadata-only reproduction commands are safe if the receipt must be refreshed:

```sh
curl -sS 'https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/?list-type=2&max-keys=1000'
curl -sSIL 'https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Original%20Network%20Traffic%20and%20Log%20data/Friday-16-02-2018/pcap.zip'
curl -sSIL 'https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Original%20Network%20Traffic%20and%20Log%20data/Friday-16-02-2018/logs.zip'
```

Do not replace these metadata requests with `aws s3 sync`; do not download the
full bucket or the selected day until the label-alignment gate is cleared.

## Fallback recommendation: IoT-23 — Grade B

IoT-23 is the fallback because the official Stratosphere page points to a
versioned Zenodo record with a CC BY 4.0 license, a published MD5 for the 21.5
GB full archive, and 23 individually described scenarios. It provides 20
malicious IoT captures and 3 real benign-device captures, so a bounded scenario
can be inspected without committing to a hundreds-of-GB corpus.

Its limitation is decisive: the public labels are analyst-generated in
`conn.log.labeled` after Zeek processing and rule-based/manual analysis. They
are not packet/interval ground truth independent of a derived flow artifact.
IoT-23 is therefore suitable as a controlled fallback for botnet/malware
behavior, not as a replacement for broad enterprise ground truth. A fallback
experiment must use the raw PCAP plus label provenance and report any native
flow that cannot be mapped exactly as ambiguous.

## IoT-23 bounded verification — `BLOCKED_ON_IOT23_LABEL_ALIGNMENT`

**Verification date:** 2026-10-06

The pre-download gate passed for exactly one small representative scenario, so
only that scenario was obtained. The full `iot_23_datasets_full.tar.gz` archive,
the 8.8 GB small archive, every other IoT-23 scenario, and all unofficial
mirrors were left untouched. The detailed receipt is
[`ml/artifacts/feature-analysis/iot23/dataset_verification.json`](../ml/artifacts/feature-analysis/iot23/dataset_verification.json).

### Official provenance

| Source | Classification | Verified evidence | Boundary |
|---|---|---|---|
| [Stratosphere IoT-23 page](https://www.stratosphereips.org/datasets-iot23) | **AUTHORITATIVE** | First-party capture context, 20 malicious plus 3 benign scenarios, scenario tables, labels, Zeek layout, Flaber process, and individual links | Individual file digests are not published on the page |
| [Zenodo record 4743746](https://zenodo.org/records/4743746) | **AUTHORITATIVE** | Publisher Zenodo; publication date 2020-01-20; version 1.0.0; DOI `10.5281/zenodo.4743746`; CC BY 4.0; archive MD5 | The MD5 covers the full archive, not a selected individual file |
| [Official-linked scenario directory](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-42-1/) | **OFFICIAL-LINKED** | Direct PCAP, README, and `bro/conn.log.labeled`; server sizes and metadata | Server ETags are not cryptographic expected hashes |
| [Stratosphere Flaber archive](https://github.com/stratosphereips/flaber) | **OFFICIAL-LINKED** | Rule-driven labeling of Zeek `conn.log` rows; matching labels can be concatenated | Archived implementation, not independent packet ground truth |
| Third-party copies | **UNVERIFIED** | None | Not consulted or used |

Official archive receipt:
`iot_23_datasets_full.tar.gz`, 21,510,801,277 bytes, MD5
`7132e603f9750b8580b6cebdbcd43e9c`. It was not downloaded.

### Selected scenario and bounded files

Selected: **`CTU-IoT-Malware-Capture-42-1` (Trojan)**. The official table
reports 8 hours, about 24,000 packets, 4,427 Zeek flows, and a 2.8 MB PCAP.
The README gives a start time but leaves duration blank. The individual files
were:

| Artifact | Official size | Local size | Local SHA-256 | Local MD5 |
|---|---:|---:|---|---|
| `2019-01-10-14-34-38-192.168.1.197.pcap` | 2,908,160 bytes | 2,908,160 bytes | `7573797f17aae96e3804a3cfb22d531b74c17bbae740de1e14048f89130fba37` | `b1a883b9bce42a96d53949c210cb4426` |
| `bro/conn.log.labeled` | 585,829 bytes | 585,829 bytes | `269fa1b22d9a37e159cf41b81a213a0032d21306f5d39b4c20cb0d211b04e8aa` | `4d31df41c4e2c9939c72584ca4c11b97` |

The individual directory and README provide no official per-file PCAP/log
digest. The README's SHA-256 is the malware-binary digest, not the PCAP digest;
it was not used as one. Therefore the local hashes are recorded for
reproducibility but cannot be verified against an official per-file checksum.

### Label model and counts

IoT-23 labels are **analyst-generated Zeek flow annotations**. The authors'
process manually analyzes the original PCAP, applies external rules with
Flaber to Zeek `conn.log` records, and publishes the final values in
`bro/conn.log.labeled`. They are not independent packet-level or interval
ground truth.

Each selected row contains Zeek `ts`, `duration`, originator/responder IPs and
ports, protocol, and one coarse `label` plus one `detailed-label` string. The
selected log contains 4,426 rows: 4,420 explicit `Benign` rows and 6 explicit
`Malicious` rows, with detailed-label counts of 3 `FileDownload` and 3
`C&C-FileDownload`. All rows have a label pair, but the benign class remains a
manual/rule-derived negative assertion; an unmatched native flow must not be
called benign. Flaber can concatenate overlapping rule labels with hyphens;
formal conflict precedence and rule provenance are not preserved in the final
row.

The observed Zeek timestamp span is 30,047.506529 seconds. This is reported as
an observation, not as independent interval truth.

### Native compatibility and integrity result

The downloaded file identifies as classic PCAP 2.4, little-endian,
microsecond timestamps, Ethernet/EN10MB, snaplen 262,144. An independent
record walk found 24,484 complete records: 22,748 IPv4 and 1,736 ARP; the
IPv4 records contained 18,183 TCP and 4,565 UDP packets, with no observed
IPv6, ICMP, VLAN, or IPv4 fragmentation. This is otherwise within the current
native parser boundary; ARP is non-IP and would not become a native IP flow.

The integrity gate failed: the file ends in record 24,485, which declares a
91-byte packet but contains only 45 bytes. `capinfos` reports that the PCAP was
cut short in the middle of a packet. The packet was not repaired, discarded,
or silently replayed.

Because the PCAP was not valid, the actual C++ engine was **not** run. There
are therefore no engine packet/flow counters, no native-v2 JSONL, no native
label coverage, and no ML metrics. The label log alone is not sufficient to
claim exact/partial/ambiguous/unknown native matches.

### Conservative alignment that remains required

If a complete, individually verifiable scenario is later supplied, an isolated
adapter must join native records to Zeek rows using directional source/dest IP,
source/dest port, protocol, and `[first_seen,last_seen]` versus
`[ts,ts+duration]`. It must not assume equal Zeek and Intriqo flow boundaries:

- `EXACT`: one candidate, same five-tuple/protocol, and matching temporal
  boundaries at available precision;
- `PARTIAL`: one candidate, same tuple/protocol, temporal overlap but different
  boundaries;
- `AMBIGUOUS`: multiple candidates, repeated tuple/interval, or competing
  labels;
- `UNKNOWN`: no defensible correspondence, missing timestamps, unsupported
  traffic, or truncation.

The adapter output must retain `flow_id`, `label`, `attack_family`,
`match_status`, `match_method`, `source_label_id`, and `ambiguity_reason`.
`UNKNOWN` is never converted to `BENIGN`. A future conservative study could
train on high-confidence benign only and validate on high-confidence benign
plus attack, but it would need to exclude unknown/ambiguous rows while
reporting their coverage and the resulting selection bias.

### Decision

`READY_FOR_BOUNDED_IOT23_ACQUISITION` was recorded before the bounded fetch.
The selected official-linked PCAP then failed integrity validation, so the
scientific acceptance criteria were not met and the work stops at
`BLOCKED_ON_IOT23_LABEL_ALIGNMENT`. No second scenario will be acquired.

## Pre-download verification gate

No CSE-CIC-IDS2018 download is approved by this report. Before obtaining the primary
dataset, verify all of the following from official sources and record the
results in a new acquisition receipt:

1. The AWS registry still identifies `arn:aws:s3:::cse-cic-ids2018` as managed
   by CIC and the bucket remains publicly listable without credentials.
2. A metadata-only object listing records the selected day, object key, byte
   size, `LastModified`, and ETag. Multipart ETags must not be presented as
   SHA-256 hashes.
3. The selected day is small enough for the authorized workspace and contains
    both documented B-profile background activity and at least one attack
    scenario with an official schedule entry. Do not synchronize the full
    bucket.
4. The selected PCAP archive and matching logs can be tied to the same day,
   capture interface, and address map. Resolve whether the public/private pairs
   represent NAT, host-side capture, or a documentation shorthand.
5. Capture timestamps are documented as UTC or can be deterministically
   converted to UTC; record precision, timezone, first/last packet times, and
   any clock discontinuity before replay.
6. The selected capture is classic PCAP or can be safely extracted to classic
   PCAP accepted by the existing Intriqo replay path. Intriqo currently accepts
   IPv4 and rejects non-IPv4 input; IPv6 is not silently discarded.
7. The schedule/log labels identify attack intervals, endpoints, and protocols
   independently of CICFlowMeter rows. A label is not accepted merely because a
   derived CSV row has a convenient class.
8. License, attribution, and AWS citation requirements are copied into the
   acquisition receipt. Do not redistribute raw data outside those terms.
9. Only after approval: download the selected archive, compute SHA-256 for the
   archive and every extracted PCAP, validate file type and packet counts, and
   retain the official object metadata alongside those hashes.
10. Only after provenance passes: replay a bounded slice through the actual C++
    engine, audit accepted/rejected packets and timestamps, run the documented
    conservative label adapter, and stop if ambiguous/unmatched coverage is
    material. No model training is part of this gate.

If the primary fails any item, evaluate the same gate against the official
IoT-23 Zenodo record and one individually listed scenario; do not switch to a
secondary mirror.

## Source evidence and candidate notes

### CSE-CIC-IDS2018

- [UNB/CIC project page](https://www.unb.ca/cic/datasets/ids-2018.html) — seven
  attack scenarios, 50 attackers, 420 PCs, 30 servers, profiles, attack table,
  raw PCAP/log availability, schedule/IP labeling description, and license.
- [AWS Open Data registry](https://registry.opendata.aws/cse-cic-ids2018) —
  official bucket ARN, region, anonymous listing command, manager, and license
  link.
- [Official S3 object listing](https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/?list-type=2)
  — metadata-only listing observed daily `pcap.zip` objects. Individual daily
  archives observed during this review were tens of GB and had multipart ETags;
  those ETags are not treated as cryptographic file hashes.
- [CIC official FAQ](https://cicresearch.ca/) — states that CIC has no file-level
  information, no data dictionary, and no documented CSV-to-PCAP relationship.

### IoT-23

- [Stratosphere project page](https://www.stratosphereips.org/datasets-iot23)
  — raw PCAP download, scenario inventory, benign devices, label-generation
  process, labels, and direct individual scenario links.
- [Zenodo record 4743746](https://zenodo.org/records/4743746) — version 1.0.0,
  21.5 GB full archive, MD5 `7132e603f9750b8580b6cebdbcd43e9c`, and CC BY 4.0.

### UNSW-NB15

- [UNSW Research project](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
  — official PCAP/BRO/Argus/CSV source link, 100 GB raw capture description,
  ground-truth/event files, nine attack families, and academic-use terms.

### UGR'16

- [NESG UGR'16 project](https://nesg.ugr.es/veritas/index.php/nesg-ugr16) —
  first-party description of NetFlow v9 calibration/test data from a Spanish ISP;
  this is not a raw-PCAP source.
- [University of Granada repository record](https://digibug.ugr.es/handle/10481/55280)
  — authors, dataset paper, NetFlow subject, and CC BY-NC-ND 3.0 ES record
  license. The raw-data license is not separately established.

### Other reviewed sources

- [CIC-DDoS2019](https://www.unb.ca/cic/datasets/ddos-2019.html) — official
  raw PCAP/log claim, independent attack schedule, 25-user benign profile,
  DDoS families, and redistribution terms.
- [TON_IoT](https://research.unsw.edu.au/projects/toniot-datasets) — official
  PCAP/Zeek/security-event description, IoT/IIoT topology, attack families, and
  academic-use terms.
- [BoT-IoT](https://research.unsw.edu.au/projects/bot-iot-dataset) — official
  69.3 GB PCAP claim, categories, normal/botnet traffic, and academic-use
  terms.
- [CTU-13](https://www.stratosphereips.org/datasets-ctu13) — official warning
  that complete mixed PCAPs are withheld, with botnet-only/truncated captures,
  labelled Argus flows, and CC BY distribution.
- [MAWI archive](https://mawi.wide.ad.jp/mawi) and [sample trace metadata](https://mawi.wide.ad.jp/mawi/samplepoint-F/2007/200701091400.html)
  — public timestamped packet traces, anonymization, WIDE research-only terms,
  and MAWILab detector-ensemble anomaly labels.
- [CAIDA DDoS 2007 catalog](https://www.caida.org/catalog/datasets/ddos-20070804_dataset),
  [README](https://publicdata.caida.org/datasets/security/ddos-20070804/README),
  and [MD5 manifest](https://publicdata.caida.org/datasets/security/ddos-20070804/md5.md5)
  — exact UTC window, PCAP size, event-only truth, AUA, and per-file hashes.

## Experiment gate

`DATASET_SELECTED` means only that a primary and fallback satisfy the metadata
selection standard well enough to justify a bounded acquisition review. It does
not mean data acquisition, native reconstruction, labels, model training, or
metrics exist. The next permitted action is the primary pre-download gate
above. Until that gate passes, the replacement native-v2 experiment remains
`NOT_STARTED`.
