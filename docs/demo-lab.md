# INTRIQO SECURITY LAB

This is the reproducible, isolated network lab for the Intriqo Release
Candidate live demonstration. It represents the **camera placement** layer of
a NIDS deployment. It is not a production network deployment and it does not
replace the existing C++ engine, Control Plane, agents, ML worker, or SOC UI.

## What is validated

The lab uses the existing `security-lab/controlled_v2` namespace, bridge, and
`tc/mirred` implementation with a separate `demo` profile. The controlled-v2
defaults remain unchanged for the locked evaluation workflow.

```text
INTRIQO SECURITY LAB

  intriqo-attacker namespace                 intriqo-victim namespace
  10.77.0.10/24                              10.77.0.20/24
          │                                          ▲
          └────────────── br-intriqo ───────────────┘
                              │
                      tc ingress mirred
                       (both bridge ports)
                              │
                 intriqo-monitor namespace
                         tap-intriqo
                              │
                   C++ INTRIQO-LAB-01 sensor
                              │
                   authenticated HTTP events
                              │
       Control Plane → PostgreSQL → Agents → SOC dashboard
```

The conceptual traffic view is:

```text
Attacker 10.77.0.10 ───────────────▶ Victim 10.77.0.20
       ╲
        ╲ mirrored frames
         ╲
          ▶ tap-intriqo → INTRIQO-LAB-01 → Control Plane → SOC Dashboard
```

The lab creates only four owned namespaces:

| Role | Namespace | Interface | Address / purpose |
|---|---|---|---|
| Attacker | `intriqo-attacker` | `lab0` | `10.77.0.10/24` |
| Victim | `intriqo-victim` | `lab0` | `10.77.0.20/24` |
| Virtual switch | `intriqo-switch` | `br-intriqo`, `sw-a`, `sw-v`, `mirror-out` | bridge and mirror owner |
| Sensor monitor | `intriqo-monitor` | `tap-intriqo`, `sensor-mgmt` | passive mirrored capture point plus host-only sensor control link |

There are no default routes, gateways, IPv6 autoconfiguration paths, physical
interface attachments, Docker network attachments, or forwarding rules. The
monitor has one separate point-to-point management veth (`169.254.77.2/30` to
the host's `169.254.77.1/30`) solely for the existing engine HTTP sink to reach
the host Control Plane. It is not bridged to the attack network and has no
forwarding or default route. The topology verifier also performs a kernel-only route lookup for an external
documentation address and requires that lookup to fail without sending a
probe.

## One-time setup and repeatable lifecycle

Linux network namespaces, `tc`, and raw packet generation require root or
`sudo`. The scripts fail closed if the required commands or privileges are not
available. They never accept a target address.

```bash
# First time on a host
./scripts/lab/setup.sh

# Every demo session
./scripts/lab/up.sh
./scripts/lab/status.sh --verify

# Stop only the lab
./scripts/lab/down.sh

# Remove and recreate the owned lab after an intentional local reset
./scripts/lab/reset.sh
```

`setup.sh` and `up.sh` reuse a fully verified owned topology. The ownership
marker records the network namespace inodes; an unexpected or partially
modified topology is reported as `BLOCKED` rather than being guessed at or
silently repaired. `down.sh` deletes only the namespaces recorded by that
marker and refuses ambiguous cleanup.

Example status output is derived from actual checks, not a dashboard fixture:

```text
INTRIQO LAB
────────────────────────────────────────
Attacker       10.77.0.10   READY
Victim         10.77.0.20   READY
Bridge         br-intriqo  READY
tap-intriqo                 READY
Traffic Mirror              ACTIVE
Attacker → Victim            CONNECTED
TAP probe                    RECEIVED
Overall                      READY
```

`READY`, `ACTIVE`, `CONNECTED`, and `RECEIVED` are printed only after the
corresponding namespace, address, link, route, bridge membership, exact
`matchall`/`mirred` filters, fixed ping, and monitor packet-counter checks pass.

## Sensor and Release Candidate integration

The demo sensor is a deployment identity, not a new database entity:

| Sensor field | Demo value |
|---|---|
| Sensor identity | `INTRIQO-LAB-01` |
| Capture interface | `tap-intriqo` in `intriqo-monitor` |
| Observed network | `10.77.0.0/24` |
| Detection | Existing C++ `PORT_SCAN`, `UDP_SCAN`, and `SYN_FLOOD` detectors |
| Event sink | Existing authenticated Control Plane HTTP sink |

`./scripts/start-demo.sh` verifies the lab and starts the existing runtime with
the C++ engine in the monitor namespace. It uses `--no-promiscuous` and a
`net 10.77.0.0/24` capture filter. The Control Plane binds only to the
host-side management address (`169.254.77.1`), while the browser remains on
localhost and Vite proxies API/WebSocket requests to that address. The other
services stay on their existing host-process path.

```bash
./scripts/start-demo.sh
./scripts/logs-intriqo.sh engine
./scripts/status-intriqo.sh
```

The command fails clearly if PostgreSQL, migrations, Control Plane readiness,
the agent poller, the engine build, libpcap, the monitor namespace, or the
configured ML worker is unavailable. Use the existing lifecycle commands for
shutdown and recovery:

```bash
./scripts/stop-intriqo.sh
./scripts/lab/down.sh
```

ML remains controlled by the normal `.env` or `.env.ml` settings. The lab
scripts never retrain, replace, or retune the locked model, threshold, v2
schema, or controlled corpus.

## Authorized traffic generators

The generators enter the owned attacker namespace only after
`status.sh --verify` succeeds. Their target and source are constants in the
existing controlled traffic helper:

```bash
./scripts/lab/port-scan.sh
./scripts/lab/udp-port-scan.sh
./scripts/lab/syn-flood.sh
```

The deterministic parameters are selected from the existing detector defaults:

- `PORT_SCAN`: destination ports `10080–10089`, two SYN attempts per port,
  fixed source ports beginning at `44000`, and a bounded one-second episode.
  This supplies ten distinct TCP flow identities and twenty attempts inside
  the existing ten-second detector window.
- `UDP_SCAN`: destination ports `10080–10089`, one UDP datagram per port,
  fixed source ports beginning at `45000`, paced at 20/s. This supplies ten
  distinct UDP flow identities to the separately registered UDP scan detector.
- `SYN_FLOOD`: destination port `65535`, one hundred unique source ports
  beginning at `43000`, paced at `75/s`. The unique five-tuples and duration
  satisfy the existing 100-attempt, 50/s, 50-incomplete-handshake, and one
  second minimum-observation requirements without changing those thresholds.

The only addresses permitted by these scripts are `10.77.0.10` and
`10.77.0.20`. The former generic target-taking helper now rejects arbitrary
targets and no longer prints a fake fallback flow.

## SOC analyst boundary

The network/security administrator (or demo operator) owns the deployment
steps: namespaces, bridge, `tc`, TAP, capture privileges, and sensor process.
The SOC analyst does **not** configure any of those resources. After login as an

```text
MONITOR → TRIAGE → INVESTIGATE → REVIEW FINDING → UPDATE INCIDENT → RESOLVE
```

The dashboard reads persisted Control Plane responses for events, incident
relationships, task status, finding evidence, provenance, and audit history. It
does not create sensor rows, alert counters, graphs, or attack-simulation
screens. The identity of the machine agent remains the `AGENT` service role and
is separate from the human analyst.

## Real deployment comparison

```text
Enterprise Network
        │
        ▼
Switch SPAN / physical TAP
        │
        ▼
Intriqo Sensor on an authorized capture interface
        │
        ▼
Control Plane → PostgreSQL
        │
        ▼
SOC Dashboard → SOC Analyst
```

In production, a network/security administrator deploys and authorizes the
sensor on the SPAN/TAP interface. The SOC analyst does not configure SPAN/TAP
or Linux namespaces. This repository validates a bounded single-sensor lab
placement, not enterprise-wide visibility, prevention, automated blocking, or
distributed horizontal scaling.

## Validation boundary

Validated by the repository's existing evidence: deterministic C++ detector
tests, Control Plane/agent/frontend workflow tests, locked-v2 ML tests, and the
controlled-v2 isolation verifier. Privileged live lab execution and full-stack
capture remain environment-dependent; if libpcap, Docker/PostgreSQL, or sudo
capability is missing, the scripts must report that gap rather than claim a
live event path.

See [the demo runbook](demo-runbook.md), [SOC Workflow](soc-workflow.md),
[runtime recovery](runtime-recovery.md), and
[ML inference integration](ml-inference-integration.md).
