# Controlled-v2 capture lab

This directory is the isolated capture implementation for the native-v2
evaluation corpus. It is separate from the legacy `security-lab` Docker bridge
and does not change the production engine or feature contracts.

## Run one episode

The runner uses the locally available `ubuntu:26.04` image with Docker
`--network none`. It bind-mounts only the repository and an external raw-PCAP
directory; no package, public target, or public dataset access is used.

```bash
security-lab/controlled_v2/run_isolated.sh train-benign-tcp
```

Run the first benign episode and replay it through the existing native-v2
harness before running attack episodes. The controller refuses traffic unless
the private namespaces, routes, sysctls, bridge mirror, and capture point pass
verification. Each episode creates three temporary validation PCAPs (attacker,
victim, monitor); only the monitor PCAP is enrolled in the corpus.

```text
10.77.0.10/lab0 -- br-intriqo-v2 -- lab0/10.77.0.20
                            \
                     tc mirror on both ports
                            \
                   tap-intriqo-v2/lab0
```

The monitor is a separate veth endpoint, not an ordinary bridge participant.
`topology.py verify` requires exactly one ingress `matchall`/`mirred mirror`
action on each endpoint bridge port and records the configuration.

## Components

- `topology.py`: owned four-namespace topology, isolation verifier, and safe
  cleanup.
- `capture.py`: kernel-timestamped immutable classic Ethernet PCAP writer.
- `traffic.py`: fixed-address, bounded TCP/UDP, SYN-flood, and port-scan
  traffic generators.
- `pcap.py`: independent classic-PCAP provenance and flow-bound inspector.
- `controller.py`: controller-owned intent, endpoint/monitor visibility gate,
  provenance, and per-flow ground-truth manifest writer.

Raw PCAPs remain outside Git. The corpus builder under `ml/` is the only path
used for native replay, alignment, quality reporting, and capture-level split
validation. No code here trains or scores a model.
