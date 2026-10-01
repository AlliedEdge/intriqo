# Intriqo PCAP Store

This directory is designated for PCAP (packet capture) files used for:
- C++ IDS Engine offline replay and testing
- Detection accuracy benchmarking
- Security scenario replay (`scripts/lab/replay-pcap.sh`)

## Naming Convention
- `<scenario>_<protocol>_<date>.pcap` (e.g., `port_scan_syn_20261001.pcap`)

*Note: Raw PCAPs containing sensitive enterprise data must be anonymized before storage.*
