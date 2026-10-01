#!/usr/bin/env bash
set -euo pipefail

PCAP_FILE="${1:-pcaps/sample.pcap}"
INTERFACE="${2:-lo}"

if [ ! -f "$PCAP_FILE" ]; then
    echo "ERROR: PCAP file not found: $PCAP_FILE"
    echo "Usage: $0 <path_to_pcap> [interface]"
    exit 1
fi

echo "=== Replaying PCAP file: $PCAP_FILE on interface: $INTERFACE ==="

if command -v tcpreplay >/dev/null 2>&1; then
    sudo tcpreplay --intf1="$INTERFACE" "$PCAP_FILE"
else
    echo "tcpreplay not found. Please install tcpreplay to replay live packet captures."
    exit 1
fi
