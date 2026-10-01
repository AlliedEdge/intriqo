#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST="${1:-127.0.0.1}"
TRAFFIC_TYPE="${2:-port-scan}"

echo "=== Generating synthetic security traffic ==="
echo "Target: $TARGET_HOST, Type: $TRAFFIC_TYPE"

case "$TRAFFIC_TYPE" in
    "port-scan")
        echo "Simulating SYN scan across common ports..."
        if command -v nmap >/dev/null 2>&1; then
            nmap -sS -p 21,22,23,25,80,443,3306,8080 "$TARGET_HOST" || true
        else
            echo "nmap not installed. Generating mock flow logs instead..."
            python3 -c "print('Simulated 20 port connections from 192.168.1.100 to $TARGET_HOST')"
        fi
        ;;
    *)
        echo "Unknown traffic type: $TRAFFIC_TYPE. Supported: port-scan"
        exit 1
        ;;
esac
