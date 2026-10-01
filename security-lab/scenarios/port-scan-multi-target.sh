#!/bin/bash

# Multi-Target Port Scan Scenario
# Simulates network reconnaissance across multiple hosts
# Tests detection of distributed scanning behavior

echo "================================================"
echo "Multi-Target Port Scan Scenario"
echo "================================================"
echo ""

TARGETS=(
    "172.20.0.20"  # victim-web
    "172.20.0.21"  # victim-db
    "172.20.0.22"  # victim-ssh
    "172.20.0.23"  # victim-app
)

echo "Targets: ${TARGETS[@]}"
echo ""

# Scenario: Scan multiple targets in sequence
echo "[1] Sequential scanning of all targets"
for target in "${TARGETS[@]}"; do
    echo "  Scanning $target..."
    nmap -sS -T4 -p 20-50 $target --max-retries 1 > /dev/null 2>&1
    sleep 1
done

echo ""
echo "[2] Comprehensive scan of subnet"
nmap -sS -T4 -p 22,80,443,3306,5432,8080 172.20.0.20-23

echo ""
echo "[3] Ping sweep + port scan"
nmap -sn 172.20.0.0/24  # Ping sweep
nmap -sS -p 80,443 --open 172.20.0.20-23  # Only scan hosts that responded

echo ""
echo "Multi-target scan complete."
echo "Expected: Multiple PORT_SCAN events from single source (172.20.0.10)"
echo "Each target should generate independent detection"
