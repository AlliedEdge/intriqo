#!/bin/bash

# Port Scan Attack Scenario
# Simulates reconnaissance phase of an attack
# This should trigger the PortScanDetector

TARGET=${1:-172.20.0.20}
SCAN_TYPE=${2:-syn}  # syn, connect, null, fin, xmas

echo "================================================"
echo "Port Scan Attack Scenario"
echo "================================================"
echo "Target: $TARGET"
echo "Scan Type: $SCAN_TYPE"
echo ""

# Scenario 1: Quick SYN scan across common ports
echo "[1] Quick SYN scan - Common ports (should trigger detection)"
nmap -sS -T4 -p 20-100 $TARGET

sleep 2

# Scenario 2: Aggressive comprehensive scan
echo ""
echo "[2] Aggressive scan - Wide port range (should trigger detection)"
nmap -sS -T4 -p 1-200 $TARGET

sleep 2

# Scenario 3: Stealth scan with timing
echo ""
echo "[3] Stealth scan - Slow timing"
nmap -sS -T2 -p 1-50 $TARGET

sleep 2

# Scenario 4: Service version detection (generates more traffic)
echo ""
echo "[4] Service version detection"
nmap -sV -p 22,80,443,3306,5432 $TARGET

echo ""
echo "Port scan scenarios complete."
echo "Expected DetectionResults: Multiple PORT_SCAN events with HIGH confidence"
