#!/bin/bash

# Normal Traffic Scenario
# Simulates legitimate user activity
# Should NOT trigger port scan detection

echo "================================================"
echo "Normal Traffic Scenario"
echo "================================================"
echo "Simulating legitimate user behavior..."
echo ""

WEB_HOST="172.20.0.20"
DB_HOST="172.20.0.21"
SSH_HOST="172.20.0.22"
APP_HOST="172.20.0.23"

# Scenario 1: Normal web browsing
echo "[1] Normal web browsing (HTTP/HTTPS)"
for i in {1..10}; do
    curl -s http://$WEB_HOST:80 > /dev/null
    sleep 0.5
    curl -s http://$WEB_HOST:8080 > /dev/null
    sleep 0.5
done

echo "  ✓ Web traffic generated (should NOT trigger)"

sleep 2

# Scenario 2: Database connections (repeated to same port)
echo ""
echo "[2] Database connections"
for i in {1..5}; do
    nc -zv $DB_HOST 5432 2>&1 | grep -q succeeded && echo "  DB connection $i"
    sleep 1
done

echo "  ✓ Database traffic generated (should NOT trigger)"

sleep 2

# Scenario 3: SSH connections (legitimate auth attempts)
echo ""
echo "[3] SSH connections (legitimate)"
for i in {1..3}; do
    timeout 2 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 testuser@$SSH_HOST exit 2>&1 | head -1
    sleep 2
done

echo "  ✓ SSH traffic generated (should NOT trigger)"

sleep 2

# Scenario 4: Application API calls
echo ""
echo "[4] Application API calls"
for port in 8000 8001 8002; do
    curl -s http://$APP_HOST:$port > /dev/null
    sleep 1
done

echo "  ✓ Application traffic generated (should NOT trigger)"

echo ""
echo "Normal traffic scenario complete."
echo "Expected: NO port scan detections"
echo "Reason: Normal traffic uses same ports repeatedly, does not probe many distinct ports"
