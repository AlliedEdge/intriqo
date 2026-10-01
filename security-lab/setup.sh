#!/bin/bash

# Intriqo Security Lab Setup Script
# Initializes and validates the controlled security environment

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "================================================"
echo "Intriqo Security Lab Setup"
echo "================================================"
echo ""

# Check prerequisites
echo "[1/6] Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed"
    echo "Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Error: docker-compose is not installed"
    echo "Install docker-compose: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✓ Docker installed: $(docker --version)"
echo "✓ docker-compose installed: $(docker-compose --version)"
echo ""

# Check if Python 3 is available
echo "[2/6] Checking Python environment..."
if ! command -v python3 &> /dev/null; then
    echo "⚠️  Warning: Python 3 not found. PCAP parser will not work."
    echo "Install Python 3 to use traffic analysis tools."
else
    echo "✓ Python 3 installed: $(python3 --version)"
    
    # Check for scapy
    if python3 -c "import scapy" 2>/dev/null; then
        echo "✓ Scapy library installed"
    else
        echo "⚠️  Warning: Scapy not installed. PCAP parser requires it."
        echo "Install with: pip3 install scapy"
    fi
fi
echo ""

# Create necessary directories
echo "[3/6] Creating directories..."
mkdir -p pcaps traffic-data
chmod 755 pcaps traffic-data
echo "✓ Directories created"
echo ""

# Make scripts executable
echo "[4/6] Setting script permissions..."
chmod +x attack-scenarios/*.sh 2>/dev/null || true
chmod +x tools/*.py 2>/dev/null || true
chmod +x containers/monitor/monitor.sh 2>/dev/null || true
chmod +x containers/victim/entrypoint.sh 2>/dev/null || true
echo "✓ Scripts are executable"
echo ""

# Build containers
echo "[5/6] Building Docker containers..."
echo "This may take a few minutes on first run..."
docker-compose build

if [ $? -eq 0 ]; then
    echo "✓ Containers built successfully"
else
    echo "❌ Error building containers"
    exit 1
fi
echo ""

# Start the lab
echo "[6/6] Starting security lab..."
docker-compose up -d

if [ $? -eq 0 ]; then
    echo "✓ Lab started successfully"
else
    echo "❌ Error starting lab"
    exit 1
fi
echo ""

# Wait for containers to be ready
echo "Waiting for containers to initialize..."
sleep 5

# Verify containers are running
echo ""
echo "================================================"
echo "Lab Status"
echo "================================================"
docker-compose ps
echo ""

# Test connectivity
echo "================================================"
echo "Testing Network Connectivity"
echo "================================================"

if docker exec intriqo-attacker ping -c 1 172.20.0.20 &> /dev/null; then
    echo "✓ Attacker → Victim Web (172.20.0.20): OK"
else
    echo "❌ Attacker → Victim Web: FAILED"
fi

if docker exec intriqo-attacker ping -c 1 172.20.0.21 &> /dev/null; then
    echo "✓ Attacker → Victim DB (172.20.0.21): OK"
else
    echo "❌ Attacker → Victim DB: FAILED"
fi

if docker exec intriqo-attacker ping -c 1 172.20.0.22 &> /dev/null; then
    echo "✓ Attacker → Victim SSH (172.20.0.22): OK"
else
    echo "❌ Attacker → Victim SSH: FAILED"
fi

if docker exec intriqo-attacker ping -c 1 172.20.0.23 &> /dev/null; then
    echo "✓ Attacker → Victim App (172.20.0.23): OK"
else
    echo "❌ Attacker → Victim App: FAILED"
fi

echo ""
echo "================================================"
echo "Setup Complete!"
echo "================================================"
echo ""
echo "Next Steps:"
echo ""
echo "1. Run an attack scenario:"
echo "   docker exec intriqo-attacker bash /scenarios/port-scan.sh"
echo ""
echo "2. Run normal traffic (should not trigger detection):"
echo "   docker exec intriqo-attacker bash /scenarios/normal-traffic.sh"
echo ""
echo "3. Capture traffic:"
echo "   docker exec intriqo-traffic-monitor /scripts/monitor.sh"
echo ""
echo "4. Parse PCAP files:"
echo "   python3 tools/pcap_parser.py pcaps/capture_<timestamp>.pcap"
echo ""
echo "5. View logs:"
echo "   docker-compose logs -f"
echo ""
echo "6. Stop the lab:"
echo "   docker-compose down"
echo ""
echo "For more information, see README.md"
echo ""
