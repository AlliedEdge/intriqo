# Security Lab Testing Guide

This guide demonstrates how to use the Intriqo Security Lab to validate detection capabilities.

## Complete Workflow

### 1. Initial Setup (One Time)

```bash
cd security-lab
./setup.sh
```

The setup script will:
- ✓ Verify Docker and docker-compose are installed
- ✓ Check Python 3 and scapy availability
- ✓ Build all container images
- ✓ Start the lab environment
- ✓ Verify network connectivity

### 2. Run Attack Scenario

Execute a port scan that should trigger detection:

```bash
docker exec intriqo-attacker bash /scenarios/port-scan.sh
```

**Expected Output:**
```
================================================
Port Scan Attack Scenario
================================================
Target: 172.20.0.20
Scan Type: syn

[1] Quick SYN scan - Common ports (should trigger detection)
Starting Nmap scan...
...
[2] Aggressive scan - Wide port range (should trigger detection)
...

Port scan scenarios complete.
Expected DetectionResults: Multiple PORT_SCAN events with HIGH confidence
```

### 3. Run Normal Traffic (Negative Test)

Execute normal traffic that should NOT trigger detection:

```bash
docker exec intriqo-attacker bash /scenarios/normal-traffic.sh
```

**Expected Output:**
```
================================================
Normal Traffic Scenario
================================================
Simulating legitimate user behavior...

[1] Normal web browsing (HTTP/HTTPS)
  ✓ Web traffic generated (should NOT trigger)
...

Normal traffic scenario complete.
Expected: NO port scan detections
```

### 4. Capture Traffic

In Terminal 1, start packet capture:

```bash
docker exec intriqo-traffic-monitor /scripts/monitor.sh
```

In Terminal 2, run an attack:

```bash
docker exec intriqo-attacker bash /scenarios/port-scan.sh
```

Wait for capture to complete (~5 minutes default, or Ctrl+C).

### 5. Parse PCAP File

Convert captured traffic to NetworkFlow format:

```bash
cd security-lab
python3 tools/pcap_parser.py pcaps/capture_*.pcap flows.json
```

**Expected Output:**
```
Parsing PCAP: pcaps/capture_20250115_103000.pcap
Processing 1247 packets...
Extracted 89 flows

============================================================
FLOW SUMMARY
============================================================

Total flows: 89
Unique source IPs: 2

Source: 172.20.0.10
  Distinct destination ports: 45
  Distinct targets: 1
  ⚠️  LIKELY PORT SCAN (threshold: 10 ports)

Source: 172.20.0.20
  Distinct destination ports: 2
  Distinct targets: 1

Flows written to: flows.json
```

### 6. Examine Flow Data

View the generated JSON:

```bash
cat flows.json | jq '.flows[0:3]'
```

**Example Flow:**
```json
{
  "timestamp": "2025-01-15T10:30:15.123Z",
  "sourceAddress": "172.20.0.10",
  "destinationAddress": "172.20.0.20",
  "sourcePort": 54321,
  "destinationPort": 80,
  "protocol": "TCP",
  "packetCount": 3,
  "byteCount": 192,
  "durationMillis": 50
}
```

### 7. Test Detection Engine (Manual Integration)

Currently, you would manually create NetworkFlow objects from this JSON and feed them to the DetectionEngine.

**Future:** Direct integration will automatically process captured traffic.

```java
// Example: How flows would be processed
List<SecurityEvent> events = new ArrayList<>();

for (JsonNode flowJson : flowsFromJson) {
    NetworkFlow flow = parseJsonToNetworkFlow(flowJson);
    List<SecurityEvent> detected = detectionEngine.processFlow(flow);
    events.addAll(detected);
}

// Verify port scan was detected
long portScanEvents = events.stream()
    .filter(e -> "PORT_SCAN".equals(e.eventType()))
    .count();

System.out.println("Port scan events detected: " + portScanEvents);
```

### 8. Stop the Lab

```bash
docker-compose down
```

## Test Scenarios

### Scenario A: Port Scan Detection

**Objective:** Verify PortScanDetector triggers on actual port scanning traffic

**Steps:**
1. Start lab: `./setup.sh`
2. Run: `docker exec intriqo-attacker bash /scenarios/port-scan.sh`
3. Parse PCAP: `python3 tools/pcap_parser.py pcaps/capture_*.pcap`
4. Verify: Source IP shows 10+ distinct destination ports

**Expected Result:** Parser shows ⚠️ LIKELY PORT SCAN warning

### Scenario B: Multi-Target Scan

**Objective:** Verify detection across multiple targets

**Steps:**
1. Run: `docker exec intriqo-attacker bash /scenarios/port-scan-multi-target.sh`
2. Parse PCAP
3. Check flow summary

**Expected Result:** Multiple target IPs each show port scanning behavior

### Scenario C: Normal Traffic (False Positive Test)

**Objective:** Verify normal traffic does NOT trigger detection

**Steps:**
1. Run: `docker exec intriqo-attacker bash /scenarios/normal-traffic.sh`
2. Parse PCAP
3. Check distinct port counts

**Expected Result:** Source shows < 10 distinct ports, NO scan warning

### Scenario D: Mixed Traffic

**Objective:** Verify detection works in presence of normal traffic

**Steps:**
1. Terminal 1: `docker exec intriqo-attacker bash /scenarios/normal-traffic.sh`
2. Terminal 2: `docker exec intriqo-attacker bash /scenarios/port-scan.sh`
3. Parse combined PCAP

**Expected Result:** Port scan detected despite normal background traffic

## Validation Checklist

After running scenarios, verify:

- [ ] Docker containers all running (`docker-compose ps`)
- [ ] Attack scripts execute without errors
- [ ] PCAP files generated in `pcaps/` directory
- [ ] Parser successfully extracts flows
- [ ] Port scan shows 10+ distinct ports
- [ ] Normal traffic shows < 10 distinct ports
- [ ] Flow JSON matches NetworkFlow schema
- [ ] No errors in container logs (`docker-compose logs`)

## Troubleshooting

### Problem: Setup fails with Docker error

**Solution:**
```bash
# Ensure Docker daemon is running
sudo systemctl start docker

# Check Docker status
docker ps

# Rebuild if necessary
docker-compose build --no-cache
```

### Problem: Scenarios don't execute

**Solution:**
```bash
# Verify scripts are executable
chmod +x attack-scenarios/*.sh

# Check container is running
docker ps | grep intriqo-attacker

# Test container access
docker exec intriqo-attacker echo "OK"
```

### Problem: No traffic captured

**Solution:**
```bash
# Check monitor container
docker logs intriqo-traffic-monitor

# Verify capture interface
docker exec intriqo-traffic-monitor ip addr show

# Try manual capture
docker exec intriqo-traffic-monitor tcpdump -i eth0 -c 10
```

### Problem: Parser fails with scapy error

**Solution:**
```bash
# Install scapy
pip3 install scapy

# Or use system package manager
sudo apt-get install python3-scapy
```

### Problem: Flows don't show port scan

**Solution:**
- Ensure attack actually ran: check script output
- Verify threshold configuration (default: 10 ports)
- Check if flows are from the attacker IP (172.20.0.10)
- Some scans may be slow/stealthy and fall outside time window

## Advanced Usage

### Custom Attack Scenarios

Create your own scenario:

```bash
#!/bin/bash
# custom-attack.sh

TARGET="172.20.0.20"

# Your custom attack logic
nmap -sS -p 1-100 $TARGET
# ... more attacks ...

echo "Custom attack complete"
```

### Long-Duration Capture

```bash
# Capture for 30 minutes
docker exec -e DURATION=1800 intriqo-traffic-monitor /scripts/monitor.sh
```

### Continuous Monitoring

```bash
# Run scenarios in loop
while true; do
    docker exec intriqo-attacker bash /scenarios/port-scan.sh
    sleep 300  # Wait 5 minutes
done
```

### Export Flows to Database (Future)

Once persistence is implemented:

```bash
# Parse and load to database
python3 tools/pcap_parser.py pcaps/capture_*.pcap flows.json
java -jar intriqo-loader.jar flows.json
```

## Integration Testing

### Testing Detection Engine Directly

```bash
# Generate test data
docker exec intriqo-attacker bash /scenarios/port-scan.sh

# Parse to JSON
python3 tools/pcap_parser.py pcaps/capture_*.pcap test-flows.json

# Run Java integration test with real data
./gradlew test --tests "DetectionEngineRealTrafficTest"
```

### Automated Test Pipeline

```bash
#!/bin/bash
# automated-test.sh

# Start lab
cd security-lab
docker-compose up -d
sleep 10

# Run each scenario
for scenario in attack-scenarios/*.sh; do
    echo "Testing: $scenario"
    docker exec intriqo-attacker bash "/scenarios/$(basename $scenario)"
    sleep 5
done

# Capture and parse
docker exec intriqo-traffic-monitor timeout 60 tcpdump -i eth0 -w /pcaps/test.pcap
python3 tools/pcap_parser.py pcaps/test.pcap results.json

# Validate
python3 validate-results.py results.json

# Cleanup
docker-compose down
```

## Performance Benchmarking

### Measure Detection Latency

Future enhancement: Add timing to measure end-to-end detection latency:

```
Traffic Generated → Captured → Parsed → Detected → Event Generated
       T0             T1         T2        T3           T4

Ingestion Latency: T1 - T0
Parsing Latency: T2 - T1
Detection Latency: T3 - T2
Total Latency: T4 - T0
```

## Security Reminders

⚠️ **This lab is for controlled testing only**

- All traffic stays within isolated Docker network
- Attack scripts target only 172.20.0.0/24
- No external network access
- Safe to run on development machines

**Never modify attack scripts to target external IPs**

## Next Steps

1. Complete Phase 2 (Network Ingestion) to automate PCAP → NetworkFlow conversion
2. Add direct PCAP ingestion to DetectionEngine
3. Implement real-time traffic processing
4. Add more attack scenarios (brute force, SYN flood, etc.)
5. Integrate with Python agent layer for autonomous investigation

See [IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md) for development roadmap.
