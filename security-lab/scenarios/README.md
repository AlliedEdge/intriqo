# Attack Scenarios

This directory contains controlled attack scenarios for testing Intriqo's detection capabilities.

**⚠️ IMPORTANT:** These scenarios are designed to run ONLY within the controlled security lab environment. Do not execute these scripts against real infrastructure.

## Available Scenarios

### 1. Port Scan (`port-scan.sh`)

Simulates reconnaissance phase of an attack by scanning multiple ports on a single target.

**Usage:**
```bash
docker exec intriqo-attacker /scenarios/port-scan.sh [target] [scan_type]
```

**Examples:**
```bash
# Default target (victim-web)
docker exec intriqo-attacker /scenarios/port-scan.sh

# Specific target
docker exec intriqo-attacker /scenarios/port-scan.sh 172.20.0.21

# Different scan type
docker exec intriqo-attacker /scenarios/port-scan.sh 172.20.0.20 syn
```

**Expected Detection:**
- Multiple `PORT_SCAN` security events
- High confidence scores
- Source: 172.20.0.10 (attacker)
- Distinct port count exceeding threshold

### 2. Multi-Target Port Scan (`port-scan-multi-target.sh`)

Scans multiple hosts across the lab network, simulating network reconnaissance.

**Usage:**
```bash
docker exec intriqo-attacker /scenarios/port-scan-multi-target.sh
```

**Expected Detection:**
- Multiple `PORT_SCAN` events (one per target)
- All from same source IP
- Demonstrates independent tracking per target

### 3. Normal Traffic (`normal-traffic.sh`)

Simulates legitimate user activity across various services.

**Usage:**
```bash
docker exec intriqo-attacker /scenarios/normal-traffic.sh
```

**Expected Detection:**
- **NO** port scan detections
- Traffic uses same ports repeatedly
- Does not exceed distinct port threshold

## Running Scenarios

### Start the Lab

```bash
cd security-lab
docker-compose up -d
```

### Execute a Scenario

```bash
# Make scripts executable (first time only)
chmod +x attack-scenarios/*.sh

# Run port scan scenario
docker exec intriqo-attacker bash /scenarios/port-scan.sh

# Run normal traffic
docker exec intriqo-attacker bash /scenarios/normal-traffic.sh

# Run multi-target scan
docker exec intriqo-attacker bash /scenarios/port-scan-multi-target.sh
```

### Capture Traffic

```bash
# Start traffic capture
docker exec intriqo-traffic-monitor /scripts/monitor.sh

# Run scenario in another terminal
docker exec intriqo-attacker bash /scenarios/port-scan.sh

# PCAP files saved to security-lab/pcaps/
```

### Stop the Lab

```bash
docker-compose down
```

## Integration with Detection Engine

To test these scenarios with the Java detection engine:

1. Capture traffic during scenario execution (see above)
2. Parse PCAP files to extract NetworkFlow objects
3. Feed flows to DetectionEngine
4. Verify SecurityEvent generation

Example integration flow:

```
Attack Scenario (Docker)
        ↓
  Traffic Capture (PCAP)
        ↓
  PCAP Parser (Python/Java)
        ↓
  NetworkFlow objects
        ↓
  DetectionEngine.processFlow()
        ↓
  SecurityEvent validation
```

## Scenario Design Principles

Each scenario follows these principles:

1. **Controlled** — Runs only within isolated lab network
2. **Reproducible** — Produces consistent detection results
3. **Documented** — Clear expected outcomes
4. **Realistic** — Mirrors real-world attack patterns
5. **Safe** — No risk to production systems

## Adding New Scenarios

When creating new attack scenarios:

1. Use only lab IPs (172.20.0.0/24)
2. Document expected detection behavior
3. Add to this README
4. Test against DetectionEngine before committing
5. Ensure scenario completes within reasonable time

## Future Scenarios (Planned)

- SSH brute force attack
- DNS tunneling/exfiltration
- SYN flood DoS
- Lateral movement simulation
- Credential stuffing
- Service exploitation attempts
