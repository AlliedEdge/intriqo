# Intriqo Controlled Security Lab

A Dockerized cybersecurity testing environment for validating detection capabilities in a safe, isolated, and reproducible manner.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              Isolated Lab Network                   │
│                 172.20.0.0/24                       │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────┐         ┌──────────────┐         │
│  │   Attacker   │────────>│  Victim Web  │         │
│  │ 172.20.0.10  │         │ 172.20.0.20  │         │
│  └──────────────┘         └──────────────┘         │
│         │                                           │
│         │                 ┌──────────────┐         │
│         ├────────────────>│  Victim DB   │         │
│         │                 │ 172.20.0.21  │         │
│         │                 └──────────────┘         │
│         │                                           │
│         │                 ┌──────────────┐         │
│         ├────────────────>│  Victim SSH  │         │
│         │                 │ 172.20.0.22  │         │
│         │                 └──────────────┘         │
│         │                                           │
│         │                 ┌──────────────┐         │
│         └────────────────>│  Victim App  │         │
│                           │ 172.20.0.23  │         │
│                           └──────────────┘         │
│                                                     │
│  ┌──────────────────────────────────────────────┐  │
│  │         Traffic Monitor                      │  │
│  │         172.20.0.100                         │  │
│  │         (PCAP Capture)                       │  │
│  └──────────────────────────────────────────────┘  │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Components

### Attacker Container (`172.20.0.10`)
- **Purpose:** Execute controlled attack scenarios
- **Tools:** nmap, hping3, netcat, tcpdump, curl, python3, scapy
- **Role:** Simulates malicious actor performing reconnaissance and attacks

### Victim Containers
- **victim-web** (`172.20.0.20`): Web services (HTTP 80, 443, 8080, 8443)
- **victim-db** (`172.20.0.21`): Database services (MySQL, PostgreSQL, MongoDB, Redis)
- **victim-ssh** (`172.20.0.22`): SSH services (ports 22, 2222)
- **victim-app** (`172.20.0.23`): Application services (ports 8000-8005)

### Traffic Monitor (`172.20.0.100`)
- **Purpose:** Capture and analyze network traffic
- **Capabilities:** PCAP generation, traffic analysis
- **Output:** PCAP files in `pcaps/` directory

## Quick Start

### 1. Start the Lab

```bash
cd security-lab
docker-compose up -d
```

**Verify all containers are running:**
```bash
docker-compose ps
```

Expected output:
```
NAME                      STATUS
intriqo-attacker          Up
intriqo-victim-web        Up
intriqo-victim-db         Up
intriqo-victim-ssh        Up
intriqo-victim-app        Up
intriqo-traffic-monitor   Up
```

### 2. Run Attack Scenario

```bash
# Port scan attack (should trigger detection)
docker exec intriqo-attacker bash /scenarios/port-scan.sh

# Multi-target scan
docker exec intriqo-attacker bash /scenarios/port-scan-multi-target.sh

# Normal traffic (should NOT trigger detection)
docker exec intriqo-attacker bash /scenarios/normal-traffic.sh
```

### 3. Capture Traffic (Optional)

In one terminal, start traffic capture:
```bash
docker exec intriqo-traffic-monitor /scripts/monitor.sh
```

In another terminal, run scenarios:
```bash
docker exec intriqo-attacker bash /scenarios/port-scan.sh
```

PCAP files are saved to `security-lab/pcaps/`

### 4. Stop the Lab

```bash
docker-compose down
```

To also remove volumes:
```bash
docker-compose down -v
```

## Integrating with Detection Engine

### Method 1: Parse PCAP Files

```bash
# Extract flows from PCAP
python3 tools/pcap_parser.py pcaps/capture.pcap flows.json

# Flows are now in JSON format compatible with NetworkFlow
```

### Method 2: Direct Traffic Capture (Future)

Future implementation will include direct integration where captured traffic is immediately fed to the detection engine.

## Attack Scenarios

See [attack-scenarios/README.md](attack-scenarios/README.md) for detailed scenario documentation.

| Scenario | File | Expected Detection |
|---|---|---|
| Port Scan | `port-scan.sh` | ✅ PORT_SCAN events (HIGH confidence) |
| Multi-Target Scan | `port-scan-multi-target.sh` | ✅ Multiple PORT_SCAN events |
| Normal Traffic | `normal-traffic.sh` | ❌ No detections |

## Network Configuration

| Container | IP Address | Services |
|---|---|---|
| Attacker | 172.20.0.10 | Attack tools |
| Victim Web | 172.20.0.20 | HTTP (80, 443, 8080, 8443) |
| Victim DB | 172.20.0.21 | MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379) |
| Victim SSH | 172.20.0.22 | SSH (22, 2222) |
| Victim App | 172.20.0.23 | Application (8000-8005) |
| Monitor | 172.20.0.100 | Traffic capture |

**Network:** `172.20.0.0/24` (isolated bridge network)

## Tools

### PCAP Parser (`tools/pcap_parser.py`)

Converts PCAP files to JSON format compatible with NetworkFlow domain model.

**Usage:**
```bash
python3 tools/pcap_parser.py capture.pcap [output.json]
```

**Output Format:**
```json
{
  "source": "capture.pcap",
  "extractedAt": "2025-01-15T10:30:00Z",
  "flowCount": 42,
  "flows": [
    {
      "timestamp": "2025-01-15T10:29:30Z",
      "sourceAddress": "172.20.0.10",
      "destinationAddress": "172.20.0.20",
      "sourcePort": 54321,
      "destinationPort": 80,
      "protocol": "TCP",
      "packetCount": 3,
      "byteCount": 192,
      "durationMillis": 50
    }
  ]
}
```

## Security Considerations

⚠️ **IMPORTANT:** This environment is designed for controlled testing ONLY.

- **Isolated Network:** All containers run on an isolated Docker network
- **No External Access:** Lab cannot reach external networks
- **Controlled Attacks:** Attack scenarios target only lab infrastructure
- **Safe to Execute:** No risk to production systems

**DO NOT:**
- Modify attack scripts to target external IPs
- Connect lab network to production networks
- Use attack scripts outside this environment
- Share attack tools without context

## Troubleshooting

### Containers Won't Start

```bash
# Check logs
docker-compose logs

# Rebuild containers
docker-compose build --no-cache
docker-compose up -d
```

### Cannot Execute Scenarios

```bash
# Ensure scripts are executable
chmod +x attack-scenarios/*.sh
chmod +x tools/*.py

# Check attacker container is running
docker exec intriqo-attacker echo "Container is accessible"
```

### No Traffic Captured

```bash
# Verify monitor is running
docker exec intriqo-traffic-monitor tcpdump -D

# Check pcaps directory permissions
ls -la pcaps/
```

### Port Scan Not Detected

- Ensure threshold is configured correctly (default: 10 ports)
- Verify flows are being extracted from PCAP
- Check that scan actually contacted 10+ distinct ports:
  ```bash
  python3 tools/pcap_parser.py pcaps/capture.pcap
  # Look for "Distinct destination ports" count
  ```

## Development Workflow

1. **Start Lab:** `docker-compose up -d`
2. **Run Scenario:** Execute attack scenario
3. **Capture Traffic:** Optional PCAP capture
4. **Extract Flows:** Parse PCAP to JSON
5. **Test Detection:** Feed flows to DetectionEngine
6. **Verify Events:** Check SecurityEvent generation
7. **Iterate:** Modify detector thresholds, retest
8. **Stop Lab:** `docker-compose down`

## Future Enhancements

- [ ] Real-time traffic streaming to detection engine
- [ ] SSH brute force scenario
- [ ] SYN flood DoS scenario
- [ ] DNS tunneling scenario
- [ ] Lateral movement simulation
- [ ] Automated scenario execution framework
- [ ] Grafana dashboard for live traffic visualization
- [ ] Integration with Python agent layer (when implemented)

## Directory Structure

```
security-lab/
├── docker-compose.yml           # Lab orchestration
├── README.md                    # This file
├── containers/
│   ├── attacker/                # Attacker container
│   │   └── Dockerfile
│   ├── victim/                  # Victim container
│   │   ├── Dockerfile
│   │   └── entrypoint.sh
│   └── monitor/                 # Traffic monitor
│       ├── Dockerfile
│       └── monitor.sh
├── attack-scenarios/            # Attack scripts
│   ├── README.md
│   ├── port-scan.sh
│   ├── port-scan-multi-target.sh
│   └── normal-traffic.sh
├── tools/                       # Analysis tools
│   └── pcap_parser.py
├── pcaps/                       # Captured traffic (generated)
└── traffic-data/                # Analysis output (generated)
```

## Support

For issues or questions:
1. Check this README
2. Review attack-scenarios/README.md
3. Check Docker logs: `docker-compose logs`
4. Verify network connectivity: `docker network inspect security-lab_lab_network`
