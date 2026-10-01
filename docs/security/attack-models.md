# Attack Models & Scenarios

Intriqo evaluates intrusion detection through explicit attack models:

1. **Reconnaissance / Port Scanning**:
   - Horizontal and vertical port sweeps (TCP SYN, ACK, FIN scans).
   - Evaluated using `security-lab/scenarios/` and `pcaps/`.

2. **Credential Brute Force**:
   - High-frequency authentication attempts across SSH/RDP/Web.
   - Identified by statistical anomaly detectors and correlation agents.

3. **Data Exfiltration**:
   - Anomalous outbound byte ratios over non-standard ports or DNS tunneling.
