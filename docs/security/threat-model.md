# Security Threat Model

## System Boundaries & Threat Surface

### 1. Packet Ingestion
- **Threat**: Malformed packets designed to crash the C++ parser (buffer overflow, denial of service).
- **Mitigation**: Bounds-checked slicing, memory-safe C++20 abstractions, fuzz testing, AddressSanitizer (ASan) in CI.

### 2. Autonomous Agents
- **Threat**: Prompt injection via network payload content causing agents to execute unauthorized defensive actions.
- **Mitigation**: Strict structured tool interfaces; response execution requires explicit deterministic policy verification; high-impact actions mandate human SOC analyst approval.

### 3. Control Plane API
- **Threat**: Unauthorized API access or privilege escalation.
- **Mitigation**: JWT/OAuth2 authentication, strict RBAC, rate limiting, and immutable audit logs.
