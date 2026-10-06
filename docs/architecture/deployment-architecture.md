# Deployment Architecture

## Local development (current Core v1 runtime)

```
./scripts/start-intriqo.sh
  ├── postgres:5432                         (Docker Compose)
  ├── Control Plane:8000                    (host process)
  ├── Agents                              (host process)
  ├── optional ML worker                  (host process)
  ├── C++ engine                          (host process)
  └── Vite dashboard:5173                 (host process)

Redis, pgAdmin, Prometheus, Grafana, Kafka, and Kubernetes are not Core v1
runtime dependencies. The root Compose file retains optional legacy service
definitions, but the documented launcher does not start them.
```

## Target production topology

```
┌──────────────────────────────────────────────────────────────┐
│  Network tap / mirror port                                    │
└─────────────────┬────────────────────────────────────────────┘
                  │  raw packets
┌─────────────────▼────────────────────────────────────────────┐
│  Intriqo Engine (C++)        — bare-metal or privileged pod   │
│  Requires: NET_RAW capability, access to network interface    │
└─────────────────┬────────────────────────────────────────────┘
                  │  SecurityEvent JSON HTTP/gRPC
┌─────────────────▼────────────────────────────────────────────┐
│  Control Plane (Python/FastAPI)  — host process in Core v1    │
│  Requires: PostgreSQL                                        │
└──────┬──────────────────────────────────┬────────────────────┘
       │  AgentTask                       │  REST/WebSocket
┌──────▼────────────┐          ┌──────────▼───────────────────┐
│  Agent Platform   │          │  SOC Dashboard (React)        │
│  (Python)         │          │  CDN or container             │
└───────────────────┘          └──────────────────────────────┘
```

## Infrastructure services

| Service     | Role                        | Scale              |
|-------------|-----------------------------|--------------------|
| PostgreSQL  | Primary persistence          | Single (+ replica) |
| Redis       | Session cache, rate limiting | Single (+ sentinel)|
| Prometheus  | Metrics scraping             | Single             |
| Grafana     | Metrics visualisation        | Single             |
| Kafka       | Event streaming (future)     | 3-node cluster     |

## Security considerations

- The engine container requires `NET_RAW` capability. All other containers
  run as non-root with minimal capabilities.
- Engine ↔ control-plane communication uses mTLS (future) or VPC-internal
  networking (current).
- The agent platform has no direct network access to the engine or database.
  It communicates only through the control plane API.
- All secrets are injected via environment variables; no secrets in images.
