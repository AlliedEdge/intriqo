# Deployment Architecture

## Local development (current)

```
docker compose up
  ├── postgres:5432
  ├── redis:6379
  └── (optional) prometheus:9090, grafana:3000

Host processes (run manually or via Makefile):
  ├── uvicorn intriqo.api.app:app --port 8000   (control plane)
  ├── python -m intriqo_agents.orchestrator.main (agents — demo only)
  └── npm run dev (frontend — Vite dev server :5173)

Engine:
  make engine-build && ./engine/build/intriqo_engine  (when implemented)
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
│  Control Plane (Python/FastAPI)  — standard container         │
│  Requires: PostgreSQL, Redis                                  │
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
