# Scalability Architecture

Intriqo is structured as a modular monorepo that scales vertically first, then horizontally where performance profiles dictate:

## Layer Scalability Profiles
1. **C++ IDS Engine (`engine/`)**:
   - Zero-copy packet parsing where supported.
   - Core-pinned worker threads with lockless ring buffers.
   - Flow hash tables partitioned by thread affinity (RSS / software hashing).

2. **FastAPI Control Plane (`control-plane/`)**:
   - Asynchronous I/O via `asyncio`.
   - Scalable through standard stateless horizontal replication behind reverse proxies.

3. **Autonomous Agent Platform (`agents/`)**:
   - Asynchronous agent execution workers.
   - Task queues allowing concurrent multi-agent investigations without blocking the detection loop.
