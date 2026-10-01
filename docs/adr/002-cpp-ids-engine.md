# ADR 002 — C++ for the IDS Engine

**Status:** Accepted  
**Date:** 2026-09-30  
**Supersedes:** Previous architecture (Java Spring Boot detection core)

## Context

The IDS engine must process network packets and maintain flow state at line
rate.  Requirements include:

- Sub-millisecond per-packet processing latency
- Flow table with tens of thousands of concurrent entries
- Zero-copy packet access from libpcap / AF_PACKET / DPDK
- Deterministic memory allocation (no GC pauses)
- Direct SIMD / hardware-accelerated feature extraction
- Future ML inference via ONNX Runtime C++ API

The previous architecture used Java (Spring Boot) for detection.  Java
introduces GC pauses, JVM startup overhead, and an indirect path to raw packet
buffers.  These are fundamental incompatibilities with the performance
requirements above.

## Decision

The IDS engine is implemented in **C++ (C++20)** using CMake as the build
system.  The engine owns:

- Packet capture abstraction (`capture/`)
- Protocol parsing (`packet/`, `protocol/`)
- Network flow construction and lifecycle (`flow/`)
- Feature extraction (`features/`)
- Rule-based detection (`detection/`, `rules/`)
- Statistical anomaly detection primitives (`anomaly/`)
- SecurityEvent generation (`events/`)
- Detection pipeline (`pipeline/`)
- Engine runtime and metrics (`runtime/`, `metrics/`)
- PCAP replay support

The engine does **not** own: authentication, business logic, LLM reasoning,
agent orchestration, database management, or frontend concerns.

## Consequences

**Positive**
- Line-rate packet processing without GC pauses.
- Direct access to libpcap / AF_PACKET zero-copy buffers.
- Clear subsystem boundaries enforced at compile time through namespaces and
  abstract interfaces.
- Future DPDK / XDP integration is architecturally straightforward.
- ONNX Runtime C++ integration for ML inference is first-class.

**Negative / mitigations**
- C++ development velocity is lower than Python for business logic → business
  logic lives in Python; C++ is strictly the performance-sensitive IDS core.
- Cross-boundary communication requires an explicit JSON contract → `contracts/`
  defines the schema; the engine serialises to it.
- More complex CI setup → `cpp.yml` workflow handles multi-compiler,
  multi-configuration, and ASAN builds.

## Alternatives rejected

- **Java (Spring Boot):** GC pauses, JVM startup, indirect packet access.
  Insufficient for line-rate packet processing.
- **Python (Scapy/dpkt):** Too slow for production packet rates; useful only
  for PCAP parsing tooling (retained in `security-lab/tools/`).
- **Rust:** Viable alternative; rejected in favour of C++ due to existing team
  expertise and mature DPDK/libpcap ecosystem.  May be reconsidered.
