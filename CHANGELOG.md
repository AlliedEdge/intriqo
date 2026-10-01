# Changelog

All notable changes to the Intriqo autonomous SOC platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-01

### Added
- **Architecture Redesign**: Migrated from legacy monolithic Java detection backend to hybrid C++ / Python architecture.
- **C++ Engine Subsystem (`engine/`)**: Modern C++20 IDS detection core scaffolding with packet capture, protocol parsing, flow lifecycle management, feature extraction, and security event generation.
- **Python Control Plane (`control-plane/`)**: FastAPI application platform owning authentication, RBAC, domain services, audit logging, and engine/agent coordination.
- **Autonomous Agent Platform (`agents/`)**: Python-based multi-agent investigation system featuring deterministic tool execution boundaries, security event adaptation, and orchestrator.
- **React SOC Dashboard (`frontend/dashboard/`)**: Feature-driven SOC dashboard structured around incidents, investigations, approvals, detections, agents, and audit logs.
- **Contract Specifications (`contracts/`)**: Versioned schemas (`SecurityEvent`, `AgentTask`, `AgentResult`, `ActionRequest`, `PolicyDecision`) defining strict layer boundaries.
- **Architecture Decision Records (ADRs)**: Documented ADR-001 through ADR-006 detailing all architectural choices and trade-offs.
- **Security Scaffolding**: Policy boundaries preventing arbitrary agent tool execution and enforcing human-in-the-loop approvals for active responses.
