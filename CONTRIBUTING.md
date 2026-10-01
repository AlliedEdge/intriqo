# Contributing to Intriqo

Thank you for your interest in contributing to Intriqo!

## Architectural Principles

1. **Clean Modular Monorepo**: All subsystems reside within this repository with strict, explicit boundaries.
2. **C++ for Packet & Flow Processing**: The IDS engine (`engine/`) is written in modern C++20. It must not own user auth, dashboard logic, or agent workflows.
3. **Python for Control Plane & Agents**: FastAPI (`control-plane/`) provides system APIs. Autonomous agents (`agents/`) execute through structured, validated tools only.
4. **Typed Cross-Boundary Contracts**: Communication across subsystem boundaries must adhere to schemas in `contracts/`.
5. **No Arbitrary Agent Execution**: Security agents propose actions; deterministic policy boundaries authorize them.

## Development Workflow

1. Fork and clone the repository.
2. Run `make setup` or `./scripts/dev/setup.sh` to configure virtual environments and tools.
3. Verify test suites pass:
   - `make test-engine` (C++ unit tests)
   - `make test-agents` (Python agent tests)
   - `make test-control-plane` (Control plane tests)
4. Submit pull requests using the provided PR template.
