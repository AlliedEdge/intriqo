# ADR 001 — Modular Monorepo

**Status:** Accepted  
**Date:** 2026-09-30

## Context

Intriqo has four distinct technical layers: a C++ IDS engine, a Python control
plane, a Python agent platform, and a React SOC dashboard.  The early-stage
codebase needs shared infrastructure (CI, contracts, security-lab fixtures,
documentation) without the operational overhead of four separately managed
repositories.

## Decision

We organise the project as a **modular monorepo** with strong architectural
boundaries between layers.  Each layer lives in its own root directory
(`engine/`, `control-plane/`, `agents/`, `frontend/`) with its own build
system, dependency file, and test suite.  Shared artefacts (contracts, scripts,
security-lab, infrastructure) live at the repository root.

## Consequences

**Positive**
- A single `git clone` yields a complete, runnable development environment.
- Cross-layer contract changes are atomic — one commit, one PR, one review.
- CI can gate per-component (path-filtered workflows) without separate repos.
- The security-lab, PCAP fixtures, and benchmark datasets are co-located with
  the code that uses them.

**Negative / mitigations**
- Repository size grows as PCAP/model artefacts accumulate → `.gitignore` and
  Git LFS policies prevent binary blobs from entering the repository.
- Build times increase as all four layers grow → path-filtered CI workflows
  ensure only affected components are rebuilt per PR.

## Alternatives rejected

- **Four separate repos:** Increases operational overhead, complicates
  cross-boundary contract changes, and makes the security-lab harder to share.
- **Single flat package:** Destroys the architectural boundaries the design
  depends on; makes it easy to accidentally couple layers.
