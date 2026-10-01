# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Please report security issues responsibly. Do NOT disclose security vulnerabilities via public GitHub issues.

To report a vulnerability:
1. Email security vulnerability reports to `security@intriqo.local` (or create a private GitHub Security Advisory).
2. Include reproduction steps, affected components (e.g. C++ engine, agent tool sandboxing, control-plane RBAC), and potential impact.
3. The project maintainers will acknowledge receipt within 48 hours and provide remediation timelines.

## Security Architecture Principles

- **Agent Isolation**: Autonomous reasoning agents do not have raw shell access, network access, or direct database write access.
- **Deterministic Response Policy**: Automated mitigation actions must pass through validation and human-in-the-loop approvals when risk thresholds are exceeded.
- **Audit Immutability**: All security actions and agent execution traces are append-only.
