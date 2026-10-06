# Intriqo Core v1 repository hygiene report

Validation date: 2026-10-06. This is a read-only inventory report for the
release-candidate workspace. No commit or push was performed.

## Git state

- Branch: `main`, aligned with `origin/main` before this validation work.
- The working tree contains the completed Core v1 implementation plus the
  validation documentation, runtime hardening, and focused regression tests.
- `git diff --check` passed during the audit.
- No files were staged, committed, or pushed.
- Temporary runtime state is ignored under `.intriqo*/`; build and frontend
  outputs are ignored under `build/` and `frontend/**/dist/`.

## Inventory and classification

| Category | Locations | Classification |
|---|---|---|
| Core source | `engine/`, `control-plane/src/`, `agents/src/`, `ml/src/`, `frontend/dashboard/src/` | CORE SOURCE |
| Tests | `engine/tests/`, `control-plane/tests/`, `agents/tests/`, `ml/tests/`, `tests/e2e/` | TEST |
| Contracts/config | `contracts/`, `docker-compose.yml`, `.env.example`, `pyproject.toml`, `package.json` | CONFIGURATION |
| Documentation | `README.md`, `docs/`, `security-lab/controlled_v2/README.md` | DOCUMENTATION |
| Locked local artifacts | `ml/artifacts/models/controlled-v2/`, `ml/artifacts/feature-analysis/controlled-v2/` | MODEL/EXPERIMENT ARTIFACT; ignored local inputs |
| Controlled lab tooling | `security-lab/controlled_v2/` | LOCAL-ONLY TOOLING; no raw captures in Git |
| Generated output | `build/`, `frontend/dashboard/dist/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `.intriqo*/` | GENERATED OUTPUT / LOCAL-ONLY |

The workspace contains local ignored `.env` files and runtime service-token
files for development. They were not tracked, are not included in this report,
and were not copied into source or documentation. Local environment files were
permission-hardened to mode `0600` during validation.

## Secret and path audit

- Tracked `.env`-like files: none.
- Tracked private-key markers: none.
- Tracked JWT-looking bearer values: none.
- Tracked absolute machine paths: documentation contains historical
  validation/provenance paths; source/configuration does not depend on them.
- Raw controlled-v2 PCAPs are outside the repository in the authorized
  `/tmp/opencode/intriqo-controlled-v2/raw` location. Repository benchmark PCAP
  outputs are ignored and are not tracked.
- No runtime SQLite ledger, service token, password, or private key is tracked.

## Protected artifact result

The local locked files were regular non-symlink files with mode `0600` and the
following observed SHA-256 values:

```text
model.joblib     69d7df6a027eebcaa64c227c3ab34d8a9fd44d4a0158264e86c3fb93db960cb5
threshold.json   28ebd68f65e255e9c32aa433b609c4dc969402605d936b8d49c357c5979058b2
flow_features_v2.json
                 67b96b59fce896ba33fdfd93cb445eeab901a2cee2c5b3347267622e0a140924
```

The v1 feature contract and the controlled-v2 manifest were not modified by
the validation. The model and research artifact directories are ignored local
inputs rather than distributable Git contents; a release package would need an
explicit artifact registry/provenance decision.

## Hygiene conclusion

No secret-tracking or raw-PCAP-tracking release blocker was observed. The
working tree is intentionally uncommitted and therefore is not itself a clean
release checkout; review and commit the intended source, tests, and
documentation as one controlled change before tagging.
