# Review-2 requirements matrix

This matrix distinguishes repository evidence from work that is only planned or
environment-gated. It does not turn a test fixture, a UI count, or a design
intention into a production claim.

| Requirement | Implementation | Test/Evidence | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| Isolated attacker/victim lab | Existing controlled-v2 topology with `demo` profile; `intriqo-attacker`, `intriqo-victim`, private `br-intriqo` | `./scripts/lab/status.sh --verify`; topology verifier | Namespaces and fixed addresses are present | Shell/Python checks pass; privileged live execution is host-gated here | IMPLEMENTED / ENVIRONMENT-GATED |
| Fixed addresses | `10.77.0.10/24` → `10.77.0.20/24` | `topology.py` address checks; traffic helper constants | No caller-selected target | Target arguments are rejected; constants are fixed | VALIDATED BY CODE/TESTS |
| No physical-network route | Forwarding/IPv6 disabled; no default or external route | Topology route/rule checks; kernel-only external route lookup | Attack traffic cannot use host default route | Verifier blocks unsafe routes | VALIDATED BY CONTROLLED LAB VERIFIER |
| Bidirectional mirror | `tc matchall` + `mirred mirror` on both switch ports to `tap-intriqo` | Exact JSON/text `tc` filter checks; monitor RX delta | Both directions reach the monitor | Verifier requires both ingress mirrors and a real probe delta | VALIDATED BY VERIFIER WHEN PRIVILEGED |
| Idempotent lifecycle | `scripts/lab/{setup,up,down,status,reset}.sh` | `bash -n`; owned marker/inode logic | Repeated setup/up reuses verified lab | Repeated verified state is reused; ambiguous partial state fails closed | IMPLEMENTED |
| Actual health status | `status.sh` reports namespace, bridge, TAP, mirror, ping, and probe checks | `status.sh --verify` | No false `READY`/`ONLINE` output | Output is derived from topology evidence | IMPLEMENTED |
| Deterministic port scan | Fixed 10-port bounded raw-SYN generator | Engine detector defaults: 10 unique ports/10 attempts/10s | Existing `PORT_SCAN` detector can fire naturally | Generator parameters are aligned; live event requires privileged runtime run | IMPLEMENTED / ENVIRONMENT-GATED |
| Deterministic SYN flood | Existing traffic helper with additive unique-source-port mode | Detector defaults: 100 attempts, 50/s, 50 incomplete, 1s observation | Existing `SYN_FLOOD` detector can fire naturally | Generator parameters are aligned; live event requires privileged runtime run | IMPLEMENTED / ENVIRONMENT-GATED |
| C++ engine on TAP | Additive `INTRIQO_ENGINE_NAMESPACE` launcher support; existing engine binary and HTTP sink | `start-demo.sh`; engine log/readiness | `INTRIQO-LAB-01` observes `tap-intriqo` | Launcher path implemented; live libpcap/namespace run is environment-gated | IMPLEMENTED / ENVIRONMENT-GATED |
| Control Plane persistence | Existing authenticated `/api/v1/events`, PostgreSQL, deduplication, correlation | Control Plane integration tests; smoke flow | Real events are persisted and linked | Existing RC path persists real events | VALIDATED BY EXISTING SUITE |
| Incident correlation | Existing deterministic correlation service | `control-plane/tests/integration/test_soc_workflow.py`, incident tests | `PORT_SCAN`/`SYN_FLOOD` create or reuse an incident | Existing active-incident correlation is preserved | VALIDATED BY EXISTING SUITE |
| Analyst task creation | Existing `/agent-tasks` endpoint plus dashboard action | RBAC tests; frontend workflow tests | Analyst can link an `INVESTIGATION` task to event/incident | UI action uses the real API and refreshes persisted data | VALIDATED BY TESTS |
| Agent investigation | Existing polling agent and detector-specific handlers | Agents tests; runtime smoke evidence | Task becomes `COMPLETED` and finding is persisted | Existing agent identity remains separate from analyst | VALIDATED BY EXISTING SUITE |
| Findings | Existing Finding contract and provenance fields | Finding integration tests; dashboard finding page | Evidence, confidence, source, detector, and links are visible | Existing API/UI path is reused | VALIDATED BY EXISTING SUITE |
| Audit traceability | Append-only event/incident/task/finding audit records | Audit integration tests; resource audit pages | Event → incident → task → finding is traceable | Existing audit records are rendered without fabricated entries | VALIDATED BY EXISTING SUITE |
| Incident lifecycle | Existing Control Plane state machine plus dashboard next-state controls | Incident transition tests; frontend lifecycle helper tests | Analyst can perform only permitted next transitions | UI offers API-allowed transitions and surfaces errors | VALIDATED BY TESTS |
| Authentication | Existing JWT/password/email verification flow | Auth unit/integration/security tests | Protected SOC routes require an authenticated user | Existing behavior is unchanged | VALIDATED BY EXISTING SUITE |
| Public registration cannot choose ADMIN | `UserCreate` ignores unknown/legacy role input; service assigns `ANALYST` | Auth and privilege-escalation tests | Public registration cannot elevate role | Existing tests cover the boundary | VALIDATED BY EXISTING SUITE |
| Analyst RBAC | Existing `AnalystUser`/`AgentUser` dependencies | `test_rbac.py`; frontend displays actual role | Analyst can view/investigate/update permitted incidents; admin-only routes remain protected | No RBAC weakening introduced | VALIDATED BY EXISTING SUITE |
| Agent identity separation | Distinct `AGENT` runtime token and `ANALYST` operator token | Runtime token bootstrap; RBAC matrix | Machine task execution is not human admin access | Existing launcher creates distinct development identities | VALIDATED BY EXISTING RUNTIME |
| ML worker readiness | Existing locked Isolation Forest v2 worker and status file | `ml/tests`; runtime recovery evidence | `READY` only after artifact/model/schema/hash checks | Locked model, threshold, schema, and corpus are untouched | VALIDATED BY EXISTING SUITE |
| ML event persistence | Existing worker posts authenticated `ML_ANOMALY` to `/api/v1/events` | ML integration/replay tests; runtime recovery evidence | Real anomaly can be promoted by analyst and investigated | Existing evidence records this path; live replay remains environment-gated | VALIDATED / ENVIRONMENT-GATED |
| ML failure isolation | ML is separate bounded file worker; C++ deterministic path is independent | `docs/ml-inference-integration.md`; runtime recovery evidence | Worker failure does not disable deterministic detection | Architecture and existing failure tests support the boundary | VALIDATED BY EXISTING EVIDENCE |
| Performance: C++ | Existing release benchmark, not live-lab capacity | `docs/engine/capture-hardening-validation.md` | Report measured environment and workload, not a universal limit | Candidate medians include 1,632,097.35 synthetic packets/s and 1,767,229.16 PCAP packets/s in the recorded environment | VALIDATED BENCHMARK |
| Performance: ML | Existing 26-record native-v2 measurement | `docs/ml-inference-integration.md` | Report model/inference metrics with limitations | 19.6 ms median, 19.9 ms p95, 49.6 scorer records/s, 51.1 one-pass records/s | VALIDATED BENCHMARK |
| Recovery | Existing lifecycle scripts and bounded retry/state behavior | `docs/runtime-recovery.md`; runtime stack tests | Services fail visibly and recover without manual DB edits | Existing RC recovery evidence is documented | VALIDATED BY EXISTING EVIDENCE |
| Security boundaries | No arbitrary targets, raw DB edits, public routes, or autonomous remediation added | Shell guards; auth/RBAC/security tests | Demo remains authorized and bounded | New generators fail closed and do not accept target input | VALIDATED BY CODE/TESTS |
| Scalability | Single host, one sensor, bounded local runtime | Architecture/ADR docs | State the limit instead of overclaiming | Single-sensor / bounded deployment validated; distributed horizontal scaling is future work | LIMITATION |
| Production network deployment | Real SPAN/TAP placement procedure | `docs/demo-lab.md` architecture boundary | Administrator deploys sensor; analyst operates SOC | Not claimed by this repository | PLANNED / OUT OF SCOPE |
| Distributed deployment | Brokers, Kubernetes, multi-sensor fleet, horizontal scale | ADR 006 and scalability docs | Future work only when measured need exists | Not introduced for the demo | PLANNED |

## Release-candidate checks

The relevant existing check families are:

```bash
# Engine
cmake -S . -B build/intriqo-runtime-release \
  -DCMAKE_BUILD_TYPE=Release -DINTRIQO_BUILD_TESTS=ON
cmake --build build/intriqo-runtime-release --parallel
ctest --test-dir build/intriqo-runtime-release --output-on-failure

# Control Plane, Agents, and ML (use the repository virtual environments)
control-plane/.venv/bin/python -m pytest -q control-plane/tests
control-plane/.venv/bin/python -m pytest -q agents/tests
PYTHONPATH=ml/src control-plane/.venv/bin/python -m pytest -q ml/tests -c ml/pyproject.toml

# Frontend
(cd frontend/dashboard && npm run typecheck && npm test -- --run && npm run lint)

# New shell/static checks
bash -n scripts/start-demo.sh scripts/lab/*.sh
python3 -m py_compile security-lab/controlled_v2/topology.py \
  security-lab/controlled_v2/traffic.py
git diff --check
```

The exact results of checks run for the current working tree are reported in
the implementation summary. A check is not marked passed here merely because a
command is listed; environment-gated failures remain visible.
