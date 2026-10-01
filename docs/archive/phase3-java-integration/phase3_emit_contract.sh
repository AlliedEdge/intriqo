#!/usr/bin/env bash
#
# Phase 3 integration helper.
#
# Runs the REAL Java detection pipeline over the Phase 2 Security Lab fixtures and
# writes the resulting SecurityEvent JSON contract (JSON Lines) to:
#
#   build/phase3-contract/port-scan-events.jsonl
#   build/phase3-contract/normal-traffic-events.jsonl
#
# The Python end-to-end test (agents/tests/test_phase3_e2e.py) reads these artefacts,
# so the contract has a single source of truth: the actual Java output.
#
# Usage:
#   scripts/phase3_emit_contract.sh
#
# Exit codes:
#   0  artefacts written
#   1  Java pipeline or Gradle failed

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ARTIFACT_DIR="build/phase3-contract"
PORT_SCAN_FIXTURE="security-lab/traffic-data/port-scan-flows.json"
NORMAL_FIXTURE="security-lab/traffic-data/normal-traffic-flows.json"
THRESHOLD=10
TIME_WINDOW=300

if [[ ! -f "$PORT_SCAN_FIXTURE" ]]; then
  echo "error: missing Phase 2 fixture: $PORT_SCAN_FIXTURE" >&2
  exit 1
fi
if [[ ! -f "$NORMAL_FIXTURE" ]]; then
  echo "error: missing Phase 2 fixture: $NORMAL_FIXTURE" >&2
  exit 1
fi

mkdir -p "$ARTIFACT_DIR"

# Run the real pipeline via the Gradle JavaExec task. Logging goes to stderr; the
# contract JSON Lines are the only stdout content we care about, so we capture stdout
# through a temp file and strip the Gradle/log noise.
echo "==> Emitting real Java SecurityEvent contract for port-scan fixture" >&2
./gradlew emitSecurityEvents \
  -Pfixture="$PORT_SCAN_FIXTURE" \
  -Pthreshold="$THRESHOLD" \
  -PtimeWindow="$TIME_WINDOW" \
  --console=plain -q > "$ARTIFACT_DIR/port-scan-raw.log" 2>&1

# Extract JSON Lines (lines starting with '{'), which are the contract objects.
grep '^{' "$ARTIFACT_DIR/port-scan-raw.log" > "$ARTIFACT_DIR/port-scan-events.jsonl" || true

echo "==> Emitting real Java SecurityEvent contract for normal-traffic fixture" >&2
./gradlew emitSecurityEvents \
  -Pfixture="$NORMAL_FIXTURE" \
  -Pthreshold="$THRESHOLD" \
  -PtimeWindow="$TIME_WINDOW" \
  --console=plain -q > "$ARTIFACT_DIR/normal-traffic-raw.log" 2>&1

grep '^{' "$ARTIFACT_DIR/normal-traffic-raw.log" > "$ARTIFACT_DIR/normal-traffic-events.jsonl" || true
# Count events. Use awk to avoid fragile shell quoting around tr/wc.

PORT_COUNT=$(grep -c '^{' "$ARTIFACT_DIR/port-scan-events.jsonl" || true)
NORMAL_COUNT=$(grep -c '^{' "$ARTIFACT_DIR/normal-traffic-events.jsonl" || true)

echo "==> port-scan-events.jsonl: $PORT_COUNT event(s)" >&2
echo "==> normal-traffic-events.jsonl: $NORMAL_COUNT event(s)" >&2
echo "==> Phase 3 contract artefacts written to $ARTIFACT_DIR/" >&2

# Fail loudly if the expectation is violated: a real port scan must emit at least one
# event, and normal traffic must emit none. This keeps the Python test honest.
if [[ "$PORT_COUNT" -lt 1 ]]; then
  echo "error: expected at least one SecurityEvent from the port-scan fixture" >&2
  exit 1
fi
if [[ "$NORMAL_COUNT" -ne 0 ]]; then
  echo "error: expected zero SecurityEvents from the normal-traffic fixture" >&2
  exit 1
fi

exit 0
