#!/usr/bin/env bash
# run_tests.sh — Run migrations + full test suite
# Execute this from your terminal (not via Kiro tools) since it needs Docker network access.
#
# Usage:
#   cd control-plane
#   ./run_tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV=".venv/bin"

echo "=== Intriqo Control Plane — Test Runner ==="
echo ""

# 1. Run Alembic migration
echo ">>> Running Alembic migration..."
"$VENV/alembic" upgrade head
echo "    Migration complete."
echo ""

# 2. Run unit tests (no DB)
echo ">>> Running unit tests..."
"$VENV/pytest" tests/unit/ -v
echo ""

# 3. Run integration tests (requires DB)
echo ">>> Running integration tests..."
TEST_DATABASE_URL="postgresql+asyncpg://intriqo:intriqo_dev@localhost:5432/intriqo" \
  "$VENV/pytest" tests/integration/ -v
echo ""

echo "=== All tests complete ==="
