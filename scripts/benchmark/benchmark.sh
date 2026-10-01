#!/usr/bin/env bash
set -euo pipefail

echo "=== Running Intriqo Performance Benchmarks ==="

# Build C++ engine benchmarks if enabled
if [ -d "engine/build" ]; then
    echo "Running C++ Engine Benchmarks..."
    if [ -f "engine/build/engine/benchmarks/engine_benchmarks" ]; then
        ./engine/build/engine/benchmarks/engine_benchmarks
    else
        echo "Engine benchmarks binary not compiled. Configure with -DINTRIQO_BUILD_BENCHMARKS=ON."
    fi
fi

# Run agent orchestration benchmarks if present
if [ -d ".venv" ]; then
    . .venv/bin/activate
fi

if [ -f "benchmarks/agents/benchmark_orchestrator.py" ]; then
    echo "Running Agent Orchestration Benchmarks..."
    python benchmarks/agents/benchmark_orchestrator.py
fi

echo "=== Benchmarks complete ==="
