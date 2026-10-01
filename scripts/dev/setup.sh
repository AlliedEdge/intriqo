#!/usr/bin/env bash
set -euo pipefail

echo "=== Setting up Intriqo Development Environment ==="

# Check for C++ toolchain
echo -n "Checking C++ compiler... "
if command -v c++ >/dev/null 2>&1; then
    echo "$(c++ --version | head -n1)"
else
    echo "WARNING: C++ compiler not found. Install g++ or clang++."
fi

# Check for CMake
echo -n "Checking CMake... "
if command -v cmake >/dev/null 2>&1; then
    echo "$(cmake --version | head -n1)"
else
    echo "WARNING: CMake not found. Install cmake >= 3.25."
fi

# Check for Python
echo -n "Checking Python... "
if command -v python3 >/dev/null 2>&1; then
    echo "$(python3 --version)"
else
    echo "WARNING: Python 3 not found."
fi

# Setup Python virtualenv if not present
if [ ! -d ".venv" ]; then
    echo "Creating Python virtual environment (.venv)..."
    python3 -m venv .venv
fi

echo "Activating virtualenv and installing python dependencies in editable mode..."
. .venv/bin/activate
pip install --upgrade pip -q
pip install -e "agents[dev]" -q
pip install -e "control-plane[dev]" -q

echo "=== Setup complete ==="
