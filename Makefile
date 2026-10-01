# =============================================================================
# Intriqo — Root Makefile
#
# Provides convenient top-level targets for the four major components:
#   engine/          C++ IDS engine        (CMake)
#   control-plane/   Python control plane  (FastAPI / pytest)
#   agents/          Python agent platform (pytest)
#   frontend/        React SOC dashboard   (Vite / npm)
#
# Usage:
#   make help            Show this help
#   make engine-build    Configure + compile the C++ engine
#   make engine-test     Run engine unit tests
#   make agents-test     Run agent platform tests
#   make control-test    Run control plane tests
#   make frontend-dev    Start the Vite dev server (runs in background)
#   make test-all        Run all test suites
#   make lint-all        Lint all components
#   make clean           Remove all build artefacts
# =============================================================================

.DEFAULT_GOAL := help
SHELL         := /bin/bash

# ── Directories ───────────────────────────────────────────────────────────────
ENGINE_DIR       := engine
CONTROL_DIR      := control-plane
AGENTS_DIR       := agents
FRONTEND_DIR     := frontend/dashboard
ENGINE_BUILD_DIR := $(ENGINE_DIR)/build

# ── Colours ───────────────────────────────────────────────────────────────────
BOLD  := \033[1m
RESET := \033[0m
GREEN := \033[32m
CYAN  := \033[36m

# =============================================================================
# HELP
# =============================================================================
.PHONY: help
help:
	@echo ""
	@echo "$(BOLD)Intriqo — Development Targets$(RESET)"
	@echo ""
	@echo "$(CYAN)Engine (C++ / CMake)$(RESET)"
	@echo "  make engine-configure    cmake configure (Release)"
	@echo "  make engine-build        cmake build"
	@echo "  make engine-test         ctest (unit + integration)"
	@echo "  make engine-bench        run engine benchmarks"
	@echo "  make engine-clean        remove engine build dir"
	@echo ""
	@echo "$(CYAN)Control Plane (Python / FastAPI)$(RESET)"
	@echo "  make control-install     pip install -e .[dev]"
	@echo "  make control-test        pytest control-plane/tests"
	@echo "  make control-lint        ruff + mypy"
	@echo ""
	@echo "$(CYAN)Agents (Python)$(RESET)"
	@echo "  make agents-install      pip install -e .[dev]"
	@echo "  make agents-test         pytest agents/tests"
	@echo "  make agents-lint         ruff + mypy"
	@echo ""
	@echo "$(CYAN)Frontend (React / Vite)$(RESET)"
	@echo "  make frontend-install    npm install"
	@echo "  make frontend-build      npm run build"
	@echo "  make frontend-test       npm run test"
	@echo "  make frontend-lint       npm run lint"
	@echo ""
	@echo "$(CYAN)Composite$(RESET)"
	@echo "  make test-all            run all test suites"
	@echo "  make lint-all            lint all components"
	@echo "  make clean               remove all build artefacts"
	@echo ""

# =============================================================================
# ENGINE (C++)
# =============================================================================
.PHONY: engine-configure engine-build engine-test engine-bench engine-clean

engine-configure:
	@echo "$(GREEN)→ Configuring engine (Release)$(RESET)"
	cmake -S $(ENGINE_DIR) -B $(ENGINE_BUILD_DIR) \
	      -DCMAKE_BUILD_TYPE=Release \
	      -DINTRIQO_BUILD_TESTS=ON \
	      -DINTRIQO_BUILD_BENCHMARKS=ON

engine-build: engine-configure
	@echo "$(GREEN)→ Building engine$(RESET)"
	cmake --build $(ENGINE_BUILD_DIR) --parallel $$(nproc)

engine-test: engine-build
	@echo "$(GREEN)→ Running engine tests$(RESET)"
	ctest --test-dir $(ENGINE_BUILD_DIR) --output-on-failure --parallel $$(nproc)

engine-bench: engine-build
	@echo "$(GREEN)→ Running engine benchmarks$(RESET)"
	$(ENGINE_BUILD_DIR)/benchmarks/intriqo_benchmarks

engine-clean:
	@echo "$(GREEN)→ Cleaning engine build$(RESET)"
	rm -rf $(ENGINE_BUILD_DIR)

# =============================================================================
# CONTROL PLANE (Python)
# =============================================================================
.PHONY: control-install control-test control-lint

control-install:
	@echo "$(GREEN)→ Installing control-plane$(RESET)"
	pip install -e "$(CONTROL_DIR)[dev]"

control-test:
	@echo "$(GREEN)→ Testing control-plane$(RESET)"
	cd $(CONTROL_DIR) && python -m pytest tests/ -v

control-lint:
	@echo "$(GREEN)→ Linting control-plane$(RESET)"
	cd $(CONTROL_DIR) && ruff check src/ tests/
	cd $(CONTROL_DIR) && mypy src/

# =============================================================================
# AGENTS (Python)
# =============================================================================
.PHONY: agents-install agents-test agents-lint agents-demo

agents-install:
	@echo "$(GREEN)→ Installing agents platform$(RESET)"
	pip install -e "$(AGENTS_DIR)[dev]"

agents-test:
	@echo "$(GREEN)→ Testing agents platform$(RESET)"
	cd $(AGENTS_DIR) && python -m pytest tests/ -v

agents-lint:
	@echo "$(GREEN)→ Linting agents$(RESET)"
	cd $(AGENTS_DIR) && ruff check src/ tests/
	cd $(AGENTS_DIR) && mypy src/

agents-demo:
	@echo "$(GREEN)→ Running agents demo$(RESET)"
	cd $(AGENTS_DIR) && python -m intriqo_agents.orchestrator.main

# =============================================================================
# FRONTEND (React / Vite)
# =============================================================================
.PHONY: frontend-install frontend-build frontend-test frontend-lint

frontend-install:
	@echo "$(GREEN)→ Installing frontend dependencies$(RESET)"
	cd $(FRONTEND_DIR) && npm install

frontend-build: frontend-install
	@echo "$(GREEN)→ Building frontend$(RESET)"
	cd $(FRONTEND_DIR) && npm run build

frontend-test: frontend-install
	@echo "$(GREEN)→ Testing frontend$(RESET)"
	cd $(FRONTEND_DIR) && npm run test -- --run

frontend-lint: frontend-install
	@echo "$(GREEN)→ Linting frontend$(RESET)"
	cd $(FRONTEND_DIR) && npm run lint

# =============================================================================
# COMPOSITE
# =============================================================================
.PHONY: test-all lint-all clean

test-all: engine-test agents-test control-test frontend-test
	@echo "$(GREEN)$(BOLD)All tests complete.$(RESET)"

lint-all: agents-lint control-lint frontend-lint
	@echo "$(GREEN)$(BOLD)All linting complete.$(RESET)"

clean: engine-clean
	@echo "$(GREEN)→ Cleaning Python caches$(RESET)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info"   -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache"  -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache"  -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)→ Cleaning frontend build$(RESET)"
	rm -rf $(FRONTEND_DIR)/dist $(FRONTEND_DIR)/.vite
	@echo "$(GREEN)$(BOLD)Clean complete.$(RESET)"
