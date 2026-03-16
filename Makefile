.PHONY: help install install-dev test test-cov lint format check generate

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ─── Setup ──────────────────────────────────────────────
install: ## Install OEBC
	python3 -m pip install .

install-dev: ## Install with dev dependencies
	python3 -m pip install -e ".[dev]"
	pre-commit install

# ─── Testing ────────────────────────────────────────────
test: ## Run tests
	python3 -m pytest tests/ -v

test-cov: ## Run tests with 100% coverage requirement
	python3 -m pytest tests/ -v --cov=oebc --cov-report=term-missing --cov-report=html --cov-fail-under=100

# ─── Code Quality ──────────────────────────────────────
lint: ## Run linter (ruff)
	python3 -m ruff check src/ tests/

format: ## Auto-format code (ruff)
	python3 -m ruff format src/ tests/
	python3 -m ruff check --fix src/ tests/

check: lint test-cov ## Run all checks (lint + test with 100% coverage)

# ─── Application Usage ─────────────────────────────────
generate: ## Run oebc generate locally
	python3 -m oebc generate --out oebc_full_catalog_enriched.json
