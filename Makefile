# ARGOS developer targets.
#
# Use `make help` to list available targets. Every command is safe to run from
# a clean checkout; `make bootstrap` is the only one that mutates your
# environment.

.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash

UV      ?= uv
PY      ?= $(UV) run python
PYTEST  ?= $(UV) run pytest
RUFF    ?= $(UV) run ruff
MYPY    ?= $(UV) run mypy

PACKAGES := packages

.PHONY: help
help: ## List available targets.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: bootstrap
bootstrap: ## Install runtime + dev dependencies using uv.
	$(UV) sync --all-extras
	$(UV) run pre-commit install --install-hooks

.PHONY: tokens
tokens: ## Regenerate design-system/tokens.{css,py,ts} from tokens.json.
	$(PY) scripts/build_tokens.py

.PHONY: lint
lint: ## Run ruff (lint + format --check).
	$(RUFF) check $(PACKAGES) scripts
	$(RUFF) format --check $(PACKAGES) scripts

.PHONY: fmt
fmt: ## Auto-format with ruff.
	$(RUFF) format $(PACKAGES) scripts
	$(RUFF) check --fix $(PACKAGES) scripts

.PHONY: typecheck
typecheck: ## Run mypy --strict across packages.
	$(MYPY) $(PACKAGES)

.PHONY: test
test: ## Run the full pytest suite with coverage.
	$(PYTEST) --cov --cov-report=term-missing

.PHONY: test-fast
test-fast: ## Run tests without coverage for quick feedback.
	$(PYTEST) -x -q

.PHONY: ci
ci: lint typecheck test ## Run everything CI runs.

.PHONY: clean
clean: ## Remove caches and generated artefacts.
	rm -rf .mypy_cache .ruff_cache .pytest_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name "*.egg-info" -prune -exec rm -rf {} +
