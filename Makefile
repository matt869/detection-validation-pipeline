# Detection validation pipeline
#
# `make ci` runs exactly what the pipeline in scheduler/jobs.yml runs on a pull
# request. If it passes here it passes there.
#
# On Windows without make, every target maps to a one-line command - see the
# recipe bodies, or use `python -m harness <command>` directly.

.DEFAULT_GOAL := help
.PHONY: help install dev lint typecheck test test-cov rules score schedule \
        schedule-check smoke run coverage report dashboard doctor db-migrate \
        db-status clean ci

PY      ?= python
PIP     ?= $(PY) -m pip
DVP     ?= $(PY) -m harness
PROFILE ?= quick-smoke

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# -- setup -------------------------------------------------------------------

install: ## Install the package
	$(PIP) install -e .

dev: ## Install with dev and live-backend extras
	$(PIP) install -e '.[dev,live]'

# -- checks ------------------------------------------------------------------

lint: ## Lint Python (ruff)
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

typecheck: ## Type-check (mypy)
	$(PY) -m mypy harness rulekit

test: ## Run the test suite
	$(PY) -m pytest -q

test-cov: ## Run tests with coverage
	$(PY) -m pytest --cov --cov-report=term-missing --cov-report=html

rules: ## Lint detection content against every shipped dialect
	$(DVP) rules lint --dialect fixture --dialect splunk --dialect elastic

score: ## Score detection content quality
	$(DVP) rules score --explain

schedule: ## Re-render the systemd drop-ins from scheduler/jobs.yml
	$(PY) scripts/render_systemd.py

schedule-check: ## Fail if the committed drop-ins no longer match the manifest
	$(PY) scripts/render_systemd.py --check

# -- running -----------------------------------------------------------------

doctor: ## Check configuration, content and backends
	$(DVP) doctor --backends

smoke: ## Offline validation run (no infrastructure needed)
	$(DVP) run --profile quick-smoke

run: ## Run a profile: make run PROFILE=credential-theft
	$(DVP) run --profile $(PROFILE)

coverage: ## Show measured ATT&CK coverage
	$(DVP) coverage

report: ## Re-render the latest run as HTML
	$(DVP) report --latest --format html

dashboard: ## Serve the local review dashboard
	$(DVP) dashboard --open

# -- database ----------------------------------------------------------------

db-migrate: ## Apply pending migrations
	$(DVP) db migrate

db-status: ## Show database status
	$(DVP) db status

# -- housekeeping ------------------------------------------------------------

clean: ## Remove build artefacts, caches and the local database
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

# -- CI ----------------------------------------------------------------------

## Content checks run before the code checks on purpose: a broken rule is the
## more common failure and the faster signal.
ci: rules test lint ## Everything a pull request must pass
	$(DVP) run --profile quick-smoke --format json --format junit
