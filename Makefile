# jwt-toolkit dev commands. Run `make` or `make help` for the list.

.DEFAULT_GOAL := help
.PHONY: help install fmt lint typecheck test test-fast cov security audit actions smoke cliprobe check pre-commit clean

UV ?= uv

help:  ## Show this help.
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install:  ## Sync dev dependencies and install pre-commit hook.
	$(UV) sync --group dev
	$(UV) run pre-commit install

fmt:  ## Auto-format code with ruff.
	$(UV) run ruff format .
	$(UV) run ruff check . --fix

lint:  ## Lint without modifying files.
	$(UV) run ruff format --check .
	$(UV) run ruff check .

typecheck:  ## Run mypy.
	$(UV) run mypy

test:  ## Run the full test suite with coverage in parallel.
	$(UV) run pytest --cov -n auto

test-fast:  ## Run tests without coverage, parallel.
	$(UV) run pytest -n auto

cov:  ## Test suite with coverage report on stdout.
	$(UV) run pytest --cov --cov-report=term-missing

security:  ## Static security scan of the source.
	$(UV) run bandit -c pyproject.toml -r jwt_toolkit --severity-level medium

audit:  ## Check dependencies for known CVEs.
	$(UV) run pip-audit

actions:  ## Security-lint the GitHub Actions workflows (zizmor).
	$(UV) run zizmor --offline --persona=regular .github/workflows

smoke:  ## Build, check and smoke-test the installed wheel and sdist.
	$(UV) run python scripts/package_check.py

CLIPROBE_ENV ?= .smoke-env
cliprobe:  ## Run cliprobe (needs Node 22+) against the installed wheel.
	$(UV) run python scripts/package_check.py --keep-venv $(CLIPROBE_ENV)
	$(UV) run python scripts/run_cliprobe.py --strict $(CLIPROBE_ENV)

check: lint typecheck test security audit actions smoke  ## Full local CI gate.

pre-commit:  ## Run all pre-commit hooks on every file.
	$(UV) run pre-commit run --all-files

clean:  ## Remove caches and build artifacts.
	rm -rf .pytest_cache .ruff_cache .mypy_cache .coverage coverage.xml htmlcov dist build .smoke-env
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
