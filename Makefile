.PHONY: help test test-unit test-integration test-cov test-fast install-test clean

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install-test: ## Install test dependencies
	uv sync --extra test

test: ## Run all tests
	uv run pytest

test-unit: ## Run unit tests only
	uv run pytest tests/unit/

test-integration: ## Run integration tests only
	uv run pytest tests/integration/

test-cov: ## Run tests with coverage report
	uv run pytest --cov=google_auth_provider --cov-report=html --cov-report=term-missing

test-fast: ## Run fast tests (exclude slow tests)
	uv run pytest -m "not slow"

clean: ## Clean up test artifacts
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -f coverage.xml
	rm -rf .coverage
