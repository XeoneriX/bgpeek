UV ?= uv
DOCKER_COMPOSE ?= docker compose

.DEFAULT_GOAL := help

TAILWINDCSS ?= tailwindcss
TAILWIND_INPUT := src/bgpeek/static/css/input.css
TAILWIND_OUTPUT := src/bgpeek/static/css/tailwind.css

.PHONY: help install lint format format-check mypy test test-cov audit bandit check secure dev dev-down dev-logs dev-rebuild migrate css css-watch clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install dev dependencies via uv
	$(UV) sync --extra dev

lint: ## Run ruff lint on src and tests
	$(UV) run ruff check src tests

format: ## Format src and tests with ruff
	$(UV) run ruff format src tests

format-check: ## Check formatting without writing changes
	$(UV) run ruff format --check src tests

mypy: ## Run mypy type checks on src
	$(UV) run mypy src

test: ## Run pytest
	$(UV) run pytest -v

test-cov: ## Run pytest with coverage report
	$(UV) run pytest --cov=bgpeek --cov-report=term-missing --cov-report=html

audit: ## Audit dependencies with pip-audit
	$(UV) run pip-audit

bandit: ## Run bandit security scan on src
	$(UV) run bandit -r src

check: lint format-check mypy test ## Run lint, format-check, mypy and tests

secure: audit bandit ## Run dependency audit and bandit scan

dev: ## Start local dev stack via docker compose
	$(DOCKER_COMPOSE) up -d

dev-down: ## Stop local dev stack
	$(DOCKER_COMPOSE) down

dev-logs: ## Tail bgpeek logs
	$(DOCKER_COMPOSE) logs -f bgpeek

dev-rebuild: ## Rebuild images from scratch and restart stack
	$(DOCKER_COMPOSE) build --no-cache && $(DOCKER_COMPOSE) up -d

migrate: ## Apply database migrations against $BGPEEK_DATABASE_URL (or default)
	$(UV) run bgpeek-migrate

css: ## Build Tailwind CSS one-shot (via Docker, no host binary required)
	$(DOCKER_COMPOSE) run --rm --no-deps tailwind \
	  /usr/local/bin/tailwindcss -i $(TAILWIND_INPUT) -o $(TAILWIND_OUTPUT) --minify

css-watch: ## Build Tailwind CSS in watch mode (starts the tailwind service)
	$(DOCKER_COMPOSE) up -d tailwind
	$(DOCKER_COMPOSE) logs -f tailwind

clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov dist
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type d -name '*.egg-info' -prune -exec rm -rf {} +
	rm -f $(TAILWIND_OUTPUT)
