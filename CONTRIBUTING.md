# Contributing to bgpeek

Thank you for considering contributing to bgpeek! This guide will help you get started.

## Development setup

**Requirements:** Python 3.12+, PostgreSQL, Redis (optional).

```bash
# Clone and install in development mode
git clone https://github.com/XeoneriX/bgpeek.git
cd bgpeek
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest

# Run linter and formatter
ruff check src/ tests/
ruff format --check src/ tests/
```

## Running locally

```bash
# Start dependencies (PostgreSQL + Redis)
docker compose -f docker-compose.yml up -d db redis

# Run the app in debug mode
BGPEEK_DEBUG=true BGPEEK_DATABASE_URL=postgresql://bgpeek:bgpeek@localhost:5432/bgpeek bgpeek
```

The app will be available at `http://localhost:8080` with auto-reload enabled.

## Code style

- **Linter/formatter:** [ruff](https://docs.astral.sh/ruff/) — configuration is in `pyproject.toml`
- **Type hints:** required on all public functions (Pydantic v2 strict mode)
- **Language:** code, comments, and documentation in English
- **Tests:** pytest + pytest-asyncio — aim for coverage on new features

Run before committing:

```bash
ruff check src/ tests/ --fix
ruff format src/ tests/
pytest
```

## Making changes

1. Fork the repository and create a branch from `main`
2. Make your changes — keep commits focused and atomic
3. Add or update tests for your changes
4. Ensure all tests pass and linting is clean
5. Open a pull request against `main`

## Pull requests

- Keep PRs focused — one feature or fix per PR
- Write a clear description of what changed and why
- Link related issues (e.g., "Fixes #123")
- All CI checks must pass before merge

## Reporting bugs

Use the [bug report template](https://github.com/XeoneriX/bgpeek/issues/new?template=bug_report.md) to file issues. Include:

- bgpeek version (`bgpeek --version` or `/api/health`)
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs (sanitize any sensitive data)

## Feature requests

Use the [feature request template](https://github.com/XeoneriX/bgpeek/issues/new?template=feature_request.md). Describe:

- The problem you're solving
- Your proposed solution
- Any alternatives you've considered

## Security vulnerabilities

**Do not open a public issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
