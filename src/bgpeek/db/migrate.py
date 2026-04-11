"""Apply SQL migrations from the `migrations/` directory using yoyo-migrations."""

from __future__ import annotations

import sys
from pathlib import Path

import structlog
from yoyo import get_backend, read_migrations  # type: ignore[import-untyped]

from bgpeek.config import settings

log = structlog.get_logger(__name__)


def _migrations_dir() -> Path:
    """Locate the migrations directory.

    yoyo expects an OS path; we ship migrations alongside the source repo.
    """
    candidates = [
        Path.cwd() / "migrations",
        Path(__file__).resolve().parents[3] / "migrations",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError(
        "could not find migrations/ directory; looked at: " + ", ".join(map(str, candidates))
    )


def _to_yoyo_dsn(dsn: str) -> str:
    """yoyo uses ``postgresql+psycopg`` style; we always use plain ``postgresql://``."""
    if dsn.startswith("postgresql://"):
        return "postgresql+psycopg://" + dsn.removeprefix("postgresql://")
    return dsn


def apply_migrations(dsn: str | None = None) -> int:
    """Apply all unapplied migrations. Returns the number of migrations applied."""
    target_dsn = dsn or settings.database_url
    migrations_dir = _migrations_dir()
    log.info("applying migrations", dir=str(migrations_dir))

    backend = get_backend(_to_yoyo_dsn(target_dsn))
    migrations = read_migrations(str(migrations_dir))

    with backend.lock():
        to_apply = backend.to_apply(migrations)
        count = len(to_apply)
        if count == 0:
            log.info("database already up to date")
            return 0
        backend.apply_migrations(to_apply)
        log.info("applied migrations", count=count)
        return count


def main() -> None:
    """CLI entry point: ``bgpeek-migrate``."""
    try:
        applied = apply_migrations()
    except Exception as exc:
        log.error("migration failed", error=str(exc))
        sys.exit(1)
    sys.exit(0 if applied >= 0 else 1)


if __name__ == "__main__":
    main()
