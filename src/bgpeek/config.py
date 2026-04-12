"""Application settings, loaded from environment variables."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for bgpeek."""

    model_config = SettingsConfigDict(
        env_prefix="BGPEEK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Server ---
    host: str = "0.0.0.0"  # noqa: S104  # bind all interfaces in container
    port: int = 8000
    workers: int = 1
    debug: bool = False

    # --- Database ---
    database_url: str = Field(
        default="postgresql://bgpeek:bgpeek@localhost:5432/bgpeek",
        description="PostgreSQL connection string",
    )

    # --- Cache ---
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection string",
    )
    cache_ttl: int = Field(
        default=60,
        description="Query cache TTL in seconds",
    )

    # --- Paths ---
    config_dir: Path = Path("/etc/bgpeek")
    static_dir: Path = Path(__file__).parent / "static"
    templates_dir: Path = Path(__file__).parent / "templates"


settings = Settings()
