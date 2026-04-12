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

    # --- JWT ---
    jwt_secret: str = "change-me-in-production"  # noqa: S105
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # --- LDAP ---
    ldap_enabled: bool = False
    ldap_server: str = ""  # e.g. "ldap://ldap.example.com:389" or "ldaps://..."
    ldap_bind_dn: str = ""  # service account DN for search
    ldap_bind_password: str = ""
    ldap_base_dn: str = ""  # e.g. "ou=people,dc=example,dc=com"
    ldap_user_filter: str = "(uid={username})"  # {username} is replaced
    ldap_use_tls: bool = False  # STARTTLS on non-SSL connection
    ldap_role_mapping: str = ""  # JSON: {"cn=noc,ou=groups,dc=ex": "noc"}
    ldap_default_role: str = "public"
    ldap_email_attr: str = "mail"
    ldap_group_attr: str = "memberOf"  # attribute on user entry listing group DNs

    # --- i18n ---
    default_lang: str = "en"

    # --- Rate limiting ---
    rate_limit_enabled: bool = True
    rate_limit_query: int = 30  # queries per minute per IP
    rate_limit_login: int = 5  # login attempts per minute per IP
    rate_limit_api: int = 60  # API calls per minute per API key

    # --- Parallel queries ---
    max_parallel_queries: int = Field(
        default=5,
        description="Maximum concurrent SSH queries for multi-device requests",
    )

    # --- Results ---
    result_ttl_days: int = Field(
        default=7,
        description="How long shared query results are kept (days)",
    )

    # --- RPKI ---
    rpki_enabled: bool = True
    rpki_api_url: str = "https://rpki.cloudflare.com/api/v1/validity"
    rpki_timeout: int = 5  # seconds
    rpki_cache_ttl: int = 3600  # 1 hour

    # --- LG links ---
    lg_links: str = ""  # JSON: [{"name": "RETN", "url": "https://lg.retn.net"}, ...]

    # --- Paths ---
    config_dir: Path = Path("/etc/bgpeek")
    static_dir: Path = Path(__file__).parent / "static"
    templates_dir: Path = Path(__file__).parent / "templates"


settings = Settings()
