"""Application settings, loaded from environment variables."""

from pathlib import Path

from pydantic import Field, field_validator
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

    # --- Access mode ---
    access_mode: str = Field(
        default="guest",
        description="Access mode: 'closed' (login required), 'guest' (anonymous with restrictions), 'open' (anonymous full access)",
    )

    # --- DNS ---
    dns_resolve_enabled: bool = Field(
        default=True,
        description="Resolve hostnames to IPs before querying. When false, only IP addresses accepted.",
    )

    # --- Database ---
    database_url: str = Field(
        default="postgresql://bgpeek:bgpeek@localhost:5432/bgpeek",
        description="PostgreSQL connection string",
    )
    db_pool_min: int = Field(default=2, description="Minimum DB pool connections")
    db_pool_max: int = Field(default=10, description="Maximum DB pool connections")
    db_command_timeout: int = Field(default=30, description="DB command timeout in seconds")
    auto_migrate: bool = Field(default=True, description="Run migrations on startup")

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

    # --- OIDC ---
    oidc_enabled: bool = False
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_server_url: str = ""  # e.g. "https://keycloak.example.com/realms/bgpeek"
    oidc_discovery_url: str = (
        ""  # auto-derived if empty: {server_url}/.well-known/openid-configuration
    )
    oidc_scopes: str = "openid email profile"
    oidc_role_claim: str = "realm_access.roles"  # JWT claim path for roles
    oidc_role_mapping: str = ""  # JSON: {"bgpeek-admin": "admin", "bgpeek-noc": "noc"}
    oidc_default_role: str = "public"

    # --- Session ---
    session_secret: str = "change-me-session-secret"  # noqa: S105

    # --- Cookies ---
    cookie_secure: bool = Field(
        default=False,
        description="Set True when behind HTTPS proxy. Cookies will only be sent over HTTPS.",
    )

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

    # --- ASN ---
    primary_asn: int | str = Field(
        default="65000",
        description="Primary ASN (digits only) used for default branding and PeeringDB link generation.",
    )

    # --- Metrics ---
    metrics_enabled: bool = Field(default=True, description="Expose /metrics Prometheus endpoint")

    # --- Rate limiting ---
    rate_limit_enabled: bool = True
    rate_limit_query: int = 30  # queries per minute per IP
    rate_limit_login: int = 5  # login attempts per minute per IP
    rate_limit_api: int = 60  # API calls per minute per API key
    rate_limit_guest: int = 10  # queries per minute per IP for guest/anonymous
    trusted_proxies: str = Field(
        default="",
        description="Comma-separated trusted proxy IPs. When set, X-Forwarded-For is used for rate limiting.",
    )

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

    # --- Audit ---
    audit_ttl_days: int = Field(
        default=90,
        description="Audit log retention in days (0 = keep forever)",
    )

    # --- Circuit breaker ---
    circuit_breaker_enabled: bool = True
    circuit_breaker_threshold: int = Field(
        default=3,
        description="Consecutive failures before marking device as down",
    )
    circuit_breaker_cooldown: int = Field(
        default=300,
        description="Seconds to wait before retrying a tripped device",
    )

    # --- Device access control ---
    device_public_by_default: bool = Field(
        default=True,
        description="If True, all devices are visible to public users unless restricted",
    )

    # --- Output visibility ---
    public_output_level: str = Field(
        default="restricted",
        description="Output detail level for public/guest users: 'restricted' (hide communities/LP/MED, mask RFC1918), 'standard' (all parsed fields, no raw), 'full' (same as NOC)",
    )

    # --- SSH ---
    ssh_username: str = Field(
        default="looking-glass",
        description="Default SSH username for devices (fallback when no credential assigned)",
    )
    keys_dir: Path = Field(
        default=Path("/etc/bgpeek/keys"), description="Directory containing SSH private key files"
    )
    encryption_key: str = Field(
        default="",
        description="Fernet key for encrypting stored passwords (generate with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')",
    )
    ssh_timeout: int = Field(
        default=30, description="Default SSH connection/command timeout in seconds"
    )
    ssh_timeout_traceroute: int = Field(
        default=120, description="SSH timeout for traceroute commands"
    )
    ssh_known_hosts_policy: str = Field(
        default="auto-add",
        description="Host key policy: 'auto-add' (accept new keys) or 'strict' (reject unknown)",
    )

    # --- RPKI ---
    rpki_enabled: bool = False
    rpki_api_url: str = "http://routinator:8323/api/v1/validity"
    rpki_timeout: int = 5  # seconds
    rpki_cache_ttl: int = 3600  # 1 hour
    rpki_error_cache_ttl: int = Field(
        default=60, description="Cache TTL for RPKI API errors (seconds)"
    )

    # --- LG links ---
    lg_links: str = ""  # JSON: [{"name": "RETN", "url": "https://lg.retn.net"}, ...]

    # --- Branding ---
    brand_site_name: str = Field(
        default="",
        description="UI brand name shown in page titles and header. If empty, defaults to 'AS<primary_asn> bgpeek'.",
    )
    brand_page_titles: dict[str, str] = Field(
        default_factory=dict,
        description="Optional per-page title suffix overrides (text after '·') as JSON object. Supported keys: index, login, history, result_page.",
    )
    brand_site_description: str = Field(
        default="Open-source looking glass for ISPs and IX operators",
        description="Application description used in API metadata.",
    )
    brand_logo_path: str = Field(
        default="/static/favicon.svg",
        description="Path or URL to the brand logo used in headers/login screens.",
    )
    brand_favicon_path: str = Field(
        default="/static/favicon.svg",
        description="Path or URL to favicon file referenced by HTML pages.",
    )
    brand_theme_storage_key: str = Field(
        default="bgpeek-theme",
        description="localStorage key used to persist dark/light mode preference.",
    )
    brand_footer: str = Field(
        default="",
        description="Optional footer suffix rendered as HTML after the '·' separator. The 'bgpeek v<version>' prefix is always shown.",
    )
    brand_peeringdb_link_enabled: bool = Field(
        default=True,
        description="Show a PeeringDB link in the top-right header using primary_asn.",
    )
    brand_custom_css: str = Field(
        default="",
        description="Optional CSS string appended to base template style block.",
    )

    # --- Paths ---
    config_dir: Path = Path("/etc/bgpeek")
    static_dir: Path = Path(__file__).parent / "static"
    templates_dir: Path = Path(__file__).parent / "templates"

    @field_validator("primary_asn")
    @classmethod
    def validate_primary_asn(cls: "Settings", value: int | str) -> str:
        """Validate primary_asn as digits-only string."""
        normalized = str(value).strip()
        if not normalized.isdigit():
            raise ValueError("primary_asn must contain digits only (for example: 152183)")
        return normalized


settings = Settings()
