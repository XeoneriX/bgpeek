"""Application settings, loaded from environment variables."""

from pathlib import Path

from pydantic import Field, field_validator, model_validator
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

    # --- API docs ---
    docs_enabled: bool = Field(
        default=True,
        description=(
            "Serve the Swagger UI at /api/docs and the OpenAPI schema at "
            "/api/openapi.json, and render the 'API' link in the main-site header. "
            "Set to false to return 404 for the docs endpoints AND hide the "
            "header link — the two must toggle together or prod users hit a "
            "dead link, and a visible endpoint stays findable for scanners."
        ),
    )

    # --- Target types ---
    allowed_target_types: str = Field(
        default="ip,cidr,hostname",
        description=(
            "Comma-separated allow-list of query-target types. "
            "`ip` = bare IPv4/IPv6 address, `cidr` = prefix notation (e.g. 192.0.2.0/24), "
            "`hostname` = DNS name (still subject to BGPEEK_DNS_RESOLVE_ENABLED). "
            "Targets classified outside this list are rejected with 400 before any SSH "
            "or DNS work. Use a narrower list in prod to reduce attack surface."
        ),
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
    enabled_languages: str = Field(
        default="en,ru",
        description=(
            "Comma-separated allow-list of language codes to expose. "
            "Languages outside the list are ignored even if requested via ?lang=, cookie, "
            "or Accept-Language. Must include `default_lang`. Set to a single code "
            "(for example `en`) in deployments that want to force one language."
        ),
    )

    # --- ASN ---
    primary_asn: int | str = Field(
        default="",
        description="Primary ASN (digits only) used for default branding and PeeringDB link generation. If unset, site_name falls back to 'bgpeek' and the PeeringDB link is hidden.",
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
    max_prefix_v4: int = Field(
        default=24,
        ge=8,
        le=32,
        description="Longest IPv4 prefix length accepted at validation and kept in filtered output. Privileged roles (admin/NOC) bypass the output filter but input validation still applies. Operators who want to expose more-specifics (e.g. /27) can raise this.",
    )
    max_prefix_v6: int = Field(
        default=48,
        ge=16,
        le=128,
        description="Longest IPv6 prefix length accepted at validation and kept in filtered output.",
    )
    accept_bare_ip_lookup: bool = Field(
        default=True,
        description="Accept bare host addresses (e.g. 8.8.8.8) as BGP query targets. The router performs longest-prefix-match and returns whichever covering prefix exists; the output filter still enforces BGPEEK_MAX_PREFIX_V4/V6 on the response, so the prefix-length invariant holds. Set to false to restore pre-v1.3.2 behavior (bare IPs rejected as 'too specific').",
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

    # --- Links ---
    lg_links: str = ""  # JSON: [{"name": "Example LG", "url": "https://lg.example.com"}, ...]
    peeringdb_link_enabled: bool = Field(
        default=True,
        description="Show a PeeringDB link in the top-right header using primary_asn.",
    )

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
    brand_custom_css: str = Field(
        default="",
        description="Optional CSS string appended to base template style block.",
    )

    # --- Logging ---
    service_name: str = Field(
        default="bgpeek",
        description="Service label attached to every structlog event as `service=<name>`. Useful when multiple bgpeek instances (or other services) ship into the same log backend — set a distinct value per deployment to partition VictoriaLogs / Loki streams.",
    )
    log_level: str = Field(
        default="info",
        description="Minimum log level for structlog output: debug, info, warning, error, critical.",
    )
    log_format: str = Field(
        default="console",
        description="Log renderer: 'console' (human, default), 'json' (machine-parseable NDJSON), 'logfmt'.",
    )
    audit_stdout: bool = Field(
        default=True,
        description="Emit audit_log entries to stdout (via structlog) in addition to the PostgreSQL row. Disable if audit noise on stdout is a problem; the DB row is unaffected.",
    )
    log_ship_url: str = Field(
        default="",
        description="Optional HTTP endpoint that receives a batched copy of every log event. Empty (default) disables shipping; stdout remains the only sink.",
    )
    log_ship_format: str = Field(
        default="ndjson",
        description="Wire format for log shipping: 'ndjson' (one JSON per line), 'loki' (Loki push API schema), 'elasticsearch' (bulk NDJSON with action lines).",
    )
    log_ship_headers: str = Field(
        default="",
        description='Optional JSON object of extra HTTP headers to attach to shipping requests, e.g. {"Authorization":"Bearer …"}.',
    )
    log_ship_batch_size: int = Field(
        default=100,
        description="Maximum number of events flushed in a single HTTP POST.",
    )
    log_ship_batch_timeout_sec: float = Field(
        default=2.0,
        description="Maximum number of seconds an event waits in the queue before being flushed.",
    )
    log_ship_queue_max: int = Field(
        default=10000,
        description="Upper bound on in-memory queue size. When full, oldest events are dropped first (never blocks log calls).",
    )
    log_ship_timeout_sec: float = Field(
        default=5.0,
        description="HTTP timeout for a single shipping request (seconds).",
    )

    # --- Paths ---
    config_dir: Path = Path("/etc/bgpeek")
    static_dir: Path = Path(__file__).parent / "static"
    templates_dir: Path = Path(__file__).parent / "templates"

    @field_validator("primary_asn")
    @classmethod
    def validate_primary_asn(cls: type["Settings"], value: int | str) -> str:
        """Validate primary_asn as digits-only string. Empty string is allowed and disables ASN-based branding."""
        normalized = str(value).strip()
        if not normalized:
            return ""
        if not normalized.isdigit():
            raise ValueError("primary_asn must contain digits only (for example: 152183)")
        return normalized

    @field_validator("enabled_languages")
    @classmethod
    def validate_enabled_languages(cls: type["Settings"], value: str) -> str:
        """Validate, lowercase-normalise, and dedupe the allow-list. Each token must
        be a known translation key; we reject unknown codes at startup rather than
        silently ignoring them, because a typo would otherwise reduce the allow-list
        to the default_lang fallback without a clear signal.
        """
        from bgpeek.core.i18n import TRANSLATIONS

        tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
        if not tokens:
            raise ValueError("enabled_languages must contain at least one language code")
        unknown = [t for t in tokens if t not in TRANSLATIONS]
        if unknown:
            known = sorted(TRANSLATIONS)
            raise ValueError(
                f"enabled_languages contains unknown code(s) {unknown}; known codes: {known}"
            )
        seen: set[str] = set()
        unique: list[str] = []
        for tok in tokens:
            if tok not in seen:
                seen.add(tok)
                unique.append(tok)
        return ",".join(unique)

    @field_validator("allowed_target_types")
    @classmethod
    def validate_allowed_target_types(cls: type["Settings"], value: str) -> str:
        """Normalise and validate the target-type allow-list. Known kinds are hard-coded
        (there are only three) — an unknown token is almost always a typo that would
        silently shrink the allow-list, so we fail at startup instead.
        """
        known = {"ip", "cidr", "hostname"}
        tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
        if not tokens:
            raise ValueError("allowed_target_types must contain at least one kind")
        unknown = [t for t in tokens if t not in known]
        if unknown:
            raise ValueError(
                f"allowed_target_types contains unknown kind(s) {unknown}; "
                f"known kinds: {sorted(known)}"
            )
        seen: set[str] = set()
        unique: list[str] = []
        for tok in tokens:
            if tok not in seen:
                seen.add(tok)
                unique.append(tok)
        return ",".join(unique)

    @model_validator(mode="after")
    def validate_default_lang_in_enabled(self) -> "Settings":
        """`default_lang` must be one of `enabled_languages` or the middleware has
        no safe fallback when the request can't be mapped to an allow-listed code.
        """
        enabled = self.enabled_languages_list
        if self.default_lang not in enabled:
            raise ValueError(
                f"default_lang={self.default_lang!r} is not in enabled_languages="
                f"{list(enabled)}; add it or change default_lang"
            )
        return self

    @property
    def enabled_languages_list(self) -> tuple[str, ...]:
        """Parsed ``enabled_languages`` as an ordered tuple (validator has already
        normalised casing and deduped, so a plain split suffices)."""
        return tuple(t for t in self.enabled_languages.split(",") if t)

    @property
    def allowed_target_types_set(self) -> frozenset[str]:
        """Parsed ``allowed_target_types`` as a frozenset for membership tests."""
        return frozenset(t for t in self.allowed_target_types.split(",") if t)


settings = Settings()
