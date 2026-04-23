"""Shared Jinja2Templates instance.

Centralising this avoids the trap of registering filters on one
Jinja2Templates() and rendering through another — each instance owns
its own ``Environment``, so filters/globals don't propagate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, TypedDict

from fastapi import Request
from fastapi.templating import Jinja2Templates
from jinja2 import pass_context

from bgpeek.config import settings
from bgpeek.core.community_labels import annotate as annotate_community
from bgpeek.core.community_labels import row_color as community_row_color
from bgpeek.core.time_utils import timeago


def _base_context(request: Request) -> dict[str, Any]:
    """Default context injected into every template render."""
    return {
        "user": getattr(request.state, "user", None),
        "current_path": request.url.path,
    }


def _role_value(user: Any) -> str | None:
    """Return normalized role string for template user objects."""
    if user is None:
        return None
    role = getattr(user, "role", None)
    if role is None:
        return None
    return str(getattr(role, "value", role))


LinkKey = Literal["looking_glass", "history", "api_docs", "admin"]


@dataclass(frozen=True)
class HeaderLinkConfig:
    """Static metadata for a header link entry."""

    href: str
    label_key: str
    requires_admin: bool = False


class HeaderLinkItem(TypedDict):
    """Resolved link item consumed by the header template."""

    href: str
    label: str
    active: bool


HEADER_LINK_REGISTRY: dict[LinkKey, HeaderLinkConfig] = {
    "looking_glass": HeaderLinkConfig(href="/", label_key="looking_glass"),
    "history": HeaderLinkConfig(href="/history", label_key="history"),
    "api_docs": HeaderLinkConfig(href="/api/docs", label_key="api_docs"),
    "admin": HeaderLinkConfig(href="/admin", label_key="admin", requires_admin=True),
}

HEADER_LINK_ORDER: tuple[LinkKey, ...] = ("history", "api_docs", "admin")


@pass_context
def header_links_for(
    context: Any,
    t: dict[str, str],
    user: Any,
    current_path: str | None = None,
) -> list[HeaderLinkItem]:
    """Build consistent header links for all SSR pages."""
    if current_path is None:
        current_path = context.get("current_path")
    if current_path is None:
        request = context.get("request")
        current_path = (
            getattr(getattr(request, "url", None), "path", "") if request is not None else ""
        )
    if not current_path:
        current_path = ""

    links: list[HeaderLinkItem] = []
    seen: set[str] = set()

    def is_active(href: str) -> bool:
        if href == "/":
            return not (
                current_path.startswith("/history")
                or current_path.startswith("/admin")
                or current_path.startswith("/api")
            )
        return current_path == href or current_path.startswith(f"{href}/")

    def add(href: str, label: str) -> None:
        if href in seen:
            return
        seen.add(href)
        links.append({"href": href, "label": label, "active": is_active(href)})

    home = HEADER_LINK_REGISTRY["looking_glass"]
    add(home.href, t[home.label_key])

    is_admin = _role_value(user) == "admin"
    for key in HEADER_LINK_ORDER:
        cfg = HEADER_LINK_REGISTRY[key]
        if cfg.requires_admin and not is_admin:
            continue
        # Hide API docs link when the endpoint itself is disabled (L18/A4).
        if key == "api_docs" and not settings.docs_enabled:
            continue
        add(cfg.href, t[cfg.label_key])

    return links


templates = Jinja2Templates(
    directory=str(settings.templates_dir),
    context_processors=[_base_context],
)
_brand_footer = settings.brand_footer.strip()
_primary_asn = str(settings.primary_asn).strip()
_has_asn = bool(_primary_asn)
_default_site_name = f"AS{_primary_asn} bgpeek" if _has_asn else "bgpeek"
_brand_site_name = settings.brand_site_name.strip() or _default_site_name
_peeringdb_url = f"https://www.peeringdb.com/asn/{_primary_asn}" if _has_asn else ""

templates.env.filters["timeago"] = timeago
templates.env.filters["annotate_community"] = annotate_community
templates.env.globals["community_row_color"] = community_row_color
templates.env.globals["enabled_languages"] = settings.enabled_languages_list
templates.env.globals["docs_enabled"] = settings.docs_enabled
templates.env.globals["header_links_for"] = header_links_for
templates.env.globals["brand"] = {
    "site_name": _brand_site_name,
    "page_titles": settings.brand_page_titles,
    "logo_path": settings.brand_logo_path,
    "favicon_path": settings.brand_favicon_path,
    "theme_storage_key": settings.brand_theme_storage_key,
    "footer": _brand_footer,
    "primary_asn": _primary_asn,
    "peeringdb_link_enabled": settings.peeringdb_link_enabled and _has_asn,
    "peeringdb_url": _peeringdb_url,
    "custom_css": settings.brand_custom_css.strip(),
}
