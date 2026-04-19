"""Shared Jinja2Templates instance.

Centralising this avoids the trap of registering filters on one
Jinja2Templates() and rendering through another — each instance owns
its own ``Environment``, so filters/globals don't propagate.
"""

from __future__ import annotations

from fastapi.templating import Jinja2Templates

from bgpeek.config import settings
from bgpeek.core.community_labels import annotate as annotate_community
from bgpeek.core.community_labels import row_color as community_row_color
from bgpeek.core.time_utils import timeago

templates = Jinja2Templates(directory=str(settings.templates_dir))
_brand_footer = settings.brand_footer.strip()
_brand_site_name = settings.brand_site_name.strip() or f"AS{settings.primary_asn} bgpeek"
_peeringdb_url = f"https://www.peeringdb.com/asn/{settings.primary_asn}"

templates.env.filters["timeago"] = timeago
templates.env.filters["annotate_community"] = annotate_community
templates.env.globals["community_row_color"] = community_row_color
templates.env.globals["brand"] = {
    "site_name": _brand_site_name,
    "page_titles": settings.brand_page_titles,
    "logo_path": settings.brand_logo_path,
    "favicon_path": settings.brand_favicon_path,
    "theme_storage_key": settings.brand_theme_storage_key,
    "footer": _brand_footer,
    "primary_asn": settings.primary_asn,
    "peeringdb_link_enabled": settings.peeringdb_link_enabled,
    "peeringdb_url": _peeringdb_url,
    "custom_css": settings.brand_custom_css.strip(),
}
