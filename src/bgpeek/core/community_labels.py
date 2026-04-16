"""In-memory cache and lookup for community labels.

The community_labels table is small and read-heavy (hit on every
rendered BGP result), so keep a process-local snapshot and invalidate
it whenever the API mutates a row.
"""

from __future__ import annotations

import asyncio
from html import escape

import structlog
from markupsafe import Markup

from bgpeek.db import community_labels as crud
from bgpeek.db.pool import get_pool
from bgpeek.models.community_label import ALLOWED_COLORS, CommunityLabel, MatchType

log = structlog.get_logger(__name__)

_cache: list[CommunityLabel] = []
_lock = asyncio.Lock()
_loaded = False

# Color token → hex value for inline style.  No Tailwind classes needed,
# so adding a new color is just an API call + DB row — no CSS rebuild.
_COLORS: dict[str, str] = {
    "amber":   "#f59e0b",
    "emerald": "#34d399",
    "rose":    "#fb7185",
    "sky":     "#38bdf8",
    "violet":  "#a78bfa",
    "slate":   "#94a3b8",
    "red":     "#f87171",
    "orange":  "#fb923c",
    "cyan":    "#22d3ee",
    "pink":    "#f472b6",
    "yellow":  "#facc15",
    "lime":    "#a3e635",
    "teal":    "#2dd4bf",
    "indigo":  "#818cf8",
    "fuchsia": "#e879f9",
    "blue":    "#60a5fa",
    "green":   "#4ade80",
}
_DEFAULT_COLOR = "#94a3b8"  # slate-400


async def refresh_cache() -> None:
    """Reload the snapshot from PostgreSQL."""
    global _cache, _loaded
    async with _lock:
        try:
            _cache = await crud.list_labels(get_pool())
            _loaded = True
        except Exception:
            log.warning("community_labels_cache_refresh_failed", exc_info=True)


async def ensure_loaded() -> None:
    """Load the cache once per process if it hasn't been yet."""
    if not _loaded:
        await refresh_cache()


def get_labels() -> list[CommunityLabel]:
    """Return the current cached snapshot (may be empty before first load)."""
    return list(_cache)


def _match(community: str, entry: CommunityLabel) -> bool:
    if entry.match_type is MatchType.EXACT:
        return community == entry.pattern
    return community.startswith(entry.pattern)


def _find_match(community: str) -> CommunityLabel | None:
    """Find the best matching label entry for a community string."""
    exact: CommunityLabel | None = None
    best_prefix: CommunityLabel | None = None
    best_prefix_len = -1
    for entry in _cache:
        if not _match(community, entry):
            continue
        if entry.match_type is MatchType.EXACT:
            exact = entry
            break
        if len(entry.pattern) > best_prefix_len:
            best_prefix = entry
            best_prefix_len = len(entry.pattern)
    return exact or best_prefix


def annotate(community: str) -> Markup:
    """Return the community as HTML — colored label text if matched, plain text otherwise."""
    entry = _find_match(community)
    esc_comm = escape(community)
    if entry is None:
        return Markup(esc_comm)  # noqa: S704 — value is html.escape()'d

    esc_label = escape(entry.label)
    color = entry.color if entry.color and entry.color in ALLOWED_COLORS else None
    hex_color = _COLORS.get(color, _DEFAULT_COLOR) if color else _DEFAULT_COLOR

    return Markup(  # noqa: S704 — all interpolated values are html.escape()'d
        f'{esc_comm} <span style="color:{hex_color}">({esc_label})</span>'
    )
