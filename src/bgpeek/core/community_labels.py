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

# Color token → (light hex, dark hex).  Light values target WCAG AA (≥4.5:1)
# on slate-50 (#f8fafc); dark values target the same on slate-950 (#020617).
# Tailwind shade mapping: light ≈ -700/-800, dark ≈ -300/-400.
_COLORS: dict[str, tuple[str, str]] = {
    "amber": ("#b45309", "#fbbf24"),  # amber-700 / amber-400
    "emerald": ("#047857", "#34d399"),  # emerald-700 / emerald-300
    "rose": ("#be123c", "#fb7185"),  # rose-700 / rose-400
    "sky": ("#0369a1", "#38bdf8"),  # sky-700 / sky-400
    "violet": ("#6d28d9", "#a78bfa"),  # violet-700 / violet-400
    "slate": ("#475569", "#94a3b8"),  # slate-600 / slate-400
    "red": ("#b91c1c", "#f87171"),  # red-700 / red-400
    "orange": ("#c2410c", "#fb923c"),  # orange-700 / orange-400
    "cyan": ("#0e7490", "#22d3ee"),  # cyan-700 / cyan-400
    "pink": ("#be185d", "#f472b6"),  # pink-700 / pink-400
    "yellow": ("#a16207", "#facc15"),  # yellow-700 / yellow-400
    "lime": ("#4d7c0f", "#a3e635"),  # lime-700 / lime-400
    "teal": ("#0f766e", "#2dd4bf"),  # teal-700 / teal-400
    "indigo": ("#4338ca", "#818cf8"),  # indigo-700 / indigo-400
    "fuchsia": ("#a21caf", "#e879f9"),  # fuchsia-700 / fuchsia-400
    "blue": ("#1d4ed8", "#60a5fa"),  # blue-700 / blue-400
    "green": ("#15803d", "#4ade80"),  # green-700 / green-400
}
_DEFAULT_LIGHT = "#475569"  # slate-600
_DEFAULT_DARK = "#94a3b8"  # slate-400


def color_pairs() -> dict[str, tuple[str, str]]:
    """Return the mapping of color token → (light hex, dark hex)."""
    return dict(_COLORS)


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


def _resolve_pair(color: str | None) -> tuple[str, str]:
    """Return (light_hex, dark_hex) for a validated color token."""
    if color and color in ALLOWED_COLORS:
        return _COLORS.get(color, (_DEFAULT_LIGHT, _DEFAULT_DARK))
    return (_DEFAULT_LIGHT, _DEFAULT_DARK)


def annotate(community: str) -> Markup:
    """Return the community as HTML with theme-adaptive coloring via CSS variables."""
    entry = _find_match(community)
    esc_comm = escape(community)
    if entry is None:
        return Markup(esc_comm)  # noqa: S704  # nosec B704 — value is html.escape()'d

    esc_label = escape(entry.label)
    light, dark = _resolve_pair(entry.color)

    # CSS variable --c is set to the light value, overridden under .dark
    # by a rule in the page <style> block. The span uses var(--c).
    return Markup(  # noqa: S704  # nosec B704 — all interpolated values are html.escape()'d
        f'<span class="cl" style="--cl:{light};--cd:{dark}">{esc_comm} ({esc_label})</span>'
    )


def row_color(communities: list[str]) -> str | None:
    """Return the dark-theme hex color for row highlight.

    Row tinting is dark-mode only (light mode has no tint), so we
    return only the dark hex value.
    """
    best_entry: CommunityLabel | None = None
    best_specificity = -1  # exact=1000+len, prefix=len

    for comm in communities:
        entry = _find_match(comm)
        if entry is None or not entry.color or entry.color not in ALLOWED_COLORS:
            continue
        if entry.match_type is MatchType.EXACT:
            specificity = 1000 + len(entry.pattern)
        else:
            specificity = len(entry.pattern)
        if specificity > best_specificity:
            best_entry = entry
            best_specificity = specificity

    if best_entry is None:
        return None
    _, dark = _resolve_pair(best_entry.color)
    return dark
