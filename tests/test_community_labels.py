"""Tests for community label lookup and annotation."""

from __future__ import annotations

from datetime import datetime

from markupsafe import Markup

from bgpeek.core import community_labels as cl
from bgpeek.models.community_label import CommunityLabel, MatchType


def _make(
    pattern: str,
    match_type: MatchType,
    label: str,
    label_id: int = 1,
    color: str | None = None,
) -> CommunityLabel:
    now = datetime.now()
    return CommunityLabel(
        id=label_id,
        pattern=pattern,
        match_type=match_type,
        label=label,
        color=color,
        created_at=now,
        updated_at=now,
    )


def _install(entries: list[CommunityLabel]) -> None:
    cl._cache = list(entries)


def test_annotate_no_labels_loaded() -> None:
    _install([])
    result = cl.annotate("64500:100")
    assert result == "64500:100"
    assert isinstance(result, Markup)


def test_annotate_exact_match() -> None:
    _install([_make("64500:100", MatchType.EXACT, "customer route")])
    result = cl.annotate("64500:100")
    assert "64500:100" in result
    assert "customer route" in result
    assert "<span" in result


def test_annotate_prefix_match() -> None:
    _install([_make("64500:1", MatchType.PREFIX, "from upstream")])
    result = cl.annotate("64500:1234")
    assert "64500:1234" in result
    assert "from upstream" in result
    assert "<span" in result


def test_annotate_no_match_when_pattern_not_prefix() -> None:
    _install([_make("64500:5", MatchType.PREFIX, "from peering")])
    result = cl.annotate("64500:100")
    assert result == "64500:100"
    assert "<span" not in result


def test_exact_match_beats_prefix() -> None:
    _install(
        [
            _make("64500:1", MatchType.PREFIX, "short prefix", 1),
            _make("64500:100", MatchType.EXACT, "exact tag", 2),
        ]
    )
    result = cl.annotate("64500:100")
    assert "exact tag" in result
    assert "short prefix" not in result


def test_longest_prefix_wins() -> None:
    _install(
        [
            _make("64500:1", MatchType.PREFIX, "short", 1),
            _make("64500:12", MatchType.PREFIX, "specific", 2),
        ]
    )
    result = cl.annotate("64500:123")
    assert "specific" in result
    assert ">short<" not in result


def test_large_community_annotated_by_exact_match() -> None:
    _install([_make("large:64500:1:2", MatchType.EXACT, "Custom tag")])
    result = cl.annotate("large:64500:1:2")
    assert "large:64500:1:2" in result
    assert "Custom tag" in result


def test_annotate_with_color_uses_css_vars() -> None:
    _install([_make("64500:100", MatchType.EXACT, "customer", color="rose")])
    result = cl.annotate("64500:100")
    assert "customer" in result
    # Light and dark hex values set as CSS variables
    assert "--cl:#be123c" in result  # rose-700 (light)
    assert "--cd:#fb7185" in result  # rose-400 (dark)
    assert 'class="cl"' in result


def test_annotate_without_color_gets_default() -> None:
    _install([_make("64500:100", MatchType.EXACT, "customer")])
    result = cl.annotate("64500:100")
    assert "--cl:#475569" in result  # slate-600 default light
    assert "--cd:#94a3b8" in result  # slate-400 default dark


def test_annotate_invalid_color_falls_back() -> None:
    _install([_make("64500:100", MatchType.EXACT, "customer", color="neon")])
    result = cl.annotate("64500:100")
    assert "--cl:#475569" in result
    assert "neon" not in result


def test_row_color_no_match() -> None:
    _install([])
    assert cl.row_color(["64500:100"]) is None


def test_row_color_no_communities() -> None:
    _install([_make("64500:100", MatchType.EXACT, "tag", color="rose")])
    assert cl.row_color([]) is None


def test_row_color_returns_dark_hex() -> None:
    _install([_make("64500:1", MatchType.PREFIX, "upstream", color="sky")])
    assert cl.row_color(["64500:1234"]) == "#38bdf8"  # dark value


def test_row_color_exact_beats_prefix() -> None:
    _install(
        [
            _make("64500:1", MatchType.PREFIX, "upstream", 1, color="sky"),
            _make("64500:100", MatchType.EXACT, "customer", 2, color="emerald"),
        ]
    )
    assert cl.row_color(["64500:100"]) == "#34d399"  # emerald dark value


def test_row_color_skips_entries_without_color() -> None:
    _install([_make("64500:100", MatchType.EXACT, "tag")])
    assert cl.row_color(["64500:100"]) is None


def _relative_luminance(hex_color: str) -> float:
    """WCAG 2.1 relative luminance from a #rrggbb hex string."""
    r, g, b = (int(hex_color[i : i + 2], 16) / 255.0 for i in (1, 3, 5))
    channels = []
    for c in (r, g, b):
        channels.append(c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4)
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def _contrast_ratio(fg: str, bg: str) -> float:
    """WCAG contrast ratio between two hex colors."""
    l1 = _relative_luminance(fg)
    l2 = _relative_luminance(bg)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


_BG_LIGHT = "#f8fafc"  # slate-50
_BG_DARK = "#020617"   # slate-950
_WCAG_AA_RATIO = 4.5   # normal text


def test_all_light_colors_pass_wcag_aa() -> None:
    """Every community label light color must be readable on slate-50."""
    for name, (light, _dark) in cl._COLORS.items():
        ratio = _contrast_ratio(light, _BG_LIGHT)
        assert ratio >= _WCAG_AA_RATIO, (
            f"{name} light ({light}) on {_BG_LIGHT}: contrast {ratio:.2f} < {_WCAG_AA_RATIO}"
        )


def test_all_dark_colors_pass_wcag_aa() -> None:
    """Every community label dark color must be readable on slate-950."""
    for name, (_light, dark) in cl._COLORS.items():
        ratio = _contrast_ratio(dark, _BG_DARK)
        assert ratio >= _WCAG_AA_RATIO, (
            f"{name} dark ({dark}) on {_BG_DARK}: contrast {ratio:.2f} < {_WCAG_AA_RATIO}"
        )


def test_annotate_escapes_html() -> None:
    _install([_make("64500:100", MatchType.EXACT, '<script>alert("xss")</script>')])
    result = cl.annotate("64500:100")
    assert "<script>" not in result
    assert "&lt;script&gt;" in result
