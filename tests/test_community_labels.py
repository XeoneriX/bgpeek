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


def test_annotate_with_color() -> None:
    _install([_make("64500:100", MatchType.EXACT, "customer", color="rose")])
    result = cl.annotate("64500:100")
    assert "#fb7185" in result
    assert "customer" in result


def test_annotate_without_color_gets_default() -> None:
    _install([_make("64500:100", MatchType.EXACT, "customer")])
    result = cl.annotate("64500:100")
    assert "#94a3b8" in result


def test_annotate_invalid_color_falls_back() -> None:
    _install([_make("64500:100", MatchType.EXACT, "customer", color="neon")])
    result = cl.annotate("64500:100")
    assert "#94a3b8" in result
    assert "neon" not in result


def test_annotate_escapes_html() -> None:
    _install([_make("64500:100", MatchType.EXACT, '<script>alert("xss")</script>')])
    result = cl.annotate("64500:100")
    assert "<script>" not in result
    assert "&lt;script&gt;" in result
