"""Tests for the configurable prefix-length cutoff (max_prefix_v4/v6)."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from bgpeek.api.query import _friendly_error
from bgpeek.config import Settings


def test_max_prefix_defaults_match_historical_behavior() -> None:
    s = Settings()
    assert s.max_prefix_v4 == 24
    assert s.max_prefix_v6 == 48


@pytest.mark.parametrize("v4", [8, 16, 24, 27, 31, 32])
def test_max_prefix_v4_accepts_valid_range(v4: int) -> None:
    s = Settings(max_prefix_v4=v4)
    assert s.max_prefix_v4 == v4


@pytest.mark.parametrize("v4", [0, 7, 33, 64])
def test_max_prefix_v4_rejects_out_of_range(v4: int) -> None:
    with pytest.raises(ValidationError):
        Settings(max_prefix_v4=v4)


@pytest.mark.parametrize("v6", [16, 48, 64, 127, 128])
def test_max_prefix_v6_accepts_valid_range(v6: int) -> None:
    s = Settings(max_prefix_v6=v6)
    assert s.max_prefix_v6 == v6


@pytest.mark.parametrize("v6", [0, 15, 129, 256])
def test_max_prefix_v6_rejects_out_of_range(v6: int) -> None:
    with pytest.raises(ValidationError):
        Settings(max_prefix_v6=v6)


def test_friendly_error_formats_cutoff_values() -> None:
    t = {"error_prefix_too_specific": "Prefix too specific (max /{v4} for IPv4, /{v6} for IPv6)"}
    with patch("bgpeek.api.query.settings") as mock_settings:
        mock_settings.max_prefix_v4 = 27
        mock_settings.max_prefix_v6 = 56
        msg = _friendly_error("prefix too specific", t)
    assert "/27" in msg
    assert "/56" in msg


def test_friendly_error_survives_missing_placeholders() -> None:
    """Older translations without {v4}/{v6} placeholders should still render."""
    t = {"error_prefix_too_specific": "Prefix too specific"}
    with patch("bgpeek.api.query.settings") as mock_settings:
        mock_settings.max_prefix_v4 = 24
        mock_settings.max_prefix_v6 = 48
        msg = _friendly_error("prefix too specific", t)
    assert msg == "Prefix too specific"


def test_min_prefix_defaults() -> None:
    s = Settings()
    assert s.min_prefix_v4 == 8
    assert s.min_prefix_v6 == 16


@pytest.mark.parametrize("v4", [0, 1, 8, 24])
def test_min_prefix_v4_accepts_valid_range(v4: int) -> None:
    # Stay <= default max (24); cross-field check is exercised separately.
    s = Settings(min_prefix_v4=v4)
    assert s.min_prefix_v4 == v4


def test_min_prefix_v4_at_field_upper_bound() -> None:
    # Field bound is /32; needs a matching max to avoid the cross-field check.
    s = Settings(min_prefix_v4=32, max_prefix_v4=32)
    assert s.min_prefix_v4 == 32


@pytest.mark.parametrize("v4", [-1, 33, 64])
def test_min_prefix_v4_rejects_out_of_range(v4: int) -> None:
    with pytest.raises(ValidationError):
        Settings(min_prefix_v4=v4)


@pytest.mark.parametrize("v6", [0, 16, 32, 48])
def test_min_prefix_v6_accepts_valid_range(v6: int) -> None:
    # Stay <= default max (48); cross-field check is exercised separately.
    s = Settings(min_prefix_v6=v6)
    assert s.min_prefix_v6 == v6


def test_min_prefix_v6_at_field_upper_bound() -> None:
    s = Settings(min_prefix_v6=128, max_prefix_v6=128)
    assert s.min_prefix_v6 == 128


@pytest.mark.parametrize("v6", [-1, 129, 256])
def test_min_prefix_v6_rejects_out_of_range(v6: int) -> None:
    with pytest.raises(ValidationError):
        Settings(min_prefix_v6=v6)


def test_min_must_not_exceed_max_v4() -> None:
    """min_prefix_v4 > max_prefix_v4 must raise — otherwise every IPv4 BGP query
    is rejected with no obvious indicator that the misconfiguration is the cause."""
    with pytest.raises(ValidationError, match="min_prefix_v4=25 > max_prefix_v4=24"):
        Settings(min_prefix_v4=25, max_prefix_v4=24)


def test_min_must_not_exceed_max_v6() -> None:
    with pytest.raises(ValidationError, match="min_prefix_v6=49 > max_prefix_v6=48"):
        Settings(min_prefix_v6=49, max_prefix_v6=48)


def test_min_equal_to_max_is_allowed() -> None:
    """Edge: min == max means only that single prefix length is accepted —
    valid (if niche) configuration."""
    s = Settings(min_prefix_v4=24, max_prefix_v4=24)
    assert s.min_prefix_v4 == s.max_prefix_v4 == 24


def test_friendly_error_too_broad_formats_min_values() -> None:
    t = {"error_prefix_too_broad": "Prefix too broad (min /{v4} for IPv4, /{v6} for IPv6)"}
    with patch("bgpeek.api.query.settings") as mock_settings:
        mock_settings.min_prefix_v4 = 8
        mock_settings.min_prefix_v6 = 16
        msg = _friendly_error("prefix too broad", t)
    assert "/8" in msg
    assert "/16" in msg


def test_friendly_error_too_broad_survives_missing_placeholders() -> None:
    t = {"error_prefix_too_broad": "Prefix too broad"}
    with patch("bgpeek.api.query.settings") as mock_settings:
        mock_settings.min_prefix_v4 = 8
        mock_settings.min_prefix_v6 = 16
        msg = _friendly_error("prefix too broad", t)
    assert msg == "Prefix too broad"
