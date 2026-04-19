"""Tests for link-related configuration and rendering."""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from bgpeek.config import Settings
from bgpeek.main import _parse_lg_links, app


def test_lg_links_env_is_loaded(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    raw = '[{"name":"Example LG","url":"https://lg.example.com"}]'
    monkeypatch.setenv("BGPEEK_LG_LINKS", raw)
    settings = Settings(_env_file=None)
    assert settings.lg_links == raw


def test_peeringdb_link_enabled_env_parses_false(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("BGPEEK_PEERINGDB_LINK_ENABLED", "false")
    settings = Settings(_env_file=None)
    assert settings.peeringdb_link_enabled is False


def test_peeringdb_link_enabled_env_parses_true(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("BGPEEK_PEERINGDB_LINK_ENABLED", "true")
    settings = Settings(_env_file=None)
    assert settings.peeringdb_link_enabled is True


def test_parse_lg_links_returns_empty_for_invalid_json() -> None:
    with patch("bgpeek.main.settings") as mock_settings:
        mock_settings.lg_links = "{not-json}"
        assert _parse_lg_links() == []


def test_parse_lg_links_returns_empty_for_non_list() -> None:
    with patch("bgpeek.main.settings") as mock_settings:
        mock_settings.lg_links = '{"name":"Example LG","url":"https://lg.example.com"}'
        assert _parse_lg_links() == []


def test_parse_lg_links_filters_invalid_entries() -> None:
    raw = (
        '[{"name":"Example LG","url":"https://lg.example.com"},'
        ' {"name":"MissingURL"},'
        ' {"url":"https://example.com"},'
        " 123,"
        ' {"name":42,"url":9001}]'
    )
    with patch("bgpeek.main.settings") as mock_settings:
        mock_settings.lg_links = raw
        assert _parse_lg_links() == [
            {"name": "Example LG", "url": "https://lg.example.com"},
            {"name": "42", "url": "9001"},
        ]


def test_parse_lg_links_returns_empty_when_blank() -> None:
    with patch("bgpeek.main.settings") as mock_settings:
        mock_settings.lg_links = "   "
        assert _parse_lg_links() == []


def test_index_renders_lg_links_when_configured(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "bgpeek.main._lg_links",
        [{"name": "Example LG", "url": "https://lg.example.com"}],
    )

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "Example LG" in response.text
    assert "https://lg.example.com" in response.text


def test_index_hides_peeringdb_icon_when_disabled(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from bgpeek.core.templates import templates

    monkeypatch.setitem(templates.env.globals["brand"], "peeringdb_link_enabled", False)

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "/static/peeringdb.png" not in response.text


def test_index_shows_peeringdb_icon_when_enabled(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from bgpeek.core.templates import templates

    monkeypatch.setitem(templates.env.globals["brand"], "peeringdb_link_enabled", True)
    monkeypatch.setitem(
        templates.env.globals["brand"], "peeringdb_url", "https://www.peeringdb.com/asn/65000"
    )

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "/static/peeringdb.png" in response.text
    assert "https://www.peeringdb.com/asn/65000" in response.text


def test_history_hides_peeringdb_icon_when_disabled(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from bgpeek.core.templates import templates

    monkeypatch.setitem(templates.env.globals["brand"], "peeringdb_link_enabled", False)

    client = TestClient(app)
    response = client.get("/history")
    assert response.status_code == 200
    assert "/static/peeringdb.png" not in response.text


def test_history_shows_peeringdb_icon_when_enabled(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from bgpeek.core.templates import templates

    monkeypatch.setitem(templates.env.globals["brand"], "peeringdb_link_enabled", True)
    monkeypatch.setitem(
        templates.env.globals["brand"], "peeringdb_url", "https://www.peeringdb.com/asn/64496"
    )

    client = TestClient(app)
    response = client.get("/history")
    assert response.status_code == 200
    assert "/static/peeringdb.png" in response.text
    assert "https://www.peeringdb.com/asn/64496" in response.text
