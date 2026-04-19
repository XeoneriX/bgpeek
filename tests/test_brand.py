"""Tests for branding-related configuration and template behavior."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from bgpeek.config import Settings
from bgpeek.main import app


def test_primary_asn_accepts_digits_only() -> None:
    settings = Settings(_env_file=None, primary_asn="64496")
    assert settings.primary_asn == "64496"


def test_primary_asn_rejects_as_prefix() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, primary_asn="AS64496")


def test_primary_asn_accepts_empty_string() -> None:
    settings = Settings(_env_file=None, primary_asn="")
    assert settings.primary_asn == ""


def test_primary_asn_unset_hides_peeringdb_icon(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from bgpeek.core.templates import templates

    monkeypatch.setitem(templates.env.globals["brand"], "primary_asn", "")
    monkeypatch.setitem(templates.env.globals["brand"], "peeringdb_link_enabled", False)

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "/static/peeringdb.png" not in response.text
    assert "peeringdb.com/asn/" not in response.text


def test_primary_asn_unset_site_name_has_no_as_prefix(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from bgpeek.core.templates import templates

    monkeypatch.setitem(templates.env.globals["brand"], "site_name", "bgpeek")
    monkeypatch.setitem(templates.env.globals["brand"], "primary_asn", "")
    monkeypatch.setitem(templates.env.globals["brand"], "peeringdb_link_enabled", False)

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "<title>bgpeek &middot; looking glass</title>" in response.text
    assert "AS bgpeek" not in response.text


def test_brand_page_titles_parses_json(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv(
        "BGPEEK_BRAND_PAGE_TITLES",
        '{"index":"AS64496 Home","login":"sign in"}',
    )
    settings = Settings(_env_file=None)
    assert settings.brand_page_titles["index"] == "AS64496 Home"
    assert settings.brand_page_titles["login"] == "sign in"


def test_brand_theme_storage_key_in_html(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from bgpeek.core.templates import templates

    monkeypatch.setitem(templates.env.globals["brand"], "theme_storage_key", "custom-theme-key")

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert 'data-theme-storage-key="custom-theme-key"' in response.text


def test_brand_page_title_override_on_index(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from bgpeek.core.templates import templates

    monkeypatch.setitem(templates.env.globals["brand"], "site_name", "AS64496 bgpeek")
    monkeypatch.setitem(templates.env.globals["brand"], "page_titles", {"index": "Home"})

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "<title>AS64496 bgpeek &middot; Home</title>" in response.text


def test_brand_footer_renders_html_when_set(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from bgpeek.core.templates import templates

    footer = '<a href="https://example.com">example.com</a>'
    monkeypatch.setitem(templates.env.globals["brand"], "footer", footer)

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert footer in response.text
    assert '<span class="mx-1">&middot;</span>' in response.text


def test_brand_footer_separator_hidden_when_empty(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from bgpeek.core.templates import templates

    monkeypatch.setitem(templates.env.globals["brand"], "footer", "")

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert '<span class="mx-1">&middot;</span>' not in response.text


def test_brand_site_name_shown_in_header(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from bgpeek.core.templates import templates

    monkeypatch.setitem(templates.env.globals["brand"], "site_name", "AS65000 bgpeek")

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "AS65000 bgpeek" in response.text


def test_brand_page_title_override_on_login(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from bgpeek.core.templates import templates

    monkeypatch.setitem(templates.env.globals["brand"], "site_name", "AS64496 bgpeek")
    monkeypatch.setitem(templates.env.globals["brand"], "page_titles", {"login": "access"})

    client = TestClient(app)
    response = client.get("/auth/login")
    assert response.status_code == 200
    assert "<title>AS64496 bgpeek &middot; access</title>" in response.text


def test_brand_page_title_override_on_history(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from bgpeek.core.templates import templates

    monkeypatch.setitem(templates.env.globals["brand"], "site_name", "AS64496 bgpeek")
    monkeypatch.setitem(templates.env.globals["brand"], "page_titles", {"history": "queries"})

    client = TestClient(app)
    response = client.get("/history")
    assert response.status_code == 200
    assert "<title>AS64496 bgpeek &middot; queries</title>" in response.text


def test_footer_always_keeps_bgpeek_version_prefix(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from bgpeek import __version__
    from bgpeek.core.templates import templates

    monkeypatch.setitem(templates.env.globals["brand"], "footer", "")

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert f"bgpeek</a> v{__version__}" in response.text
