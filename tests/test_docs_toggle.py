"""Tests for the BGPEEK_DOCS_ENABLED toggle (A4 — prod-gate hardening)."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from bgpeek.core.templates import templates


def _build_fresh_app(*, docs_enabled: bool) -> FastAPI:
    """Build a minimal FastAPI mirroring the two settings `main.py` wires from
    `settings.docs_enabled`. Avoids reloading `bgpeek.main` (which pollutes
    `sys.modules` and breaks other test modules that cached `from bgpeek.main
    import app` at module scope)."""
    return FastAPI(
        docs_url="/api/docs" if docs_enabled else None,
        openapi_url="/api/openapi.json" if docs_enabled else None,
        redoc_url=None,
    )


class TestDocsEndpointDefault:
    """Under the OSS-friendly default (`docs_enabled=True`) Swagger is live."""

    def test_swagger_ui_returns_200(self) -> None:
        from bgpeek.main import app

        client = TestClient(app)
        resp = client.get("/api/docs")
        assert resp.status_code == 200

    def test_openapi_schema_returns_200(self) -> None:
        from bgpeek.main import app

        client = TestClient(app)
        resp = client.get("/api/openapi.json")
        assert resp.status_code == 200
        # Sanity: the JSON payload is actually an OpenAPI document.
        assert resp.json().get("openapi", "").startswith("3.")

    def test_app_wired_under_default_settings(self) -> None:
        from bgpeek.main import app

        # The built-in Swagger UI is replaced by a branded /api/docs handler
        # that renders the same spec inside the app shell, so FastAPI's own
        # ``docs_url`` is None even when docs are enabled. The OpenAPI schema
        # is still served from FastAPI itself, gated on ``docs_enabled``.
        assert app.docs_url is None
        assert app.openapi_url == "/api/openapi.json"
        assert app.redoc_url is None


class TestDocsEndpointDisabled:
    """Verify that a FastAPI constructed with `docs_enabled=False` returns 404
    on both the Swagger UI and the OpenAPI schema. The module-level `bgpeek.main`
    app can't be re-wired in place (FastAPI freezes docs URLs at construction),
    so we rebuild a minimal app that mirrors the same conditional."""

    def test_swagger_ui_404_when_disabled(self) -> None:
        app = _build_fresh_app(docs_enabled=False)
        assert app.docs_url is None
        assert app.openapi_url is None
        client = TestClient(app)
        assert client.get("/api/docs").status_code == 404
        assert client.get("/api/openapi.json").status_code == 404

    def test_swagger_ui_200_when_enabled(self) -> None:
        app = _build_fresh_app(docs_enabled=True)
        assert app.docs_url == "/api/docs"
        assert app.openapi_url == "/api/openapi.json"
        client = TestClient(app)
        assert client.get("/api/docs").status_code == 200
        assert client.get("/api/openapi.json").status_code == 200


class TestDocsLinkInHeader:
    """Template-side: the `API` header link mirrors the toggle via a Jinja2 global."""

    def test_link_present_under_default(self) -> None:
        from bgpeek.main import app

        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 200
        assert 'href="/api/docs"' in resp.text

    def test_link_hidden_when_global_is_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from bgpeek.main import app
        from bgpeek.core import templates as templates_mod

        # ``header_links_for`` filters the docs entry based on
        # ``settings.docs_enabled`` at render time, so toggle it on the live
        # settings object rather than through the Jinja global (the Jinja
        # global is a display-only fallback for templates that still consult
        # it directly).
        monkeypatch.setitem(templates.env.globals, "docs_enabled", False)
        monkeypatch.setattr(templates_mod.settings, "docs_enabled", False)
        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 200
        assert 'href="/api/docs"' not in resp.text


class TestDocsConfig:
    def test_default_is_true(self) -> None:
        from bgpeek.config import Settings

        assert Settings().docs_enabled is True

    def test_accepts_false(self) -> None:
        from bgpeek.config import Settings

        assert Settings(docs_enabled=False).docs_enabled is False
