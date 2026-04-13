"""Smoke test: health endpoint and index page render."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from bgpeek import __version__
from bgpeek.main import app


def test_health() -> None:
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__


def test_index_renders() -> None:
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "bgpeek" in response.text.lower()
    assert "htmx" in response.text.lower()


def test_deep_health_all_ok() -> None:
    mock_pool = AsyncMock()
    mock_pool.fetchval = AsyncMock(return_value=1)
    mock_redis = AsyncMock()
    mock_redis.ping = AsyncMock(return_value=True)

    client = TestClient(app)
    with (
        patch("bgpeek.main.get_pool", return_value=mock_pool),
        patch("bgpeek.main.get_redis", return_value=mock_redis),
    ):
        response = client.get("/api/health?deep=true")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["redis"] == "ok"


def test_deep_health_degraded_db_down() -> None:
    mock_redis = AsyncMock()
    mock_redis.ping = AsyncMock(return_value=True)

    client = TestClient(app)
    with (
        patch("bgpeek.main.get_pool", side_effect=RuntimeError("no pool")),
        patch("bgpeek.main.get_redis", return_value=mock_redis),
    ):
        response = client.get("/api/health?deep=true")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert "error" in body["database"]
    assert body["redis"] == "ok"


def test_deep_health_degraded_redis_down() -> None:
    mock_pool = AsyncMock()
    mock_pool.fetchval = AsyncMock(return_value=1)

    client = TestClient(app)
    with (
        patch("bgpeek.main.get_pool", return_value=mock_pool),
        patch("bgpeek.main.get_redis", side_effect=RuntimeError("no redis")),
    ):
        response = client.get("/api/health?deep=true")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["database"] == "ok"
    assert "error" in body["redis"]
