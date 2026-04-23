"""Unit tests for template helper behavior."""

from __future__ import annotations

from types import SimpleNamespace

from bgpeek.core.templates import _base_context, header_links_for
from bgpeek.models.user import UserRole

_TRANSLATIONS = {
    "looking_glass": "Looking Glass",
    "history": "History",
    "api_docs": "API",
    "admin": "Admin",
}


def _ctx(path: str | None = None) -> dict[str, object]:
    if path is None:
        return {}
    request = SimpleNamespace(url=SimpleNamespace(path=path))
    return {"request": request}


def test_base_context_returns_user_from_request_state() -> None:
    request = SimpleNamespace(
        state=SimpleNamespace(user="alice"), url=SimpleNamespace(path="/history")
    )
    assert _base_context(request) == {"user": "alice", "current_path": "/history"}


def test_base_context_defaults_user_to_none_when_missing() -> None:
    request = SimpleNamespace(state=SimpleNamespace(), url=SimpleNamespace(path="/"))
    assert _base_context(request) == {"user": None, "current_path": "/"}


def test_header_links_for_non_admin_defaults() -> None:
    links = header_links_for(_ctx(), _TRANSLATIONS, user=SimpleNamespace(role="public"))
    assert links == [
        {"href": "/", "label": "Looking Glass", "active": True},
        {"href": "/history", "label": "History", "active": False},
        {"href": "/api/docs", "label": "API", "active": False},
    ]


def test_header_links_for_admin_adds_admin_link() -> None:
    links = header_links_for(_ctx(), _TRANSLATIONS, user=SimpleNamespace(role="admin"))
    assert links == [
        {"href": "/", "label": "Looking Glass", "active": True},
        {"href": "/history", "label": "History", "active": False},
        {"href": "/api/docs", "label": "API", "active": False},
        {"href": "/admin", "label": "Admin", "active": False},
    ]


def test_header_links_for_accepts_enum_role() -> None:
    links = header_links_for(_ctx(), _TRANSLATIONS, user=SimpleNamespace(role=UserRole.ADMIN))
    assert {"href": "/admin", "label": "Admin", "active": False} in links


def test_header_links_for_keeps_consistent_order() -> None:
    links = header_links_for(
        _ctx("/history"),
        _TRANSLATIONS,
        user=SimpleNamespace(role="admin"),
    )
    assert links == [
        {"href": "/", "label": "Looking Glass", "active": False},
        {"href": "/history", "label": "History", "active": True},
        {"href": "/api/docs", "label": "API", "active": False},
        {"href": "/admin", "label": "Admin", "active": False},
    ]


def test_header_links_for_inferrs_admin_section_marks_admin_active() -> None:
    links = header_links_for(
        _ctx("/admin/users"),
        _TRANSLATIONS,
        user=SimpleNamespace(role="admin"),
    )
    assert links == [
        {"href": "/", "label": "Looking Glass", "active": False},
        {"href": "/history", "label": "History", "active": False},
        {"href": "/api/docs", "label": "API", "active": False},
        {"href": "/admin", "label": "Admin", "active": True},
    ]


def test_header_links_for_inferrs_history_section_marks_history_active() -> None:
    links = header_links_for(
        _ctx("/history"),
        _TRANSLATIONS,
        user=SimpleNamespace(role="admin"),
    )
    assert links == [
        {"href": "/", "label": "Looking Glass", "active": False},
        {"href": "/history", "label": "History", "active": True},
        {"href": "/api/docs", "label": "API", "active": False},
        {"href": "/admin", "label": "Admin", "active": False},
    ]


def test_header_links_for_allows_current_path_override() -> None:
    links = header_links_for(
        _ctx("/history"),
        _TRANSLATIONS,
        user=SimpleNamespace(role="admin"),
        current_path="/admin/users",
    )
    assert links == [
        {"href": "/", "label": "Looking Glass", "active": False},
        {"href": "/history", "label": "History", "active": False},
        {"href": "/api/docs", "label": "API", "active": False},
        {"href": "/admin", "label": "Admin", "active": True},
    ]


def test_header_links_for_home_stays_active_on_non_history_non_admin_pages() -> None:
    links = header_links_for(
        _ctx("/result/abc123"), _TRANSLATIONS, user=SimpleNamespace(role="public")
    )
    assert links[0] == {"href": "/", "label": "Looking Glass", "active": True}
