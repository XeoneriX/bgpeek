"""Tests for the admin panel UI (SSR routes)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from bgpeek.main import app
from bgpeek.models.user import User, UserRole

_NOW = datetime.now(tz=UTC)

_ADMIN = User(
    id=1,
    username="admin",
    email="admin@example.com",
    role=UserRole.ADMIN,
    auth_provider="api_key",
    api_key_hash="h",
    enabled=True,
    created_at=_NOW,
)

_NOC = User(
    id=2,
    username="noc",
    email=None,
    role=UserRole.NOC,
    auth_provider="api_key",
    api_key_hash="h2",
    enabled=True,
    created_at=_NOW,
)


# Every admin route, regardless of method, must reject non-admin users.
# Parameterised so a new route added later is covered automatically if included
# in this list. Centralises defense-in-depth coverage.
_ADMIN_ROUTES: list[tuple[str, str]] = [
    ("GET", "/admin"),
    ("GET", "/admin/devices"),
    ("GET", "/admin/devices/new"),
    ("POST", "/admin/devices"),
    ("GET", "/admin/devices/1/edit"),
    ("POST", "/admin/devices/1"),
    ("POST", "/admin/devices/1/delete"),
    ("GET", "/admin/credentials"),
    ("GET", "/admin/credentials/new"),
    ("POST", "/admin/credentials"),
    ("GET", "/admin/credentials/1/edit"),
    ("POST", "/admin/credentials/1"),
    ("POST", "/admin/credentials/1/delete"),
    ("GET", "/admin/users"),
    ("GET", "/admin/users/new"),
    ("POST", "/admin/users"),
    ("GET", "/admin/users/1/edit"),
    ("POST", "/admin/users/1"),
    ("POST", "/admin/users/1/delete"),
    ("GET", "/admin/community-labels"),
    ("GET", "/admin/community-labels/new"),
    ("POST", "/admin/community-labels"),
    ("GET", "/admin/community-labels/1/edit"),
    ("POST", "/admin/community-labels/1"),
    ("POST", "/admin/community-labels/1/delete"),
    ("GET", "/admin/webhooks"),
    ("GET", "/admin/webhooks/new"),
    ("POST", "/admin/webhooks"),
    ("GET", "/admin/webhooks/1/edit"),
    ("POST", "/admin/webhooks/1"),
    ("POST", "/admin/webhooks/1/delete"),
]


@pytest.mark.parametrize(("method", "path"), _ADMIN_ROUTES)
def test_admin_routes_reject_noc(method: str, path: str) -> None:
    """Every admin route returns 403 for a non-admin (NOC) caller."""
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_NOC),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
    ):
        client = TestClient(app)
        response = client.request(
            method, path, headers={"X-API-Key": "any"}, follow_redirects=False
        )

    assert response.status_code == 403, (
        f"{method} {path} returned {response.status_code}, expected 403"
    )


@pytest.mark.parametrize(("method", "path"), _ADMIN_ROUTES)
def test_admin_routes_reject_unauthenticated(method: str, path: str) -> None:
    """Every admin route returns 401 for an unauthenticated caller."""
    client = TestClient(app)
    response = client.request(method, path, follow_redirects=False)
    assert response.status_code == 401, (
        f"{method} {path} returned {response.status_code}, expected 401"
    )


def test_admin_index_no_auth_returns_401() -> None:
    client = TestClient(app)
    response = client.get("/admin")
    assert response.status_code == 401


def test_admin_index_noc_user_returns_403() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_NOC),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
    ):
        client = TestClient(app)
        response = client.get("/admin", headers={"X-API-Key": "any"})
    assert response.status_code == 403


def test_admin_index_admin_renders_dashboard() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.device_crud.list_devices",
            new=AsyncMock(return_value=[1, 2, 3]),
        ),
        patch(
            "bgpeek.ui.admin.user_crud.list_users",
            new=AsyncMock(return_value=[_ADMIN, _NOC]),
        ),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[1]),
        ),
        patch(
            "bgpeek.ui.admin.webhook_crud.list_webhooks",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "bgpeek.ui.admin.label_crud.list_labels",
            new=AsyncMock(return_value=[1, 2, 3, 4]),
        ),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
    ):
        client = TestClient(app)
        response = client.get("/admin", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    body = response.text
    assert "Dashboard" in body
    # Stat counts rendered
    assert ">3<" in body  # devices
    assert ">2<" in body  # users
    assert ">1<" in body  # credentials
    assert ">0<" in body  # webhooks
    assert ">4<" in body  # community labels
    # Sidebar nav present
    assert "/admin/devices" in body
    assert "/admin/users" in body
    assert "/admin/community-labels" in body


def test_admin_link_shown_for_admin_in_main_navbar() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.main.get_pool", return_value=object()),
        patch("bgpeek.main.device_crud.list_devices", new=AsyncMock(return_value=[])),
    ):
        client = TestClient(app)
        response = client.get("/", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert 'href="/admin"' in response.text


def test_admin_link_hidden_for_noc_in_main_navbar() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_NOC),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.main.get_pool", return_value=object()),
        patch("bgpeek.main.device_crud.list_devices", new=AsyncMock(return_value=[])),
    ):
        client = TestClient(app)
        response = client.get("/", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert 'href="/admin"' not in response.text


# ---------------------------------------------------------------------------
# Admin devices CRUD
# ---------------------------------------------------------------------------


_DEVICE_ROW = {
    "id": 1,
    "name": "rt1",
    "address": "192.0.2.1",
    "port": 22,
    "platform": "juniper_junos",
    "description": "",
    "location": "SYD",
    "region": "AU",
    "enabled": True,
    "restricted": False,
    "credential_id": None,
    "source4": None,
    "source6": None,
    "created_at": _NOW,
    "updated_at": _NOW,
}


def _admin_auth_patches() -> list:
    return [
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
    ]


def test_devices_list_renders() -> None:
    from bgpeek.models.device import Device

    device = Device.model_validate(_DEVICE_ROW)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.device_crud.list_devices",
            new=AsyncMock(return_value=[device]),
        ),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "bgpeek.ui.admin.cb_failure_counts",
            new=AsyncMock(return_value={}),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.device_query_stats",
            new=AsyncMock(return_value={}),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.devices_with_success_history",
            new=AsyncMock(return_value=set()),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.recent_device_failures",
            new=AsyncMock(return_value={}),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/devices", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert "rt1" in response.text
    assert "192.0.2.1" in response.text
    assert "juniper_junos" in response.text
    assert "/admin/devices/new" in response.text
    assert "/admin/devices/1/edit" in response.text


def test_devices_list_shows_recent_failure_error_as_tooltip() -> None:
    """When `recent_device_failures` has a row for a device, the badge's
    `title=` attribute surfaces the concrete error message so operators can
    see `ssh connect timeout` on hover without cracking open the server logs.
    """
    from datetime import UTC, datetime

    from bgpeek.models.device import Device

    device = Device.model_validate(_DEVICE_ROW)
    recent = {device.id: ("ssh connect timeout", datetime.now(UTC))}
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.device_crud.list_devices",
            new=AsyncMock(return_value=[device]),
        ),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "bgpeek.ui.admin.cb_failure_counts",
            new=AsyncMock(return_value={}),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.device_query_stats",
            new=AsyncMock(return_value={}),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.devices_with_success_history",
            new=AsyncMock(return_value={device.id}),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.recent_device_failures",
            new=AsyncMock(return_value=recent),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/devices", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert 'title="ssh connect timeout"' in response.text


def test_devices_list_renders_circuit_breaker_status() -> None:
    from bgpeek.models.device import Device

    device = Device.model_validate(_DEVICE_ROW)
    # Default threshold is 3, so 2 recent failures render the warning badge.
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.device_crud.list_devices",
            new=AsyncMock(return_value=[device]),
        ),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "bgpeek.ui.admin.cb_failure_counts",
            new=AsyncMock(return_value={"rt1": 2}),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.device_query_stats",
            new=AsyncMock(return_value={}),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.devices_with_success_history",
            new=AsyncMock(return_value=set()),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.recent_device_failures",
            new=AsyncMock(return_value={}),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/devices", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    # Warning badge: <count>/<threshold>
    assert "2/3" in response.text


def test_devices_list_renders_circuit_breaker_open() -> None:
    from bgpeek.models.device import Device

    device = Device.model_validate(_DEVICE_ROW)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.device_crud.list_devices",
            new=AsyncMock(return_value=[device]),
        ),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "bgpeek.ui.admin.cb_failure_counts",
            new=AsyncMock(return_value={"rt1": 999}),  # well over any threshold
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.device_query_stats",
            new=AsyncMock(return_value={}),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.devices_with_success_history",
            new=AsyncMock(return_value=set()),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.recent_device_failures",
            new=AsyncMock(return_value={}),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/devices", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert "Open (blocked)" in response.text


def test_devices_list_renders_query_usage() -> None:
    from datetime import UTC, datetime

    from bgpeek.models.device import Device

    device = Device.model_validate(_DEVICE_ROW)
    last_seen = datetime(2026, 4, 17, 10, 30, tzinfo=UTC)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.device_crud.list_devices",
            new=AsyncMock(return_value=[device]),
        ),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "bgpeek.ui.admin.cb_failure_counts",
            new=AsyncMock(return_value={}),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.device_query_stats",
            new=AsyncMock(return_value={1: (last_seen, 42)}),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.devices_with_success_history",
            new=AsyncMock(return_value=set()),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.recent_device_failures",
            new=AsyncMock(return_value={}),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/devices", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert "42 queries" in response.text
    assert "2026-04-17 10:30" in response.text


def test_devices_list_renders_never_queried() -> None:
    from bgpeek.models.device import Device

    device = Device.model_validate(_DEVICE_ROW)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.device_crud.list_devices",
            new=AsyncMock(return_value=[device]),
        ),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "bgpeek.ui.admin.cb_failure_counts",
            new=AsyncMock(return_value={}),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.device_query_stats",
            new=AsyncMock(return_value={}),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.devices_with_success_history",
            new=AsyncMock(return_value=set()),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.recent_device_failures",
            new=AsyncMock(return_value={}),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/devices", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert "never queried" in response.text


def test_devices_list_has_query_link() -> None:
    from bgpeek.models.device import Device

    device = Device.model_validate(_DEVICE_ROW)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.device_crud.list_devices",
            new=AsyncMock(return_value=[device]),
        ),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "bgpeek.ui.admin.cb_failure_counts",
            new=AsyncMock(return_value={}),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.device_query_stats",
            new=AsyncMock(return_value={}),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.devices_with_success_history",
            new=AsyncMock(return_value=set()),
        ),
        patch(
            "bgpeek.ui.admin.audit_crud.recent_device_failures",
            new=AsyncMock(return_value={}),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/devices", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert 'href="/?location=rt1"' in response.text


def test_index_preselects_device_when_param_matches() -> None:
    from bgpeek.models.device import Device

    device = Device.model_validate(_DEVICE_ROW)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.main.get_pool", return_value=object()),
        patch(
            "bgpeek.main.device_crud.list_devices",
            new=AsyncMock(return_value=[device]),
        ),
    ):
        client = TestClient(app)
        response = client.get("/?location=rt1", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    # Option for rt1 is rendered with selected attribute
    assert 'value="rt1" selected' in response.text


def test_index_ignores_unknown_location_param() -> None:
    from bgpeek.models.device import Device

    device = Device.model_validate(_DEVICE_ROW)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.main.get_pool", return_value=object()),
        patch(
            "bgpeek.main.device_crud.list_devices",
            new=AsyncMock(return_value=[device]),
        ),
    ):
        client = TestClient(app)
        response = client.get("/?location=does-not-exist", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    # No <option ... selected> attribute on any device
    assert 'value="rt1" selected' not in response.text


def test_devices_list_noc_returns_403() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_NOC),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
    ):
        client = TestClient(app)
        response = client.get("/admin/devices", headers={"X-API-Key": "any"})

    assert response.status_code == 403


def test_devices_new_form_renders() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/devices/new", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert 'name="name"' in response.text
    assert 'name="address"' in response.text
    assert 'name="platform"' in response.text
    # Platforms datalist populated from supported_platforms()
    assert "juniper_junos" in response.text


def test_devices_create_redirects_and_calls_crud() -> None:
    from bgpeek.models.device import Device

    created_device = Device.model_validate(_DEVICE_ROW)
    create_mock = AsyncMock(return_value=created_device)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.device_crud.create_device", new=create_mock),
        patch("bgpeek.ui.admin.log_audit", new=AsyncMock(return_value=None)),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/devices",
            headers={"X-API-Key": "any"},
            data={
                "name": "rt1",
                "address": "192.0.2.1",
                "platform": "juniper_junos",
                "port": "22",
                "enabled": "1",
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/devices"
    create_mock.assert_awaited_once()
    payload = create_mock.await_args.args[1]
    assert payload.name == "rt1"
    assert str(payload.address) == "192.0.2.1"
    assert payload.enabled is True


def test_devices_create_invalid_address_rerenders_form() -> None:
    create_mock = AsyncMock()
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
        patch("bgpeek.ui.admin.device_crud.create_device", new=create_mock),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/devices",
            headers={"X-API-Key": "any"},
            data={
                "name": "rt1",
                "address": "not-an-ip",
                "platform": "juniper_junos",
                "port": "22",
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert 'name="name"' in response.text  # form re-rendered
    create_mock.assert_not_awaited()


def test_devices_new_form_has_no_test_ssh_button() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/devices/new", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert "test-ssh-btn" not in response.text
    assert "Test SSH" not in response.text


def test_devices_edit_form_shows_test_ssh_when_cred_set() -> None:
    from bgpeek.models.device import Device

    row = dict(_DEVICE_ROW)
    row["credential_id"] = 7
    device = Device.model_validate(row)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.device_crud.get_device_by_id",
            new=AsyncMock(return_value=device),
        ),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/devices/1/edit", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert "test-ssh-btn" in response.text
    # The fetch target wires in the credential and device IDs
    assert "bgpeekTestSSH(7, 1)" in response.text


def test_devices_edit_form_shows_hint_without_credential() -> None:
    from bgpeek.models.device import Device

    device = Device.model_validate(_DEVICE_ROW)  # credential_id=None
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.device_crud.get_device_by_id",
            new=AsyncMock(return_value=device),
        ),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/devices/1/edit", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert "test-ssh-btn" not in response.text
    assert "Assign an SSH credential" in response.text


def test_devices_new_form_save_button_has_loading_attribute() -> None:
    """Save buttons in admin forms opt into the disable-on-submit loader via
    `data-loading-text`. Delete buttons (inline `text-xs`) deliberately skip
    the attribute — swapping their label to "Saving…" would shift layout."""
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/devices/new", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert 'data-loading-text="Saving…"' in response.text
    # And the loader IIFE is wired into the base template once.
    assert "data-loading-text" in response.text
    assert "btn.dataset.loadingText" in response.text


def test_devices_new_form_includes_junos_source_warning() -> None:
    """Warning block + toggle JS ship with every device form; visibility is client-side."""
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/devices/new", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    # Warning element ships with `hidden` attr — JS flips it when platform=junos + no source.
    assert 'id="junos-source-warning"' in response.text
    assert "juniper_junos" in response.text  # platform literal referenced by the toggle
    assert "explicit source IP" in response.text


def test_devices_edit_form_prefilled() -> None:
    from bgpeek.models.device import Device

    device = Device.model_validate(_DEVICE_ROW)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.device_crud.get_device_by_id",
            new=AsyncMock(return_value=device),
        ),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[]),
        ),
    ):
        client = TestClient(app)
        response = client.get(
            "/admin/devices/1/edit",
            headers={"X-API-Key": "any"},
        )

    assert response.status_code == 200
    assert 'value="rt1"' in response.text
    assert 'value="192.0.2.1"' in response.text
    assert 'action="/admin/devices/1"' in response.text


def test_devices_delete_redirects_and_calls_crud() -> None:
    from bgpeek.models.device import Device

    device = Device.model_validate(_DEVICE_ROW)
    delete_mock = AsyncMock(return_value=True)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.device_crud.get_device_by_id",
            new=AsyncMock(return_value=device),
        ),
        patch("bgpeek.ui.admin.device_crud.delete_device", new=delete_mock),
        patch("bgpeek.ui.admin.invalidate_device", new=AsyncMock()),
        patch("bgpeek.ui.admin.log_audit", new=AsyncMock(return_value=None)),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/devices/1/delete",
            headers={"X-API-Key": "any"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/devices"
    delete_mock.assert_awaited_once()


# ---------------------------------------------------------------------------
# Admin credentials CRUD
# ---------------------------------------------------------------------------


_CRED_ROW = {
    "id": 1,
    "name": "default",
    "description": "",
    "auth_type": "key",
    "username": "lg-user",
    "key_name": "id_rsa",
    "password": None,
    "created_at": _NOW,
    "updated_at": _NOW,
    "device_count": 2,
}


def test_credentials_list_renders() -> None:
    from bgpeek.models.credential import CredentialWithUsage

    cred = CredentialWithUsage.model_validate(_CRED_ROW)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[cred]),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/credentials", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert "default" in response.text
    assert "lg-user" in response.text
    assert "id_rsa" in response.text
    assert "/admin/credentials/new" in response.text
    assert "/admin/credentials/1/edit" in response.text


def test_credentials_list_hides_delete_when_in_use() -> None:
    from bgpeek.models.credential import CredentialWithUsage

    cred = CredentialWithUsage.model_validate(_CRED_ROW)  # device_count=2
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.credential_crud.list_credentials",
            new=AsyncMock(return_value=[cred]),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/credentials", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert "/admin/credentials/1/delete" not in response.text


def test_credentials_new_form_renders() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
    ):
        client = TestClient(app)
        response = client.get("/admin/credentials/new", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert 'name="name"' in response.text
    assert 'name="auth_type"' in response.text
    assert 'name="username"' in response.text
    assert 'name="password"' in response.text


def test_credentials_create_key_only() -> None:
    create_mock = AsyncMock()
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.credential_crud.create_credential", new=create_mock),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/credentials",
            headers={"X-API-Key": "any"},
            data={
                "name": "default",
                "auth_type": "key",
                "username": "lg-user",
                "key_name": "id_rsa",
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/credentials"
    create_mock.assert_awaited_once()
    payload = create_mock.await_args.args[1]
    assert payload.name == "default"
    assert payload.key_name == "id_rsa"


def test_credentials_create_password_missing_rerenders() -> None:
    create_mock = AsyncMock()
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.credential_crud.create_credential", new=create_mock),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/credentials",
            headers={"X-API-Key": "any"},
            data={
                "name": "cred1",
                "auth_type": "password",
                "username": "u",
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "password is required" in response.text
    create_mock.assert_not_awaited()


def test_credentials_edit_form_omits_existing_password() -> None:
    from bgpeek.models.credential import Credential

    row = dict(_CRED_ROW)
    row["password"] = "****"  # noqa: S105  # masked value from list query
    row.pop("device_count")
    cred = Credential.model_validate(row)

    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.credential_crud.get_credential",
            new=AsyncMock(return_value=cred),
        ),
    ):
        client = TestClient(app)
        response = client.get(
            "/admin/credentials/1/edit",
            headers={"X-API-Key": "any"},
        )

    assert response.status_code == 200
    # Masked password must NOT be echoed into the form
    assert "****" not in response.text
    assert 'action="/admin/credentials/1"' in response.text


def test_credentials_update_empty_password_keeps_existing() -> None:
    from bgpeek.models.credential import Credential

    row = dict(_CRED_ROW)
    row["password"] = "****"  # noqa: S105
    row.pop("device_count")
    cred = Credential.model_validate(row)

    update_mock = AsyncMock(return_value=cred)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.credential_crud.get_credential",
            new=AsyncMock(return_value=cred),
        ),
        patch("bgpeek.ui.admin.credential_crud.update_credential", new=update_mock),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/credentials/1",
            headers={"X-API-Key": "any"},
            data={
                "name": "default",
                "auth_type": "key",
                "username": "lg-user",
                "key_name": "id_rsa",
                # password field omitted — should keep existing
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    update_mock.assert_awaited_once()
    payload = update_mock.await_args.args[2]
    # password must not be in the update set when left blank
    assert "password" not in payload.model_dump(exclude_unset=True)


def test_credentials_delete_in_use_returns_409() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.credential_crud.delete_credential",
            new=AsyncMock(side_effect=ValueError("credential 1 still referenced by 2 device(s)")),
        ),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/credentials/1/delete",
            headers={"X-API-Key": "any"},
            follow_redirects=False,
        )

    assert response.status_code == 409


# ---------------------------------------------------------------------------
# Admin users CRUD
# ---------------------------------------------------------------------------


def test_users_list_renders_and_marks_current() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.user_crud.list_users",
            new=AsyncMock(return_value=[_ADMIN, _NOC]),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/users", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert "admin" in response.text
    assert "noc" in response.text
    # "you" marker on current user (admin)
    assert "(you)" in response.text
    # Delete button for NOC (id=2), not for self (id=1)
    assert "/admin/users/2/delete" in response.text
    assert "/admin/users/1/delete" not in response.text


def test_users_new_form_renders() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
    ):
        client = TestClient(app)
        response = client.get("/admin/users/new", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert 'name="auth_type"' in response.text
    assert 'value="local"' in response.text
    assert 'value="api_key"' in response.text
    assert 'name="username"' in response.text
    assert 'name="password"' in response.text


def test_users_create_local_redirects() -> None:
    create_local_mock = AsyncMock()
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.user_crud.create_local_user", new=create_local_mock),
        patch("bgpeek.ui.admin.log_audit", new=AsyncMock(return_value=None)),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/users",
            headers={"X-API-Key": "any"},
            data={
                "auth_type": "local",
                "username": "alice",
                "email": "alice@example.com",
                "role": "public",
                "password": "correct-horse-battery-staple",
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/users"
    create_local_mock.assert_awaited_once()
    payload = create_local_mock.await_args.args[1]
    assert payload.username == "alice"
    assert payload.role == UserRole.PUBLIC


def test_users_create_local_short_password_rerenders() -> None:
    create_local_mock = AsyncMock()
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.user_crud.create_local_user", new=create_local_mock),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/users",
            headers={"X-API-Key": "any"},
            data={
                "auth_type": "local",
                "username": "alice",
                "role": "public",
                "password": "short",  # too short (min 8)
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert 'name="username"' in response.text  # form rerendered
    create_local_mock.assert_not_awaited()


def test_users_create_api_key_shows_key_page() -> None:
    create_mock = AsyncMock()
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.user_crud.create_user", new=create_mock),
        patch("bgpeek.ui.admin.log_audit", new=AsyncMock(return_value=None)),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/users",
            headers={"X-API-Key": "any"},
            data={
                "auth_type": "api_key",
                "username": "bot-user",
                "role": "noc",
            },
            follow_redirects=False,
        )

    assert response.status_code == 200
    assert "API key generated" in response.text
    assert "bot-user" in response.text
    # The generated key is displayed exactly once in the page
    create_mock.assert_awaited_once()
    payload = create_mock.await_args.args[1]
    assert payload.username == "bot-user"
    assert payload.api_key  # a key was generated


def test_users_create_invalid_role_rerenders() -> None:
    create_local_mock = AsyncMock()
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.user_crud.create_local_user", new=create_local_mock),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/users",
            headers={"X-API-Key": "any"},
            data={
                "auth_type": "local",
                "username": "alice",
                "role": "super-admin",  # not in _ROLE_CHOICES
                "password": "correct-horse-battery-staple",
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "invalid role" in response.text
    create_local_mock.assert_not_awaited()


def test_users_edit_form_prefilled() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.user_crud.get_user_by_id",
            new=AsyncMock(return_value=_NOC),
        ),
    ):
        client = TestClient(app)
        response = client.get(
            "/admin/users/2/edit",
            headers={"X-API-Key": "any"},
        )

    assert response.status_code == 200
    assert 'value="noc"' in response.text
    assert 'action="/admin/users/2"' in response.text


def test_users_update_redirects() -> None:
    update_mock = AsyncMock(return_value=_NOC)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.user_crud.update_user", new=update_mock),
        patch("bgpeek.ui.admin.log_audit", new=AsyncMock(return_value=None)),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/users/2",
            headers={"X-API-Key": "any"},
            data={
                "role": "public",
                "email": "noc@example.com",
                "enabled": "1",
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    update_mock.assert_awaited_once()
    payload = update_mock.await_args.args[2]
    assert payload.role == UserRole.PUBLIC
    assert payload.email == "noc@example.com"
    assert payload.enabled is True


def test_users_delete_self_returns_400() -> None:
    delete_mock = AsyncMock(return_value=True)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.user_crud.delete_user", new=delete_mock),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/users/1/delete",  # _ADMIN.id == 1
            headers={"X-API-Key": "any"},
            follow_redirects=False,
        )

    assert response.status_code == 400
    delete_mock.assert_not_awaited()


def test_users_delete_other_redirects() -> None:
    delete_mock = AsyncMock(return_value=True)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.user_crud.get_user_by_id",
            new=AsyncMock(return_value=_NOC),
        ),
        patch("bgpeek.ui.admin.user_crud.delete_user", new=delete_mock),
        patch("bgpeek.ui.admin.log_audit", new=AsyncMock(return_value=None)),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/users/2/delete",  # _NOC.id == 2
            headers={"X-API-Key": "any"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/users"
    delete_mock.assert_awaited_once()


# ---------------------------------------------------------------------------
# Admin community labels CRUD
# ---------------------------------------------------------------------------


_LABEL_ROW = {
    "id": 1,
    "pattern": "65000:100",
    "match_type": "exact",
    "label": "Customer traffic",
    "color": "emerald",
    "created_at": _NOW,
    "updated_at": _NOW,
}


def test_labels_list_renders() -> None:
    from bgpeek.models.community_label import CommunityLabel

    label = CommunityLabel.model_validate(_LABEL_ROW)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.label_crud.list_labels",
            new=AsyncMock(return_value=[label]),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/community-labels", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert "65000:100" in response.text
    assert "Customer traffic" in response.text
    assert "/admin/community-labels/new" in response.text
    assert "/admin/community-labels/1/edit" in response.text


def test_labels_new_form_renders_color_swatches() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
    ):
        client = TestClient(app)
        response = client.get("/admin/community-labels/new", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert 'name="pattern"' in response.text
    assert 'name="match_type"' in response.text
    # Color swatches rendered from color_pairs()
    assert 'value="emerald"' in response.text
    assert 'value="amber"' in response.text


def test_labels_create_redirects_and_refreshes_cache() -> None:
    create_mock = AsyncMock()
    refresh_mock = AsyncMock()
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.label_crud.create_label", new=create_mock),
        patch("bgpeek.ui.admin.refresh_label_cache", new=refresh_mock),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/community-labels",
            headers={"X-API-Key": "any"},
            data={
                "pattern": "65000:100",
                "match_type": "exact",
                "label": "Customer traffic",
                "color": "emerald",
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/community-labels"
    create_mock.assert_awaited_once()
    refresh_mock.assert_awaited_once()
    payload = create_mock.await_args.args[1]
    assert payload.pattern == "65000:100"
    assert payload.color == "emerald"


def test_labels_create_no_color_ok() -> None:
    create_mock = AsyncMock()
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.label_crud.create_label", new=create_mock),
        patch("bgpeek.ui.admin.refresh_label_cache", new=AsyncMock()),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/community-labels",
            headers={"X-API-Key": "any"},
            data={
                "pattern": "65000:",
                "match_type": "prefix",
                "label": "Customer range",
                "color": "",
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    payload = create_mock.await_args.args[1]
    assert payload.color is None


def test_labels_create_invalid_color_rerenders() -> None:
    create_mock = AsyncMock()
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.label_crud.create_label", new=create_mock),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/community-labels",
            headers={"X-API-Key": "any"},
            data={
                "pattern": "65000:100",
                "match_type": "exact",
                "label": "Test",
                "color": "hotpink",  # not in ALLOWED_COLORS
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "invalid color" in response.text
    create_mock.assert_not_awaited()


def test_labels_edit_form_prefilled() -> None:
    from bgpeek.models.community_label import CommunityLabel

    label = CommunityLabel.model_validate(_LABEL_ROW)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.label_crud.get_label",
            new=AsyncMock(return_value=label),
        ),
    ):
        client = TestClient(app)
        response = client.get(
            "/admin/community-labels/1/edit",
            headers={"X-API-Key": "any"},
        )

    assert response.status_code == 200
    assert 'value="65000:100"' in response.text
    assert 'action="/admin/community-labels/1"' in response.text


def test_labels_delete_redirects() -> None:
    delete_mock = AsyncMock(return_value=True)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.label_crud.delete_label", new=delete_mock),
        patch("bgpeek.ui.admin.refresh_label_cache", new=AsyncMock()),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/community-labels/1/delete",
            headers={"X-API-Key": "any"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    delete_mock.assert_awaited_once()


# ---------------------------------------------------------------------------
# Admin webhooks CRUD
# ---------------------------------------------------------------------------


_WEBHOOK_ROW = {
    "id": 1,
    "name": "slack-noc",
    "url": "https://hooks.slack.com/services/T0/B0/xxx",
    "secret": "shhh",
    "events": ["device_create", "login"],
    "enabled": True,
    "created_at": _NOW,
    "updated_at": _NOW,
}


def test_webhooks_list_renders() -> None:
    from bgpeek.models.webhook import Webhook

    hook = Webhook.model_validate(_WEBHOOK_ROW)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.webhook_crud.list_webhooks",
            new=AsyncMock(return_value=[hook]),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/webhooks", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert "slack-noc" in response.text
    assert "hooks.slack.com" in response.text
    # Secret must NOT be echoed into list markup
    assert "shhh" not in response.text
    assert "/admin/webhooks/1/edit" in response.text


def test_webhooks_new_form_renders_event_checkboxes() -> None:
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
    ):
        client = TestClient(app)
        response = client.get("/admin/webhooks/new", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert 'name="events" value="query"' in response.text
    assert 'name="events" value="device_create"' in response.text
    assert 'name="events" value="login"' in response.text


def test_webhooks_create_requires_at_least_one_event() -> None:
    create_mock = AsyncMock()
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.webhook_crud.create_webhook", new=create_mock),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/webhooks",
            headers={"X-API-Key": "any"},
            data={
                "name": "test",
                "url": "https://example.com/hook",
                "enabled": "1",
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    assert "select at least one event" in response.text
    create_mock.assert_not_awaited()


def test_webhooks_create_redirects() -> None:
    create_mock = AsyncMock()
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.webhook_crud.create_webhook", new=create_mock),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/webhooks",
            headers={"X-API-Key": "any"},
            data={
                "name": "slack-noc",
                "url": "https://example.com/hook",
                "events": ["device_create", "login"],
                "secret": "abc123",
                "enabled": "1",
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin/webhooks"
    create_mock.assert_awaited_once()
    payload = create_mock.await_args.args[1]
    assert payload.name == "slack-noc"
    assert [e.value for e in payload.events] == ["device_create", "login"]
    assert payload.secret == "abc123"  # noqa: S105


def test_webhooks_create_rejects_private_url() -> None:
    create_mock = AsyncMock()
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.webhook_crud.create_webhook", new=create_mock),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/webhooks",
            headers={"X-API-Key": "any"},
            data={
                "name": "internal",
                "url": "http://10.0.0.1/hook",  # private IP — SSRF blocked
                "events": ["login"],
            },
            follow_redirects=False,
        )

    assert response.status_code == 400
    create_mock.assert_not_awaited()


def test_webhooks_edit_form_hides_secret() -> None:
    from bgpeek.models.webhook import Webhook

    hook = Webhook.model_validate(_WEBHOOK_ROW)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch(
            "bgpeek.ui.admin.webhook_crud.get_webhook",
            new=AsyncMock(return_value=hook),
        ),
    ):
        client = TestClient(app)
        response = client.get("/admin/webhooks/1/edit", headers={"X-API-Key": "any"})

    assert response.status_code == 200
    assert "shhh" not in response.text
    assert 'value="slack-noc"' in response.text
    # The existing events are pre-checked. Whitespace/attribute order in
    # rendered HTML is flexible, so check for the checkbox value and the
    # presence of a nearby `checked` attribute.
    import re

    for event_name in ("device_create", "login"):
        assert re.search(
            rf'value="{event_name}"[^>]*\s+checked\b',
            response.text,
        ), f"expected {event_name} checkbox to be pre-checked"


def test_webhooks_update_empty_secret_keeps_existing() -> None:
    from bgpeek.models.webhook import Webhook

    hook = Webhook.model_validate(_WEBHOOK_ROW)
    update_mock = AsyncMock(return_value=hook)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.webhook_crud.update_webhook", new=update_mock),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/webhooks/1",
            headers={"X-API-Key": "any"},
            data={
                "name": "slack-noc",
                "url": "https://example.com/hook",
                "events": ["login"],
                "enabled": "1",
                # secret intentionally omitted
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    update_mock.assert_awaited_once()
    payload = update_mock.await_args.args[2]
    assert "secret" not in payload.model_dump(exclude_unset=True)


def test_webhooks_delete_redirects() -> None:
    delete_mock = AsyncMock(return_value=True)
    with (
        patch(
            "bgpeek.core.auth.user_crud.get_user_by_api_key",
            new=AsyncMock(return_value=_ADMIN),
        ),
        patch("bgpeek.core.auth.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.get_pool", return_value=object()),
        patch("bgpeek.ui.admin.webhook_crud.delete_webhook", new=delete_mock),
    ):
        client = TestClient(app)
        response = client.post(
            "/admin/webhooks/1/delete",
            headers={"X-API-Key": "any"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    delete_mock.assert_awaited_once()
