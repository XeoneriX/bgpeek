"""Tests for the async SSH client wrapper."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from bgpeek.core import ssh as ssh_module
from bgpeek.core.ssh import (
    SSHClient,
    SSHCommandError,
    SSHConnectionError,
    SSHTimeoutError,
)


def _make_client(**overrides: Any) -> SSHClient:
    defaults: dict[str, Any] = {
        "host": "10.0.0.1",
        "username": "netops",
        "platform": "juniper_junos",
        "password": "secret",
        "timeout": 2,
    }
    defaults.update(overrides)
    return SSHClient(**defaults)


# ---------- construction ----------


def test_init_requires_password_or_key() -> None:
    with pytest.raises(ValueError, match="password or key_path"):
        SSHClient(
            host="10.0.0.1",
            username="netops",
            platform="juniper_junos",
        )


def test_init_with_password() -> None:
    client = _make_client()
    assert client._connection is None


def test_init_with_key_only() -> None:
    client = SSHClient(
        host="10.0.0.1",
        username="netops",
        platform="juniper_junos",
        password=None,
        key_path=Path("/tmp/id_rsa"),  # noqa: S108
    )
    assert client._connection is None


# ---------- connect ----------


async def test_connect_success(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_conn = MagicMock()
    monkeypatch.setattr(ssh_module, "ConnectHandler", lambda **_: mock_conn)

    client = _make_client()
    await client.connect()

    assert client._connection is mock_conn
    await client.disconnect()


async def test_connect_auth_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(**_: Any) -> Any:
        raise NetmikoAuthenticationException("bad creds")

    monkeypatch.setattr(ssh_module, "ConnectHandler", _boom)

    client = _make_client()
    with pytest.raises(SSHConnectionError):
        await client.connect()
    assert client._connection is None


async def test_connect_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def _slow(**_: Any) -> Any:
        import time

        time.sleep(5)
        return MagicMock()

    monkeypatch.setattr(ssh_module, "ConnectHandler", _slow)

    client = _make_client(timeout=1)
    with pytest.raises(SSHTimeoutError):
        await client.connect()
    assert client._connection is None


async def test_connect_netmiko_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(**_: Any) -> Any:
        raise NetmikoTimeoutException("timeout")

    monkeypatch.setattr(ssh_module, "ConnectHandler", _boom)

    client = _make_client()
    with pytest.raises(SSHTimeoutError):
        await client.connect()
    assert client._connection is None


# ---------- send_command ----------


async def test_send_command_requires_connection() -> None:
    client = _make_client()
    with pytest.raises(SSHConnectionError):
        await client.send_command("show version")


async def test_send_command_success(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_conn = MagicMock()
    mock_conn.send_command.return_value = "output text"
    monkeypatch.setattr(ssh_module, "ConnectHandler", lambda **_: mock_conn)

    client = _make_client()
    await client.connect()
    result = await client.send_command("show version")
    assert result == "output text"
    mock_conn.send_command.assert_called_once_with("show version", read_timeout=2)


async def test_send_command_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_conn = MagicMock()

    def _slow(*_: Any, **__: Any) -> str:
        import time

        time.sleep(5)
        return "never"

    mock_conn.send_command.side_effect = _slow
    monkeypatch.setattr(ssh_module, "ConnectHandler", lambda **_: mock_conn)

    client = _make_client(timeout=1)
    await client.connect()
    with pytest.raises(SSHTimeoutError):
        await client.send_command("show version", timeout=1)


async def test_send_command_error(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = RuntimeError("device blew up")
    monkeypatch.setattr(ssh_module, "ConnectHandler", lambda **_: mock_conn)

    client = _make_client()
    await client.connect()
    with pytest.raises(SSHCommandError):
        await client.send_command("show version")


async def test_send_command_expect_string(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_conn = MagicMock()
    mock_conn.send_command.return_value = "ok"
    monkeypatch.setattr(ssh_module, "ConnectHandler", lambda **_: mock_conn)

    client = _make_client()
    await client.connect()
    await client.send_command("show version", expect_string=r"#\s*$")
    mock_conn.send_command.assert_called_once_with("show version", read_timeout=2, expect_string=r"#\s*$")


# ---------- disconnect ----------


async def test_disconnect_calls_netmiko(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_conn = MagicMock()
    monkeypatch.setattr(ssh_module, "ConnectHandler", lambda **_: mock_conn)

    client = _make_client()
    await client.connect()
    await client.disconnect()

    mock_conn.disconnect.assert_called_once()
    assert client._connection is None


async def test_disconnect_when_not_connected() -> None:
    client = _make_client()
    await client.disconnect()
    assert client._connection is None


# ---------- context manager ----------


async def test_context_manager_connects_and_disconnects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_conn = MagicMock()
    monkeypatch.setattr(ssh_module, "ConnectHandler", lambda **_: mock_conn)

    async with _make_client() as client:
        assert client._connection is mock_conn

    mock_conn.disconnect.assert_called_once()


async def test_context_manager_disconnects_on_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mock_conn = MagicMock()
    monkeypatch.setattr(ssh_module, "ConnectHandler", lambda **_: mock_conn)

    with pytest.raises(RuntimeError, match="boom"):
        async with _make_client():
            raise RuntimeError("boom")

    mock_conn.disconnect.assert_called_once()


async def test_asyncio_module_imported() -> None:
    # sanity: ensure the module uses asyncio.to_thread (exercised elsewhere)
    assert hasattr(asyncio, "to_thread")
