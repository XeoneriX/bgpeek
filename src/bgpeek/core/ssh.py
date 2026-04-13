"""Async SSH client wrapper around netmiko for network device access."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import TracebackType
from typing import Any

import structlog
from netmiko import ConnectHandler  # type: ignore[import-untyped]

from bgpeek.config import settings
from netmiko.base_connection import BaseConnection  # type: ignore[import-untyped]
from netmiko.exceptions import (  # type: ignore[import-untyped]
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

logger = structlog.get_logger(__name__)


class SSHError(Exception):
    """Base exception for SSH-related failures."""


class SSHConnectionError(SSHError):
    """Failed to establish or maintain SSH connection."""


class SSHCommandError(SSHError):
    """A command executed but the device returned an error."""


class SSHTimeoutError(SSHError):
    """Connection or command exceeded its timeout."""


class SSHClient:
    """Async wrapper around netmiko for talking to network devices."""

    def __init__(
        self,
        *,
        host: str,
        username: str,
        platform: str,
        port: int = 22,
        password: str | None = None,
        key_path: Path | None = None,
        timeout: int = 30,
        global_delay_factor: float = 1.0,
    ) -> None:
        if password is None and key_path is None:
            raise ValueError("Either password or key_path must be provided")

        self._host = host
        self._username = username
        self._platform = platform
        self._port = port
        self._password = password
        self._key_path = key_path
        self._timeout = timeout
        self._global_delay_factor = global_delay_factor
        self._connection: BaseConnection | None = None

    def _build_netmiko_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "device_type": self._platform,
            "host": self._host,
            "username": self._username,
            "port": self._port,
            "timeout": self._timeout,
            "global_delay_factor": self._global_delay_factor,
        }
        if self._password is not None:
            kwargs["password"] = self._password
        if self._key_path is not None:
            kwargs["use_keys"] = True
            kwargs["key_file"] = str(self._key_path)
        kwargs["ssh_config_file"] = None
        if settings.ssh_known_hosts_policy != "strict":
            kwargs["ssh_strict"] = False
        return kwargs

    async def connect(self) -> None:
        """Open the SSH connection. Raises SSHConnectionError or SSHTimeoutError."""
        kwargs = self._build_netmiko_kwargs()
        try:
            connection = await asyncio.wait_for(
                asyncio.to_thread(ConnectHandler, **kwargs),
                timeout=self._timeout,
            )
        except TimeoutError as exc:
            logger.warning(
                "ssh connect timeout",
                host=self._host,
                port=self._port,
                platform=self._platform,
            )
            raise SSHTimeoutError(
                f"Connection to {self._host}:{self._port} timed out after {self._timeout}s"
            ) from exc
        except NetmikoTimeoutException as exc:
            logger.warning(
                "ssh connect timeout",
                host=self._host,
                port=self._port,
                platform=self._platform,
            )
            raise SSHTimeoutError(str(exc)) from exc
        except NetmikoAuthenticationException as exc:
            logger.warning(
                "ssh authentication failed",
                host=self._host,
                port=self._port,
                username=self._username,
            )
            raise SSHConnectionError(
                f"Authentication failed for {self._username}@{self._host}"
            ) from exc
        except Exception as exc:
            logger.warning(
                "ssh connect failed",
                host=self._host,
                port=self._port,
                error=str(exc),
            )
            raise SSHConnectionError(str(exc)) from exc

        self._connection = connection
        logger.info(
            "ssh connection opened",
            host=self._host,
            port=self._port,
            platform=self._platform,
        )

    async def send_command(
        self,
        command: str,
        *,
        timeout: int | None = None,  # noqa: ASYNC109
        expect_string: str | None = None,
    ) -> str:
        """Send a command and return raw output."""
        if self._connection is None:
            raise SSHConnectionError("Not connected")

        effective_timeout = timeout if timeout is not None else self._timeout
        connection = self._connection

        logger.debug("ssh command sent", host=self._host, command=command)

        def _run() -> str:
            kwargs: dict[str, Any] = {"read_timeout": effective_timeout}
            if expect_string is not None:
                kwargs["expect_string"] = expect_string
            result = connection.send_command(command, **kwargs)
            if isinstance(result, str):
                return result
            return str(result)

        try:
            output = await asyncio.wait_for(
                asyncio.to_thread(_run),
                timeout=effective_timeout,
            )
        except TimeoutError as exc:
            logger.warning(
                "ssh command timeout",
                host=self._host,
                command=command,
                timeout=effective_timeout,
            )
            raise SSHTimeoutError(
                f"Command on {self._host} timed out after {effective_timeout}s"
            ) from exc
        except NetmikoTimeoutException as exc:
            logger.warning("ssh command timeout", host=self._host, command=command)
            raise SSHTimeoutError(str(exc)) from exc
        except Exception as exc:
            logger.warning(
                "ssh command failed",
                host=self._host,
                command=command,
                error=str(exc),
            )
            raise SSHCommandError(str(exc)) from exc

        return output

    async def disconnect(self) -> None:
        """Close the SSH connection. Idempotent."""
        if self._connection is None:
            return

        connection = self._connection
        self._connection = None
        try:
            await asyncio.to_thread(connection.disconnect)
        except Exception as exc:
            logger.warning("ssh disconnect error", host=self._host, error=str(exc))
            return

        logger.info("ssh connection closed", host=self._host, port=self._port)

    async def __aenter__(self) -> SSHClient:
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.disconnect()
