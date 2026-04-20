"""Tests for bgpeek.core.logging.configure_logging."""

from __future__ import annotations

import io
import json
import logging
from contextlib import redirect_stdout

import pytest
import structlog

from bgpeek.config import settings
from bgpeek.core.logging import configure_logging


def _capture_log(event: str = "hello", **kw: object) -> str:
    """Emit a single info event and return stdout verbatim."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        structlog.get_logger().info(event, **kw)
    return buf.getvalue()


def test_json_format_emits_valid_ndjson(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "log_format", "json")
    monkeypatch.setattr(settings, "log_level", "info")
    configure_logging()

    output = _capture_log("hello", device="rt1", count=42).strip()

    # One line → one valid JSON document.
    assert "\n" not in output
    payload = json.loads(output)
    assert payload["event"] == "hello"
    assert payload["device"] == "rt1"
    assert payload["count"] == 42
    assert payload["level"] == "info"
    assert "timestamp" in payload


def test_logfmt_format_emits_key_value_pairs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "log_format", "logfmt")
    monkeypatch.setattr(settings, "log_level", "info")
    configure_logging()

    output = _capture_log("hello", device="rt1").strip()

    assert "event=hello" in output
    assert "device=rt1" in output
    assert "level=info" in output


def test_console_format_is_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "log_format", "console")
    monkeypatch.setattr(settings, "log_level", "info")
    configure_logging()

    output = _capture_log("hello", device="rt1")
    # structlog ConsoleRenderer writes the event keyword somewhere on the line;
    # don't pin the exact layout since it's cosmetic, but both pieces must
    # appear in the same output block.
    assert "hello" in output
    assert "device" in output
    assert "rt1" in output


def test_invalid_format_falls_back_to_console(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "log_format", "junk")
    monkeypatch.setattr(settings, "log_level", "info")
    configure_logging()

    output = _capture_log("hello")
    # Console output is not valid JSON; confirm fallback took effect.
    with pytest.raises(json.JSONDecodeError):
        json.loads(output)


def test_level_filter_drops_debug_at_info(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "log_format", "json")
    monkeypatch.setattr(settings, "log_level", "info")
    configure_logging()

    buf = io.StringIO()
    with redirect_stdout(buf):
        structlog.get_logger().debug("suppressed")
    assert buf.getvalue() == ""


def test_level_filter_passes_through_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "log_format", "json")
    monkeypatch.setattr(settings, "log_level", "warning")
    configure_logging()

    # info suppressed, warning passes
    info_out = _capture_log("ignored")
    assert info_out == ""

    buf = io.StringIO()
    with redirect_stdout(buf):
        structlog.get_logger().warning("seen", x=1)
    payload = json.loads(buf.getvalue().strip())
    assert payload["event"] == "seen"
    assert payload["level"] == "warning"


def test_unknown_level_defaults_to_info(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "log_format", "json")
    monkeypatch.setattr(settings, "log_level", "nonsense")
    configure_logging()

    output = _capture_log("hello").strip()
    payload = json.loads(output)
    assert payload["level"] == "info"


def test_configure_logging_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Calling twice must not crash or corrupt the pipeline."""
    monkeypatch.setattr(settings, "log_format", "json")
    monkeypatch.setattr(settings, "log_level", "info")
    configure_logging()
    configure_logging()
    output = _capture_log("hello").strip()
    json.loads(output)  # still valid


# ---------------------------------------------------------------------------
# Restore a predictable default after this module so downstream tests that
# rely on structlog defaults aren't left with the filtered config from the
# last test case.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_default_level() -> None:
    yield
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.NOTSET),
    )
