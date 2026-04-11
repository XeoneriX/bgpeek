"""Output filtering for router responses: drop more-specific prefixes."""

from __future__ import annotations

import re
from collections.abc import Iterable

from bgpeek.core.validators import (
    DEFAULT_MAX_PREFIX_V4,
    DEFAULT_MAX_PREFIX_V6,
    parse_target,
    prefix_too_specific,
)

_PREFIX_RE = re.compile(r"(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)/\d{1,3}")
_BLOCK_START_WINDOW = 20


def _is_too_specific(value: str, max_v4: int, max_v6: int) -> bool | None:
    """True if too specific, False if allowed, None if unparseable."""
    try:
        network = parse_target(value)
    except ValueError:
        return None
    return prefix_too_specific(network, max_v4=max_v4, max_v6=max_v6)


def filter_prefixes(
    prefixes: Iterable[str],
    *,
    max_v4: int = DEFAULT_MAX_PREFIX_V4,
    max_v6: int = DEFAULT_MAX_PREFIX_V6,
) -> list[str]:
    """Return only prefixes whose prefix length is within the allowed maximum."""
    result: list[str] = []
    for item in prefixes:
        verdict = _is_too_specific(item, max_v4, max_v6)
        if verdict is True:
            continue
        result.append(item)
    return result


def filter_route_text(
    text: str,
    *,
    max_v4: int = DEFAULT_MAX_PREFIX_V4,
    max_v6: int = DEFAULT_MAX_PREFIX_V6,
) -> str:
    """Filter plain-text router output line by line, dropping too-specific blocks."""
    if not text:
        return ""

    lines = text.split("\n")
    out: list[str] = []
    drop_block = False
    in_block = False

    for line in lines:
        match = _PREFIX_RE.search(line)
        starts_block = False
        if match is not None:
            stripped = line.lstrip()
            stripped_match = _PREFIX_RE.search(stripped)
            if (
                stripped_match is not None and stripped_match.start() == 0
            ) or match.start() < _BLOCK_START_WINDOW:
                starts_block = True

        if starts_block and match is not None:
            verdict = _is_too_specific(match.group(0), max_v4, max_v6)
            drop_block = verdict is True
            in_block = True
            if not drop_block:
                out.append(line)
        elif in_block:
            if not drop_block:
                out.append(line)
        else:
            out.append(line)

    return "\n".join(out)


def filter_route_records(
    records: Iterable[dict[str, object]],
    *,
    prefix_field: str = "prefix",
    max_v4: int = DEFAULT_MAX_PREFIX_V4,
    max_v6: int = DEFAULT_MAX_PREFIX_V6,
) -> list[dict[str, object]]:
    """Filter structured BGP route records, dropping those with too-specific prefixes."""
    result: list[dict[str, object]] = []
    for record in records:
        if prefix_field not in record:
            result.append(record)
            continue
        value = record[prefix_field]
        if not isinstance(value, str):
            result.append(record)
            continue
        verdict = _is_too_specific(value, max_v4, max_v6)
        if verdict is True:
            continue
        result.append(record)
    return result
