"""Shared model helpers.

Intentionally tiny — this file only exists to keep one strip-whitespace
helper out of every CRUD model. Pydantic's `model_config.str_strip_whitespace`
is global-across-a-model and would silently strip passwords/secrets too, so
we strip per-field via `Annotated[..., BeforeValidator(_strip)]` instead.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BeforeValidator


def _strip(value: Any) -> Any:  # noqa: ANN401 — forwards anything non-string untouched
    return value.strip() if isinstance(value, str) else value


# `TypeAlias` assignment (not PEP 695 `type`) because Pydantic resolves
# `Annotated[...]` through the annotation; the runtime `TypeAliasType` wrapper
# that the `type` keyword produces would hide the `BeforeValidator` from
# Pydantic's metadata walk.
TrimmedStr = Annotated[str, BeforeValidator(_strip)]
"""A ``str`` field that is whitespace-stripped before any further validation.

Use for human-entered identifier fields (names, usernames, URLs, patterns)
where a leading/trailing space is always accidental. **Do not** use for
passwords, API keys, or secrets — those must be preserved verbatim.
"""

TrimmedOptStr = Annotated[str | None, BeforeValidator(_strip)]
"""Optional variant of :data:`TrimmedStr`. ``None`` passes through unchanged."""
