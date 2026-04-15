"""Shared Jinja2Templates instance.

Centralising this avoids the trap of registering filters on one
Jinja2Templates() and rendering through another — each instance owns
its own ``Environment``, so filters/globals don't propagate.
"""

from __future__ import annotations

from fastapi.templating import Jinja2Templates

from bgpeek.config import settings
from bgpeek.core.community_labels import annotate as annotate_community
from bgpeek.core.time_utils import timeago

templates = Jinja2Templates(directory=str(settings.templates_dir))

templates.env.filters["timeago"] = timeago
templates.env.filters["annotate_community"] = annotate_community
