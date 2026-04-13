"""Role-based output visibility: filter response fields by user role."""

from __future__ import annotations

import re

from bgpeek.config import settings
from bgpeek.models.query import BGPRoute, QueryResponse, QueryType
from bgpeek.models.user import UserRole

# RFC1918 + RFC6598 (CGNAT) patterns for masking internal IPs
_RFC1918_RE = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|100\.(?:6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\.\d{1,3}\.\d{1,3}"
    r")\b"
)

_PRIVILEGED_ROLES = frozenset({UserRole.ADMIN, UserRole.NOC})


def _is_privileged(user_role: str | None) -> bool:
    if user_role is None:
        return False
    try:
        return UserRole(user_role) in _PRIVILEGED_ROLES
    except ValueError:
        return False


def filter_response(response: QueryResponse, user_role: str | None) -> QueryResponse:
    """Return a filtered copy of the response based on the user's role.

    NOC/admin users always see full output.
    Public users see filtered output based on settings.public_output_level.
    """
    if _is_privileged(user_role):
        return response

    level = settings.public_output_level
    if level == "full":
        return response

    # Work on a copy
    data = response.model_dump()

    if response.query_type == QueryType.BGP_ROUTE:
        data = _filter_bgp(data, level)
    elif response.query_type == QueryType.PING:
        data = _filter_ping(data, level)
    elif response.query_type == QueryType.TRACEROUTE:
        data = _filter_traceroute(data, level)

    # Standard and restricted: hide raw output
    if level in ("restricted", "standard"):
        data["raw_output"] = ""

    return QueryResponse.model_validate(data)


def _filter_bgp(data: dict, level: str) -> dict:
    """Filter BGP response fields."""
    if level == "restricted":
        # Strip communities, LP, MED from parsed routes
        filtered_routes = []
        for route in data.get("parsed_routes", []):
            route = dict(route)  # copy
            route["communities"] = []
            route["local_pref"] = None
            route["med"] = None
            filtered_routes.append(route)
        data["parsed_routes"] = filtered_routes
    # standard: keep all parsed fields
    return data


def _filter_ping(data: dict, level: str) -> dict:
    """Filter ping output to summary only for restricted level."""
    if level == "restricted":
        output = data.get("filtered_output", "")
        summary = _extract_ping_summary(output)
        data["filtered_output"] = summary
    return data


def _extract_ping_summary(output: str) -> str:
    """Extract the summary lines from ping output (packet loss + RTT stats)."""
    lines = output.strip().split("\n")
    summary_lines = []
    for line in lines:
        lower = line.lower()
        # Match summary lines across vendors
        if any(kw in lower for kw in [
            "packet loss", "packets transmitted", "received",
            "min/avg/max", "round-trip", "rtt",
            # Huawei
            "packet(s) transmitted", "packet(s) received",
        ]):
            summary_lines.append(line)
    return "\n".join(summary_lines) if summary_lines else output


def _filter_traceroute(data: dict, level: str) -> dict:
    """Mask RFC1918/CGNAT addresses in traceroute output."""
    if level == "restricted":
        output = data.get("filtered_output", "")
        data["filtered_output"] = _RFC1918_RE.sub("[internal]", output)
    return data
