"""Parse raw BGP route output from routers into structured records."""

from __future__ import annotations

import re

import structlog

from bgpeek.models.query import BGPRoute

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Juniper JunOS
# ---------------------------------------------------------------------------

_JUNOS_PREFIX_RE = re.compile(r"^\s{0,4}\*?\s*([\d.]+/\d+|[\da-fA-F:]+/\d+)\s")
_JUNOS_NEXTHOP_RE = re.compile(r"Next hop:\s+(\S+)")
_JUNOS_ASPATH_RE = re.compile(r"AS path:\s+(.+?)(?:\s*$)")
_JUNOS_COMMUNITY_RE = re.compile(r"Communities:\s+(.+)")
_JUNOS_LOCALPREF_RE = re.compile(r"Localpref:\s+(\d+)")
_JUNOS_MED_RE = re.compile(r"MED:\s+(\d+)")


def _parse_junos(text: str) -> list[BGPRoute]:
    routes: list[BGPRoute] = []
    current_prefix: str | None = None
    current_nh: str | None = None
    current_aspath: str | None = None
    current_origin: str | None = None
    current_med: int | None = None
    current_lp: int | None = None
    current_comms: list[str] = []
    current_best = False
    in_entry = False

    def _has_data() -> bool:
        return any(
            v is not None
            for v in (current_nh, current_aspath, current_origin, current_med, current_lp)
        ) or bool(current_comms)

    def _flush() -> None:
        if current_prefix is not None and _has_data():
            routes.append(
                BGPRoute(
                    prefix=current_prefix,
                    next_hop=current_nh,
                    as_path=current_aspath,
                    origin=current_origin,
                    med=current_med,
                    local_pref=current_lp,
                    communities=list(current_comms),
                    best=current_best,
                )
            )

    for line in text.splitlines():
        prefix_m = _JUNOS_PREFIX_RE.match(line)
        if prefix_m:
            _flush()
            current_prefix = prefix_m.group(1)
            current_nh = None
            current_aspath = None
            current_origin = None
            current_med = None
            current_lp = None
            current_comms = []
            current_best = "*" in line.split(prefix_m.group(1))[0]
            in_entry = True
            continue

        # New path entry under same prefix (Junos shows "BGP    Preference:" for each path)
        if in_entry and re.match(r"\s+BGP\s+Preference:", line):
            had_data = _has_data()
            _flush()
            current_nh = None
            current_aspath = None
            current_origin = None
            current_med = None
            current_lp = None
            current_comms = []
            # After flushing a populated entry, reset best for subsequent paths;
            # keep best from the prefix line for the first (empty) path block.
            if had_data:
                current_best = False
            continue

        if not in_entry:
            continue

        m = _JUNOS_NEXTHOP_RE.search(line)
        if m:
            current_nh = m.group(1)
            continue

        m = _JUNOS_ASPATH_RE.search(line)
        if m:
            raw = m.group(1).strip()
            # Origin code is at end: I/E/?
            origin_map = {"I": "IGP", "E": "EGP", "?": "Incomplete"}
            parts = raw.split()
            if parts and parts[-1] in origin_map:
                current_origin = origin_map[parts[-1]]
                current_aspath = " ".join(parts[:-1]) if len(parts) > 1 else ""
            else:
                current_aspath = raw

        m = _JUNOS_COMMUNITY_RE.search(line)
        if m:
            current_comms = m.group(1).strip().split()
            continue

        m = _JUNOS_LOCALPREF_RE.search(line)
        if m:
            current_lp = int(m.group(1))
            continue

        m = _JUNOS_MED_RE.search(line)
        if m:
            current_med = int(m.group(1))
            continue

    _flush()
    return routes


# ---------------------------------------------------------------------------
# Cisco IOS / IOS-XE / IOS-XR and Arista EOS
# ---------------------------------------------------------------------------

_CISCO_ENTRY_RE = re.compile(r"BGP routing table entry for ([\d.]+/\d+|[\da-fA-F:]+/\d+)")
_CISCO_ORIGIN_RE = re.compile(r"Origin\s+(IGP|EGP|incomplete)", re.IGNORECASE)
_CISCO_METRIC_RE = re.compile(r"metric\s+(\d+)", re.IGNORECASE)
_CISCO_LOCALPREF_RE = re.compile(r"localpref\s+(\d+)", re.IGNORECASE)
_CISCO_COMMUNITY_RE = re.compile(r"Community:\s+(.+)")
_CISCO_BEST_RE = re.compile(r"\bbest\b", re.IGNORECASE)
# Next-hop line: an IP at the start of a line (with some indent)
_CISCO_NEXTHOP_RE = re.compile(r"^\s+([\d.]+|[\da-fA-F:]+)\s+from\s+", re.MULTILINE)
# AS path line: just ASNs on the line (possibly with leading whitespace)
_CISCO_ASPATH_LINE_RE = re.compile(r"^\s{2,}([\d\s]+)\s*$", re.MULTILINE)


def _parse_cisco(text: str) -> list[BGPRoute]:
    routes: list[BGPRoute] = []
    # Split into per-entry blocks
    entries = re.split(r"(?=BGP routing table entry for)", text)

    for entry in entries:
        entry = entry.strip()
        prefix_m = _CISCO_ENTRY_RE.search(entry)
        if not prefix_m:
            continue

        prefix = prefix_m.group(1)
        lines = entry.splitlines()

        # Find "Paths:" line to know where paths start
        paths_idx = -1
        for i, ln in enumerate(lines):
            if re.search(r"Paths:", ln):
                paths_idx = i
                break

        if paths_idx < 0:
            continue

        # Parse individual paths: a path block starts with an AS-path line (or
        # a next-hop line if the AS is local) and continues with attribute lines.
        path_blocks: list[list[str]] = []
        current_block: list[str] = []

        for ln in lines[paths_idx + 1 :]:
            stripped = ln.strip()
            if not stripped:
                continue
            # A new path block starts with a line that's either:
            # - An AS path (digits and spaces only)
            # - "Local" keyword
            # - An IP address followed by "from"
            is_aspath_line = (
                re.match(r"^\s{2}\d", ln) and "from" not in ln and "Origin" not in ln
            ) or re.match(r"^\s{2}Local\s*$", ln)
            if is_aspath_line:
                if current_block:
                    path_blocks.append(current_block)
                current_block = [ln]
            else:
                current_block.append(ln)

        if current_block:
            path_blocks.append(current_block)

        for block in path_blocks:
            block_text = "\n".join(block)
            nh: str | None = None
            aspath: str | None = None
            origin: str | None = None
            med: int | None = None
            lp: int | None = None
            comms: list[str] = []
            best = False

            # First line is typically the AS path
            first_stripped = block[0].strip()
            if re.match(r"^[\d\s]+$", first_stripped):
                aspath = " ".join(first_stripped.split())
            elif first_stripped == "Local":
                aspath = ""

            # Next-hop
            nh_m = _CISCO_NEXTHOP_RE.search(block_text)
            if nh_m:
                nh = nh_m.group(1)

            # Origin
            origin_m = _CISCO_ORIGIN_RE.search(block_text)
            if origin_m:
                raw_origin = origin_m.group(1)
                origin = {"igp": "IGP", "egp": "EGP", "incomplete": "Incomplete"}.get(
                    raw_origin.lower(), raw_origin
                )

            # Metric (MED)
            med_m = _CISCO_METRIC_RE.search(block_text)
            if med_m:
                med = int(med_m.group(1))

            # Local preference
            lp_m = _CISCO_LOCALPREF_RE.search(block_text)
            if lp_m:
                lp = int(lp_m.group(1))

            # Communities
            comm_m = _CISCO_COMMUNITY_RE.search(block_text)
            if comm_m:
                comms = comm_m.group(1).strip().split()

            # Best
            if _CISCO_BEST_RE.search(block_text):
                best = True

            routes.append(
                BGPRoute(
                    prefix=prefix,
                    next_hop=nh,
                    as_path=aspath,
                    origin=origin,
                    med=med,
                    local_pref=lp,
                    communities=comms,
                    best=best,
                )
            )

    return routes


# ---------------------------------------------------------------------------
# Huawei VRP
# ---------------------------------------------------------------------------

_HUAWEI_PREFIX_RE = re.compile(
    r"BGP routing table entry information of ([\d.]+/\d+|[\da-fA-F:]+/\d+)"
)
_HUAWEI_FROM_RE = re.compile(r"From:\s+(\S+)")
_HUAWEI_ASPATH_RE = re.compile(r"AS-path:?\s+([\d\s,]+?)(?:,\s*origin|\s*$)", re.IGNORECASE)
_HUAWEI_ORIGIN_RE = re.compile(r"origin:\s*(\S+)", re.IGNORECASE)
_HUAWEI_COMMUNITY_RE = re.compile(r"Community:\s+(.+)")
_HUAWEI_MED_RE = re.compile(r"MED:\s*(\d+)", re.IGNORECASE)
_HUAWEI_LOCALPREF_RE = re.compile(r"localpref:\s*(\d+)", re.IGNORECASE)
_HUAWEI_BEST_RE = re.compile(r"\bbest\b", re.IGNORECASE)


def _parse_huawei(text: str) -> list[BGPRoute]:
    routes: list[BGPRoute] = []
    # Split on each "BGP routing table entry information of" block
    entries = re.split(r"(?=BGP routing table entry information of)", text)

    for entry in entries:
        entry = entry.strip()
        prefix_m = _HUAWEI_PREFIX_RE.search(entry)
        if not prefix_m:
            continue

        prefix = prefix_m.group(1)

        # Split on "From:" to get individual paths
        from_blocks = re.split(r"(?=From:)", entry[prefix_m.end() :])

        for fb in from_blocks:
            fb = fb.strip()
            if not fb.startswith("From:"):
                continue

            nh: str | None = None
            aspath: str | None = None
            origin: str | None = None
            med: int | None = None
            lp: int | None = None
            comms: list[str] = []
            best = False

            from_m = _HUAWEI_FROM_RE.search(fb)
            if from_m:
                nh = from_m.group(1)

            asp_m = _HUAWEI_ASPATH_RE.search(fb)
            if asp_m:
                raw = asp_m.group(1).strip().rstrip(",").strip()
                # Huawei may use commas or spaces
                aspath = " ".join(raw.replace(",", " ").split())

            origin_m = _HUAWEI_ORIGIN_RE.search(fb)
            if origin_m:
                raw_o = origin_m.group(1).strip().rstrip(",")
                origin = {"igp": "IGP", "egp": "EGP", "incomplete": "Incomplete"}.get(
                    raw_o.lower(), raw_o
                )

            med_m = _HUAWEI_MED_RE.search(fb)
            if med_m:
                med = int(med_m.group(1))

            lp_m = _HUAWEI_LOCALPREF_RE.search(fb)
            if lp_m:
                lp = int(lp_m.group(1))

            comm_m = _HUAWEI_COMMUNITY_RE.search(fb)
            if comm_m:
                comms = comm_m.group(1).strip().split()

            if _HUAWEI_BEST_RE.search(fb):
                best = True

            routes.append(
                BGPRoute(
                    prefix=prefix,
                    next_hop=nh,
                    as_path=aspath,
                    origin=origin,
                    med=med,
                    local_pref=lp,
                    communities=comms,
                    best=best,
                )
            )

    return routes


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_PLATFORM_PARSERS: dict[str, type[object] | None] = {}

_CISCO_PLATFORMS = frozenset({"cisco_ios", "cisco_xe", "cisco_xr", "arista_eos"})
_JUNOS_PLATFORMS = frozenset({"juniper_junos"})
_HUAWEI_PLATFORMS = frozenset({"huawei"})


def parse_bgp_output(text: str, *, platform: str) -> list[BGPRoute]:
    """Parse raw BGP route output into structured records.

    Best-effort: returns an empty list on any unexpected input or parse failure.
    """
    if not text or not text.strip():
        return []

    try:
        if platform in _JUNOS_PLATFORMS:
            return _parse_junos(text)
        if platform in _CISCO_PLATFORMS:
            return _parse_cisco(text)
        if platform in _HUAWEI_PLATFORMS:
            return _parse_huawei(text)

        log.warning("bgp_parser_unsupported_platform", platform=platform)
        return []

    except Exception:
        log.exception("bgp_parser_failed", platform=platform)
        return []
