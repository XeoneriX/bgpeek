"""Tests for role-based output visibility (response_filter)."""
# ruff: noqa: C408 — dict() as readable kwargs-style factory is intentional

from __future__ import annotations

from unittest.mock import patch

import pytest

from bgpeek.core.response_filter import filter_response, should_hide_raw_output
from bgpeek.core.templates import templates
from bgpeek.models.query import BGPRoute, QueryResponse, QueryType


def _make_bgp_response(**overrides) -> QueryResponse:
    """Build a BGP QueryResponse with sensible defaults."""
    defaults = dict(
        device_name="rt1",
        query_type=QueryType.BGP_ROUTE,
        target="8.8.8.0/24",
        command="show ip bgp 8.8.8.0/24",
        raw_output="BGP raw output here",
        filtered_output="BGP filtered output here",
        runtime_ms=120,
        parsed_routes=[
            BGPRoute(
                prefix="8.8.8.0/24",
                next_hop="10.0.0.1",
                as_path="64500 13335",
                origin="IGP",
                med=100,
                local_pref=200,
                communities=["64500:100", "64500:200"],
                best=True,
            ),
        ],
    )
    defaults.update(overrides)
    return QueryResponse(**defaults)


def _make_ping_response(**overrides) -> QueryResponse:
    """Build a ping QueryResponse."""
    defaults = dict(
        device_name="rt1",
        query_type=QueryType.PING,
        target="8.8.8.8",
        command="ping 8.8.8.8 count 5",
        raw_output=(
            "PING 8.8.8.8 (8.8.8.8): 56 data bytes\n"
            "64 bytes from 8.8.8.8: icmp_seq=0 ttl=56 time=1.23 ms\n"
            "64 bytes from 8.8.8.8: icmp_seq=1 ttl=56 time=1.45 ms\n"
            "--- 8.8.8.8 ping statistics ---\n"
            "5 packets transmitted, 5 received, 0% packet loss\n"
            "round-trip min/avg/max = 1.23/1.34/1.45 ms"
        ),
        filtered_output=(
            "PING 8.8.8.8 (8.8.8.8): 56 data bytes\n"
            "64 bytes from 8.8.8.8: icmp_seq=0 ttl=56 time=1.23 ms\n"
            "64 bytes from 8.8.8.8: icmp_seq=1 ttl=56 time=1.45 ms\n"
            "--- 8.8.8.8 ping statistics ---\n"
            "5 packets transmitted, 5 received, 0% packet loss\n"
            "round-trip min/avg/max = 1.23/1.34/1.45 ms"
        ),
        runtime_ms=5000,
    )
    defaults.update(overrides)
    return QueryResponse(**defaults)


def _make_traceroute_response(**overrides) -> QueryResponse:
    """Build a traceroute QueryResponse."""
    defaults = dict(
        device_name="rt1",
        query_type=QueryType.TRACEROUTE,
        target="8.8.8.8",
        command="traceroute 8.8.8.8",
        raw_output=(
            "traceroute to 8.8.8.8\n"
            " 1  10.0.0.1  1.2 ms\n"
            " 2  172.16.0.1  2.3 ms\n"
            " 3  192.168.1.1  3.4 ms\n"
            " 4  100.64.0.1  4.5 ms\n"
            " 5  8.8.8.8  5.6 ms"
        ),
        filtered_output=(
            "traceroute to 8.8.8.8\n"
            " 1  10.0.0.1  1.2 ms\n"
            " 2  172.16.0.1  2.3 ms\n"
            " 3  192.168.1.1  3.4 ms\n"
            " 4  100.64.0.1  4.5 ms\n"
            " 5  8.8.8.8  5.6 ms"
        ),
        runtime_ms=8000,
    )
    defaults.update(overrides)
    return QueryResponse(**defaults)


# --- 1. Privileged roles see everything ---


@pytest.mark.parametrize("role", ["admin", "noc"])
def test_privileged_role_no_filtering(role: str) -> None:
    resp = _make_bgp_response()
    with patch("bgpeek.core.response_filter.settings") as mock_settings:
        mock_settings.public_output_level = "restricted"
        result = filter_response(resp, user_role=role)

    assert result.raw_output == resp.raw_output
    assert result.parsed_routes[0].communities == ["64500:100", "64500:200"]
    assert result.parsed_routes[0].local_pref == 200
    assert result.parsed_routes[0].med == 100


# --- 2. Restricted BGP strips communities, LP, MED ---


def test_restricted_bgp_strips_communities_lp_med() -> None:
    resp = _make_bgp_response()
    with patch("bgpeek.core.response_filter.settings") as mock_settings:
        mock_settings.public_output_level = "restricted"
        result = filter_response(resp, user_role="public")

    assert result.parsed_routes[0].communities == []
    assert result.parsed_routes[0].local_pref is None
    assert result.parsed_routes[0].med is None


# --- 3. Restricted BGP keeps core fields ---


def test_restricted_bgp_keeps_prefix_nexthop_aspath() -> None:
    resp = _make_bgp_response()
    with patch("bgpeek.core.response_filter.settings") as mock_settings:
        mock_settings.public_output_level = "restricted"
        result = filter_response(resp, user_role="public")

    route = result.parsed_routes[0]
    assert route.prefix == "8.8.8.0/24"
    assert route.next_hop == "10.0.0.1"
    assert route.as_path == "64500 13335"
    assert route.origin == "IGP"
    assert route.best is True


# --- 4. Restricted hides raw_output ---


def test_restricted_clears_bgp_filtered_output() -> None:
    """filtered_output (CLI text) carries LP/communities/MED in its raw form;
    restricted level must scrub it too, not just parsed_routes."""
    resp = _make_bgp_response(
        filtered_output=(
            "8.8.8.0/24 from 10.0.0.1\n"
            "    localpref 200, MED 100\n"
            "    Communities: 64500:100 64500:200"
        ),
    )
    with patch("bgpeek.core.response_filter.settings") as mock_settings:
        mock_settings.public_output_level = "restricted"
        result = filter_response(resp, user_role="public")

    assert result.filtered_output == ""


def test_restricted_hides_raw_output() -> None:
    resp = _make_bgp_response()
    with patch("bgpeek.core.response_filter.settings") as mock_settings:
        mock_settings.public_output_level = "restricted"
        result = filter_response(resp, user_role="public")

    assert result.raw_output == ""


# --- 5. Restricted ping: summary only ---


def test_restricted_ping_summary_only() -> None:
    resp = _make_ping_response()
    with patch("bgpeek.core.response_filter.settings") as mock_settings:
        mock_settings.public_output_level = "restricted"
        result = filter_response(resp, user_role="public")

    # Should keep only summary lines
    assert "packet loss" in result.filtered_output
    assert "round-trip" in result.filtered_output
    # Should not contain per-packet lines
    assert "icmp_seq=0" not in result.filtered_output
    assert "56 data bytes" not in result.filtered_output


# --- 6. Restricted traceroute masks RFC1918 ---


def test_restricted_traceroute_masks_rfc1918() -> None:
    resp = _make_traceroute_response()
    with patch("bgpeek.core.response_filter.settings") as mock_settings:
        mock_settings.public_output_level = "restricted"
        result = filter_response(resp, user_role="public")

    # RFC1918 and CGNAT addresses should be masked
    assert "10.0.0.1" not in result.filtered_output
    assert "172.16.0.1" not in result.filtered_output
    assert "192.168.1.1" not in result.filtered_output
    assert "100.64.0.1" not in result.filtered_output
    # Public IP should remain
    assert "8.8.8.8" in result.filtered_output
    # Masked placeholder should be present
    assert "[internal]" in result.filtered_output


# --- 7. Standard keeps all parsed fields ---


def test_standard_keeps_all_parsed_fields() -> None:
    resp = _make_bgp_response()
    with patch("bgpeek.core.response_filter.settings") as mock_settings:
        mock_settings.public_output_level = "standard"
        result = filter_response(resp, user_role="public")

    route = result.parsed_routes[0]
    assert route.communities == ["64500:100", "64500:200"]
    assert route.local_pref == 200
    assert route.med == 100


# --- 8. Standard hides raw_output ---


def test_standard_hides_raw_output() -> None:
    resp = _make_bgp_response()
    with patch("bgpeek.core.response_filter.settings") as mock_settings:
        mock_settings.public_output_level = "standard"
        result = filter_response(resp, user_role="public")

    assert result.raw_output == ""


# --- 9. Full level: no filtering even for public ---


def test_full_level_no_filtering() -> None:
    resp = _make_bgp_response()
    with patch("bgpeek.core.response_filter.settings") as mock_settings:
        mock_settings.public_output_level = "full"
        result = filter_response(resp, user_role="public")

    assert result.raw_output == resp.raw_output
    assert result.parsed_routes[0].communities == ["64500:100", "64500:200"]
    assert result.parsed_routes[0].local_pref == 200
    assert result.parsed_routes[0].med == 100


# --- 10. None role treated as public ---


def test_none_role_treated_as_public() -> None:
    resp = _make_bgp_response()
    with patch("bgpeek.core.response_filter.settings") as mock_settings:
        mock_settings.public_output_level = "restricted"
        result = filter_response(resp, user_role=None)

    # Should be filtered same as public
    assert result.raw_output == ""
    assert result.parsed_routes[0].communities == []
    assert result.parsed_routes[0].local_pref is None
    assert result.parsed_routes[0].med is None


# --- 11. should_hide_raw_output: hides 'Show raw' toggle at restricted level ---


@pytest.mark.parametrize("role", ["admin", "noc"])
def test_hide_raw_false_for_privileged_at_restricted(role: str) -> None:
    with patch("bgpeek.core.response_filter.settings") as mock_settings:
        mock_settings.public_output_level = "restricted"
        assert should_hide_raw_output(role) is False


@pytest.mark.parametrize("role", ["public", "guest", None])
def test_hide_raw_true_for_unprivileged_at_restricted(role: str | None) -> None:
    with patch("bgpeek.core.response_filter.settings") as mock_settings:
        mock_settings.public_output_level = "restricted"
        assert should_hide_raw_output(role) is True


@pytest.mark.parametrize("level", ["standard", "full"])
@pytest.mark.parametrize("role", ["public", "guest", None])
def test_hide_raw_false_when_not_restricted(role: str | None, level: str) -> None:
    with patch("bgpeek.core.response_filter.settings") as mock_settings:
        mock_settings.public_output_level = level
        assert should_hide_raw_output(role) is False


# --- 12. Rendered HTML: 'Show raw' block is suppressed when hide_raw is true ---


def _render_result_partial(*, hide_raw: bool) -> str:
    """Render partials/result.html with a BGP result whose filtered_output
    contains LP/communities/MED — the strings the restricted filter is meant
    to suppress from unprivileged viewers.
    """
    resp = _make_bgp_response(
        filtered_output=(
            "8.8.8.0/24 from 10.0.0.1\n"
            "    localpref 200, MED 100\n"
            "    Communities: 64500:100 64500:200"
        ),
    )
    template = templates.env.get_template("partials/result.html")
    return template.render(
        result=resp,
        hide_raw=hide_raw,
        t={
            "prefix": "Prefix",
            "next_hop": "Next Hop",
            "as_path": "AS Path",
            "origin": "Origin",
            "lp": "LP",
            "med": "MED",
            "age": "Age",
            "communities": "Communities",
            "rpki": "RPKI",
            "rpki_valid": "Valid",
            "rpki_invalid": "Invalid",
            "rpki_not_found": "Not found",
            "rpki_unknown": "Not verified",
            "show_raw": "Show detailed output",
            "share": "Share",
            "copied": "Copied!",
            "cached": "cached",
            "network_not_in_table": "Network not in table",
            "network_not_in_table_hint": "hint",
            "no_output": "No output",
            "dns_resolved_notice": "dns",
        },
    )


def test_template_hides_show_raw_block_when_hide_raw_true() -> None:
    html = _render_result_partial(hide_raw=True)
    # Toggle and the CLI text it contained must not appear.
    assert "Show detailed output" not in html
    assert "localpref" not in html
    assert "Communities:" not in html
    assert "MED 100" not in html


def test_template_shows_show_raw_block_when_hide_raw_false() -> None:
    html = _render_result_partial(hide_raw=False)
    assert "Show detailed output" in html
    assert "localpref" in html
    assert "Communities:" in html
