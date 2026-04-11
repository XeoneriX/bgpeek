"""Tests for bgpeek.core.output_filter."""

from __future__ import annotations

import pytest

from bgpeek.core.output_filter import (
    filter_prefixes,
    filter_route_records,
    filter_route_text,
)


def test_filter_prefixes_empty() -> None:
    assert filter_prefixes([]) == []


def test_filter_prefixes_all_pass() -> None:
    data = ["8.8.8.0/24", "185.66.84.0/22", "192.0.0.0/8"]
    assert filter_prefixes(data) == data


def test_filter_prefixes_mixed_v4() -> None:
    data = [
        "8.8.8.0/24",
        "8.8.8.128/25",
        "1.1.1.0/24",
        "1.1.1.128/26",
        "192.0.0.0/8",
    ]
    assert filter_prefixes(data) == ["8.8.8.0/24", "1.1.1.0/24", "192.0.0.0/8"]


def test_filter_prefixes_mixed_v6() -> None:
    data = ["2001:db8::/32", "2001:db8::/49", "2001:db8::/64"]
    assert filter_prefixes(data) == ["2001:db8::/32"]


def test_filter_prefixes_unparseable_passthrough() -> None:
    data = ["not-a-prefix", "", "8.8.8.0/24"]
    assert filter_prefixes(data) == ["not-a-prefix", "", "8.8.8.0/24"]


def test_filter_prefixes_custom_threshold() -> None:
    data = ["8.8.8.0/24", "10.0.0.0/16", "192.0.0.0/8"]
    assert filter_prefixes(data, max_v4=16) == ["10.0.0.0/16", "192.0.0.0/8"]


def test_filter_prefixes_default_route_allowed() -> None:
    assert filter_prefixes(["0.0.0.0/0"]) == ["0.0.0.0/0"]
    assert filter_prefixes(["::/0"]) == ["::/0"]


def test_filter_prefixes_bare_host_dropped() -> None:
    assert filter_prefixes(["8.8.8.8"]) == []


def test_filter_route_text_empty() -> None:
    assert filter_route_text("") == ""


def test_filter_route_text_single_allowed_no_cont() -> None:
    text = "8.8.8.0/24 via 10.0.0.1"
    assert filter_route_text(text) == text


def test_filter_route_text_single_dropped_no_cont() -> None:
    text = "8.8.8.128/25 via 10.0.0.1"
    assert filter_route_text(text) == ""


def test_filter_route_text_allowed_with_continuations() -> None:
    text = "\n".join(
        [
            "8.8.8.0/24 via 10.0.0.1",
            "  Next-hop: 10.0.0.1",
            "  AS-path: 15169",
        ]
    )
    assert filter_route_text(text) == text


def test_filter_route_text_dropped_with_continuations() -> None:
    text = "\n".join(
        [
            "8.8.8.128/25 via 10.0.0.1",
            "  Next-hop: 10.0.0.1",
            "  AS-path: 15169",
        ]
    )
    assert filter_route_text(text) == ""


def test_filter_route_text_mixed() -> None:
    lines = [
        "185.66.84.0/22 via 10.0.0.1",
        "  Next-hop: 10.0.0.1",
        "185.66.84.128/25 via 10.0.0.2",
        "  Next-hop: 10.0.0.2",
        "1.1.1.0/24 via 10.0.0.3",
    ]
    expected = "\n".join(
        [
            "185.66.84.0/22 via 10.0.0.1",
            "  Next-hop: 10.0.0.1",
            "1.1.1.0/24 via 10.0.0.3",
        ]
    )
    assert filter_route_text("\n".join(lines)) == expected


def test_filter_route_text_no_prefix_unchanged() -> None:
    text = "Routing table\n  some header\n  no prefixes here"
    assert filter_route_text(text) == text


def test_filter_route_text_v6_block() -> None:
    text = "\n".join(
        [
            "2001:db8::/49 via fe80::1",
            "  Next-hop: fe80::1",
            "2001:4860::/32 via fe80::2",
            "  Next-hop: fe80::2",
        ]
    )
    expected = "\n".join(
        [
            "2001:4860::/32 via fe80::2",
            "  Next-hop: fe80::2",
        ]
    )
    assert filter_route_text(text) == expected


def test_filter_route_records_empty() -> None:
    assert filter_route_records([]) == []


def test_filter_route_records_all_pass() -> None:
    data: list[dict[str, object]] = [
        {"prefix": "8.8.8.0/24", "nh": "10.0.0.1"},
        {"prefix": "185.66.84.0/22", "nh": "10.0.0.2"},
    ]
    assert filter_route_records(data) == data


def test_filter_route_records_mixed() -> None:
    data: list[dict[str, object]] = [
        {"prefix": "8.8.8.0/24"},
        {"prefix": "8.8.8.128/25"},
        {"prefix": "1.1.1.0/26"},
        {"prefix": "2001:db8::/48"},
        {"prefix": "2001:db8::/64"},
    ]
    result = filter_route_records(data)
    assert result == [
        {"prefix": "8.8.8.0/24"},
        {"prefix": "2001:db8::/48"},
    ]


def test_filter_route_records_missing_field_kept() -> None:
    data: list[dict[str, object]] = [
        {"nh": "10.0.0.1"},
        {"prefix": "8.8.8.128/25"},
    ]
    assert filter_route_records(data) == [{"nh": "10.0.0.1"}]


def test_filter_route_records_unparseable_kept() -> None:
    data: list[dict[str, object]] = [
        {"prefix": "not-a-prefix"},
        {"prefix": ""},
        {"prefix": 12345},
    ]
    assert filter_route_records(data) == data


def test_filter_route_records_custom_field() -> None:
    data: list[dict[str, object]] = [
        {"cidr": "8.8.8.0/24"},
        {"cidr": "8.8.8.128/25"},
    ]
    assert filter_route_records(data, prefix_field="cidr") == [{"cidr": "8.8.8.0/24"}]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.0/24", True),
        ("8.8.8.0/25", False),
        ("2001:db8::/48", True),
        ("2001:db8::/49", False),
    ],
)
def test_filter_prefixes_parametrized(value: str, expected: bool) -> None:
    result = filter_prefixes([value])
    assert (value in result) is expected
