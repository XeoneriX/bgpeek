"""Tests for bgpeek.core.bgp_parser."""

from __future__ import annotations

from bgpeek.core.bgp_parser import parse_bgp_output
from bgpeek.models.query import BGPRoute

JUNOS_SINGLE = """\
inet.0: 5 destinations, 8 routes (5 active, 0 holddown, 0 hidden)

* 8.8.8.0/24 (3 entries, 1 announced)
        BGP    Preference: 170/-101
                Next hop: 10.0.0.1 via ge-0/0/0.0
                AS path: 15169 I
                Communities: 65000:100 65000:200
                Localpref: 100
                MED: 0
"""

JUNOS_MULTIPATH = """\
* 8.8.8.0/24 (3 entries, 1 announced)
        BGP    Preference: 170/-101
                Next hop: 10.0.0.1 via ge-0/0/0.0
                AS path: 15169 I
                Communities: 65000:100
                Localpref: 100
                MED: 0
        BGP    Preference: 170/-101
                Next hop: 10.0.0.2 via ge-0/0/1.0
                AS path: 3356 15169 I
                Communities: 65000:200
                Localpref: 90
                MED: 10
"""

CISCO_SINGLE = """\
BGP routing table entry for 8.8.8.0/24, version 42
Paths: (1 available, best #1, table default)
  15169
    10.0.0.1 from 10.0.0.1 (192.168.1.1)
      Origin IGP, metric 0, localpref 100, valid, external, best
      Community: 65000:100 65000:200
"""

CISCO_MULTIPATH = """\
BGP routing table entry for 8.8.8.0/24, version 42
Paths: (2 available, best #1, table default)
  15169
    10.0.0.1 from 10.0.0.1 (192.168.1.1)
      Origin IGP, metric 0, localpref 100, valid, external, best
      Community: 65000:100 65000:200
  3356 15169
    10.0.0.2 from 10.0.0.2 (192.168.2.1)
      Origin IGP, metric 10, localpref 90, valid, external
      Community: 65000:300
"""

CISCO_XR_OUTPUT = """\
BGP routing table entry for 8.8.8.0/24
Paths: (1 available, best #1)
  15169
    10.0.0.1 from 10.0.0.1 (192.168.1.1)
      Origin IGP, metric 0, localpref 100, valid, external, best
      Community: 65000:100
"""

ARISTA_OUTPUT = """\
BGP routing table entry for 8.8.8.0/24
Paths: (1 available, best #1)
  15169
    10.0.0.1 from 10.0.0.1 (192.168.1.1)
      Origin IGP, metric 5, localpref 200, valid, external, best
      Community: 65000:500
"""

HUAWEI_SINGLE = """\
 BGP local router ID : 10.0.0.1
 Local AS number : 65000

 Paths:   1 available, 1 best
 BGP routing table entry information of 8.8.8.0/24:
 From: 10.0.0.2
 AS-path: 15169, origin: IGP
 Community: 65000:100
 MED: 0, localpref: 100, best
"""

HUAWEI_MULTIPATH = """\
 BGP local router ID : 10.0.0.1
 Local AS number : 65000

 Paths:   2 available, 1 best
 BGP routing table entry information of 8.8.8.0/24:
 From: 10.0.0.2
 AS-path: 15169, origin: IGP
 Community: 65000:100
 MED: 0, localpref: 100, best
 From: 10.0.0.3
 AS-path: 3356 15169, origin: IGP
 Community: 65000:200
 MED: 10, localpref: 90
"""


# ---- JunOS ----


def test_junos_single_route() -> None:
    routes = parse_bgp_output(JUNOS_SINGLE, platform="juniper_junos")
    assert len(routes) == 1
    r = routes[0]
    assert r.prefix == "8.8.8.0/24"
    assert r.next_hop == "10.0.0.1"
    assert r.as_path == "15169"
    assert r.origin == "IGP"
    assert r.med == 0
    assert r.local_pref == 100
    assert r.communities == ["65000:100", "65000:200"]
    assert r.best is True


def test_junos_multipath() -> None:
    routes = parse_bgp_output(JUNOS_MULTIPATH, platform="juniper_junos")
    assert len(routes) == 2
    assert routes[0].next_hop == "10.0.0.1"
    assert routes[0].as_path == "15169"
    assert routes[0].local_pref == 100
    assert routes[0].communities == ["65000:100"]
    assert routes[1].next_hop == "10.0.0.2"
    assert routes[1].as_path == "3356 15169"
    assert routes[1].local_pref == 90
    assert routes[1].med == 10
    assert routes[1].communities == ["65000:200"]


# ---- Cisco IOS/XE ----


def test_cisco_ios_single_route() -> None:
    routes = parse_bgp_output(CISCO_SINGLE, platform="cisco_ios")
    assert len(routes) == 1
    r = routes[0]
    assert r.prefix == "8.8.8.0/24"
    assert r.next_hop == "10.0.0.1"
    assert r.as_path == "15169"
    assert r.origin == "IGP"
    assert r.med == 0
    assert r.local_pref == 100
    assert r.communities == ["65000:100", "65000:200"]
    assert r.best is True


def test_cisco_ios_multipath() -> None:
    routes = parse_bgp_output(CISCO_MULTIPATH, platform="cisco_ios")
    assert len(routes) == 2
    assert routes[0].best is True
    assert routes[0].as_path == "15169"
    assert routes[0].communities == ["65000:100", "65000:200"]
    assert routes[1].best is False
    assert routes[1].as_path == "3356 15169"
    assert routes[1].next_hop == "10.0.0.2"
    assert routes[1].med == 10
    assert routes[1].local_pref == 90
    assert routes[1].communities == ["65000:300"]


def test_cisco_xe_uses_same_parser() -> None:
    routes = parse_bgp_output(CISCO_SINGLE, platform="cisco_xe")
    assert len(routes) == 1
    assert routes[0].prefix == "8.8.8.0/24"


# ---- 6WIND VSR ----


def test_sixwind_os_uses_same_parser_as_cisco_style_output() -> None:
    routes = parse_bgp_output(CISCO_SINGLE, platform="sixwind_os")
    assert len(routes) == 1
    assert routes[0].prefix == "8.8.8.0/24"


# ---- Cisco XR ----


def test_cisco_xr_single_route() -> None:
    routes = parse_bgp_output(CISCO_XR_OUTPUT, platform="cisco_xr")
    assert len(routes) == 1
    r = routes[0]
    assert r.prefix == "8.8.8.0/24"
    assert r.next_hop == "10.0.0.1"
    assert r.as_path == "15169"
    assert r.origin == "IGP"
    assert r.med == 0
    assert r.local_pref == 100
    assert r.communities == ["65000:100"]
    assert r.best is True


# ---- Arista EOS ----


def test_arista_eos_single_route() -> None:
    routes = parse_bgp_output(ARISTA_OUTPUT, platform="arista_eos")
    assert len(routes) == 1
    r = routes[0]
    assert r.prefix == "8.8.8.0/24"
    assert r.next_hop == "10.0.0.1"
    assert r.as_path == "15169"
    assert r.origin == "IGP"
    assert r.med == 5
    assert r.local_pref == 200
    assert r.communities == ["65000:500"]
    assert r.best is True


# ---- Huawei VRP ----


def test_huawei_single_route() -> None:
    routes = parse_bgp_output(HUAWEI_SINGLE, platform="huawei")
    assert len(routes) == 1
    r = routes[0]
    assert r.prefix == "8.8.8.0/24"
    assert r.next_hop == "10.0.0.2"
    assert r.as_path == "15169"
    assert r.origin == "IGP"
    assert r.med == 0
    assert r.local_pref == 100
    assert r.communities == ["65000:100"]
    assert r.best is True


def test_huawei_multipath() -> None:
    routes = parse_bgp_output(HUAWEI_MULTIPATH, platform="huawei")
    assert len(routes) == 2
    assert routes[0].next_hop == "10.0.0.2"
    assert routes[0].as_path == "15169"
    assert routes[0].best is True
    assert routes[1].next_hop == "10.0.0.3"
    assert routes[1].as_path == "3356 15169"
    assert routes[1].med == 10
    assert routes[1].local_pref == 90
    assert routes[1].best is False


# ---- Edge cases ----


def test_empty_input_returns_empty_list() -> None:
    assert parse_bgp_output("", platform="cisco_ios") == []
    assert parse_bgp_output("", platform="juniper_junos") == []
    assert parse_bgp_output("", platform="huawei") == []


def test_whitespace_only_returns_empty_list() -> None:
    assert parse_bgp_output("   \n\n  ", platform="cisco_ios") == []


def test_garbage_input_returns_empty_list() -> None:
    assert parse_bgp_output("random garbage text\nno bgp here", platform="cisco_ios") == []
    assert parse_bgp_output("random garbage text\nno bgp here", platform="juniper_junos") == []
    assert parse_bgp_output("random garbage text\nno bgp here", platform="huawei") == []


def test_unsupported_platform_returns_empty_list() -> None:
    assert parse_bgp_output(CISCO_SINGLE, platform="unknown_vendor") == []


def test_no_match_output_returns_empty_list() -> None:
    cisco_no_match = """\
% Network not in table
"""
    assert parse_bgp_output(cisco_no_match, platform="cisco_ios") == []


def test_best_route_flag_junos() -> None:
    routes = parse_bgp_output(JUNOS_SINGLE, platform="juniper_junos")
    assert routes[0].best is True


def test_best_route_flag_cisco() -> None:
    routes = parse_bgp_output(CISCO_MULTIPATH, platform="cisco_ios")
    assert routes[0].best is True
    assert routes[1].best is False


def test_communities_extracted_correctly() -> None:
    routes = parse_bgp_output(CISCO_SINGLE, platform="cisco_ios")
    assert routes[0].communities == ["65000:100", "65000:200"]


def test_as_path_extracted_correctly() -> None:
    routes = parse_bgp_output(CISCO_MULTIPATH, platform="cisco_ios")
    assert routes[1].as_path == "3356 15169"


def test_med_extracted_correctly() -> None:
    routes = parse_bgp_output(ARISTA_OUTPUT, platform="arista_eos")
    assert routes[0].med == 5


def test_localpref_extracted_correctly() -> None:
    routes = parse_bgp_output(ARISTA_OUTPUT, platform="arista_eos")
    assert routes[0].local_pref == 200


def test_junos_active_route_from_state() -> None:
    """Junos marks the active path with State: <Active …>; non-active
    paths use <NotBest …> or <Ext>. The parser should set active=True
    only for the path whose State line contains "Active"."""
    text = """\
8.8.8.0/24 (4 entries, 1 announced)
        *BGP    Preference: 170/-120
                Next hop: 10.0.0.1 via ae2.0
                State: <Active Ext>
                AS path: 15169 I
                Localpref: 119
         BGP    Preference: 170/-120
                Next hop: 10.0.0.2 via ae0.0
                State: <NotBest Int Ext>
                AS path: 15169 I
                Localpref: 119
         BGP    Preference: 170/-51
                Next hop: 10.0.0.3 via et-0/0/10.0
                State: <Ext>
                AS path: 31133 15169 I
                Localpref: 50
"""
    routes = parse_bgp_output(text, platform="juniper_junos")
    assert len(routes) == 3
    assert routes[0].active is True
    assert routes[0].best is True
    assert routes[1].active is False
    assert routes[1].best is False
    assert routes[2].active is False
    assert routes[2].best is False


def test_junos_age_and_med_from_combined_line() -> None:
    """Junos packs Age, Metric (MED) and Metric2 onto a single line. We
    must extract Age and Metric (= MED), and ignore Metric2 (IGP cost)."""
    text = """\
* 8.8.8.0/24 (1 entries, 1 announced)
        BGP    Preference: 170/-101
                Next hop: 10.0.0.1 via ge-0/0/0.0
                AS path: 15169 I
                Localpref: 100
                Age: 4d 10:03:27  Metric: 42   Metric2: 100000
"""
    routes = parse_bgp_output(text, platform="juniper_junos")
    assert len(routes) == 1
    assert routes[0].age == "4d 10:03:27"
    assert routes[0].med == 42
    assert not hasattr(routes[0], "metric2") or getattr(routes[0], "metric2", None) is None


def test_junos_med_keyword_wins_over_metric() -> None:
    """When both 'MED:' and 'Metric:' are present, the explicit MED
    keyword is the source of truth."""
    text = """\
* 1.1.1.0/24 (1 entries, 1 announced)
        BGP    Preference: 170/-101
                Next hop: 10.0.0.1 via ge-0/0/0.0
                AS path: 13335 I
                Localpref: 100
                MED: 7
                Age: 1d  Metric: 99   Metric2: 100000
"""
    routes = parse_bgp_output(text, platform="juniper_junos")
    assert len(routes) == 1
    assert routes[0].med == 7


def test_junos_as_path_with_originator_annotation() -> None:
    """Junos detail output may suffix the AS-path with annotations like
    (Originator), (Looped), (Aggregator ...). These must be stripped so
    the trailing I/E/? origin code is still detected."""
    text = """\
* 8.8.8.0/24 (3 entries, 1 announced)
        BGP    Preference: 170/-101
                Next hop: 10.10.0.13 via ge-0/0/0.0
                AS path: 15169 I (Originator)
                Communities: 65000:100
"""
    routes = parse_bgp_output(text, platform="juniper_junos")
    assert len(routes) == 1
    assert routes[0].as_path == "15169"
    assert routes[0].origin == "IGP"


def test_junos_as_path_with_multiple_annotations() -> None:
    text = """\
* 8.8.8.0/24 (1 entries, 1 announced)
        BGP    Preference: 170/-101
                Next hop: 10.0.0.1 via ge-0/0/0.0
                AS path: 3356 15169 ? (Originator) (Looped)
"""
    routes = parse_bgp_output(text, platform="juniper_junos")
    assert len(routes) == 1
    assert routes[0].as_path == "3356 15169"
    assert routes[0].origin == "Incomplete"


def test_bgp_route_model_defaults() -> None:
    r = BGPRoute(prefix="10.0.0.0/8")
    assert r.next_hop is None
    assert r.as_path is None
    assert r.origin is None
    assert r.med is None
    assert r.local_pref is None
    assert r.communities == []
    assert r.best is False
