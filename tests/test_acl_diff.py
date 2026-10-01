from ipaddress import IPv4Network

import pytest

from acl_diff import Action, Protocol, Rule, analyze_diff
from acl_diff.policy import allow_boxes, count_packets

NET = IPv4Network
FULL = NET("0.0.0.0/0")


def test_reorder_tcp_rules_gains_exactly_four_allows():
    deny = Rule(Action.DENY, Protocol.TCP, NET("10.0.0.0/31"), NET("192.0.2.0/30"), (80, 81))
    allow = Rule(Action.ALLOW, Protocol.TCP, NET("10.0.0.0/30"), NET("192.0.2.0/31"), (81, 82))
    result = analyze_diff([deny, allow], [allow, deny])
    assert result.new_allows == 4
    assert result.new_denies == 0
    assert result.new_allow_samples
    assert not result.new_deny_samples
    for packet in result.new_allow_samples:
        assert packet.protocol is Protocol.TCP
        assert NET("10.0.0.0/30").__contains__(packet.source)
        assert NET("192.0.2.0/31").__contains__(packet.destination)
        assert 81 <= packet.port <= 82


def test_empty_to_any_allow_counts_whole_space():
    any_all = Rule(Action.ALLOW, Protocol.ANY, FULL, FULL)
    result = analyze_diff([], [any_all])
    assert result.new_allows == 2**81 + 2**64
    assert result.new_denies == 0


def test_any_split_into_three_rules_is_equivalent():
    any_all = Rule(Action.ALLOW, Protocol.ANY, FULL, FULL)
    split = [
        Rule(Action.ALLOW, Protocol.TCP, FULL, FULL, (0, 65535)),
        Rule(Action.ALLOW, Protocol.UDP, FULL, FULL, (0, 65535)),
        Rule(Action.ALLOW, Protocol.ICMP, FULL, FULL),
    ]
    assert analyze_diff([any_all], split).new_allows == 0
    assert analyze_diff([any_all], split).new_denies == 0
    assert analyze_diff(split, [any_all]).new_allows == 0
    assert analyze_diff(split, [any_all]).new_denies == 0


def test_shadowed_rule_change_produces_no_diff():
    base = [Rule(Action.ALLOW, Protocol.ANY, FULL, FULL)]
    shadowed_a = base + [Rule(Action.DENY, Protocol.TCP, NET("10.0.0.0/8"), FULL, (0, 65535))]
    shadowed_b = base + [Rule(Action.DENY, Protocol.UDP, NET("10.0.0.0/8"), FULL, (53, 53))]
    result = analyze_diff(shadowed_a, shadowed_b)
    assert result.new_allows == 0
    assert result.new_denies == 0


def test_new_denies_and_samples():
    old = [Rule(Action.ALLOW, Protocol.UDP, NET("10.0.0.0/24"), NET("192.0.2.0/24"), (53, 53))]
    result = analyze_diff(old, [])
    assert result.new_allows == 0
    assert result.new_denies == 256 * 256
    assert result.new_deny_samples
    sample = result.new_deny_samples[0]
    assert sample.protocol is Protocol.UDP
    assert sample.port == 53


def test_icmp_counts_one_packet_per_address_pair():
    old = [Rule(Action.ALLOW, Protocol.ICMP, NET("10.0.0.0/24"), NET("192.0.2.0/24"))]
    result = analyze_diff(old, [])
    assert result.new_denies == 256 * 256
    assert result.new_deny_samples[0].port is None


def test_partial_overlap_counts_exactly():
    old = [Rule(Action.ALLOW, Protocol.TCP, NET("10.0.0.0/24"), FULL, (80, 80))]
    new = [Rule(Action.ALLOW, Protocol.TCP, NET("10.0.0.128/25"), FULL, (80, 80))]
    result = analyze_diff(old, new)
    assert result.new_allows == 0
    assert result.new_denies == 128 * 2**32


def test_identical_policies_have_no_diff():
    rules = [
        Rule(Action.DENY, Protocol.TCP, NET("10.0.0.0/8"), FULL, (22, 22)),
        Rule(Action.ALLOW, Protocol.ANY, FULL, FULL),
    ]
    result = analyze_diff(rules, rules)
    assert result.new_allows == 0
    assert result.new_denies == 0


def test_default_deny_for_unmatched():
    assert count_packets(allow_boxes([])) == 0


def test_rule_validation():
    with pytest.raises(ValueError):
        Rule(Action.ALLOW, Protocol.TCP, FULL, FULL)
    with pytest.raises(ValueError):
        Rule(Action.ALLOW, Protocol.ICMP, FULL, FULL, (1, 2))
    with pytest.raises(ValueError):
        Rule(Action.ALLOW, Protocol.UDP, FULL, FULL, (100, 1))
    with pytest.raises(ValueError):
        Rule(Action.ALLOW, Protocol.TCP, FULL, FULL, (0, 70000))
