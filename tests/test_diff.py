import ipaddress

from terramesh import (
    Action,
    PortRange,
    Protocol,
    Rule,
    diff_policies,
    evaluate_allow_regions,
)


def net(value):
    return ipaddress.IPv4Network(value)


def test_reorder_tcp_rules_produces_exactly_four_newly_allowed():
    deny = Rule(
        protocol=Protocol.TCP,
        source=net("10.0.0.0/31"),
        destination=net("192.0.2.0/30"),
        action=Action.DENY,
        ports=PortRange(80, 81),
    )
    allow = Rule(
        protocol=Protocol.TCP,
        source=net("10.0.0.0/30"),
        destination=net("192.0.2.0/31"),
        action=Action.ALLOW,
        ports=PortRange(81, 82),
    )
    result = diff_policies([deny, allow], [allow, deny])
    assert result.newly_allowed.count == 4
    assert result.newly_denied.count == 0
    assert result.newly_allowed.examples
    for packet in result.newly_allowed.examples:
        assert packet.protocol is Protocol.TCP
        assert packet.source in net("10.0.0.0/31")
        assert packet.destination in net("192.0.2.0/31")
        assert packet.port == 81


def test_empty_to_any_allow_counts_whole_ipv4_space():
    any_allow = Rule(
        protocol=Protocol.ANY,
        source=net("0.0.0.0/0"),
        destination=net("0.0.0.0/0"),
        action=Action.ALLOW,
    )
    result = diff_policies([], [any_allow])
    assert result.newly_allowed.count == 2**81 + 2**64
    assert result.newly_denied.count == 0


def test_any_split_into_tcp_udp_icmp_is_equivalent():
    any_allow = Rule(
        protocol=Protocol.ANY,
        source=net("0.0.0.0/0"),
        destination=net("0.0.0.0/0"),
        action=Action.ALLOW,
    )
    split = [
        Rule(
            protocol=Protocol.TCP,
            source=net("0.0.0.0/0"),
            destination=net("0.0.0.0/0"),
            action=Action.ALLOW,
            ports=PortRange(0, 65535),
        ),
        Rule(
            protocol=Protocol.UDP,
            source=net("0.0.0.0/0"),
            destination=net("0.0.0.0/0"),
            action=Action.ALLOW,
            ports=PortRange(0, 65535),
        ),
        Rule(
            protocol=Protocol.ICMP,
            source=net("0.0.0.0/0"),
            destination=net("0.0.0.0/0"),
            action=Action.ALLOW,
        ),
    ]
    result = diff_policies([any_allow], split)
    assert result.newly_allowed.count == 0
    assert result.newly_denied.count == 0


def test_shadowed_rule_change_produces_no_diff():
    cover = Rule(
        protocol=Protocol.ANY,
        source=net("0.0.0.0/0"),
        destination=net("0.0.0.0/0"),
        action=Action.ALLOW,
    )
    shadowed_v1 = Rule(
        protocol=Protocol.TCP,
        source=net("10.0.0.0/8"),
        destination=net("192.0.2.0/24"),
        action=Action.DENY,
        ports=PortRange(22, 22),
    )
    shadowed_v2 = Rule(
        protocol=Protocol.UDP,
        source=net("172.16.0.0/12"),
        destination=net("198.51.100.0/24"),
        action=Action.ALLOW,
        ports=PortRange(53, 53),
    )
    result = diff_policies([cover, shadowed_v1], [cover, shadowed_v2])
    assert result.newly_allowed.count == 0
    assert result.newly_denied.count == 0


def test_newly_denied_when_rule_removed():
    allow = Rule(
        protocol=Protocol.TCP,
        source=net("10.0.0.0/24"),
        destination=net("192.0.2.0/24"),
        action=Action.ALLOW,
        ports=PortRange(443, 443),
    )
    result = diff_policies([allow], [])
    assert result.newly_allowed.count == 0
    assert result.newly_denied.count == 256 * 256
    assert result.newly_denied.examples[0].port == 443


def test_default_action_is_deny():
    assert evaluate_allow_regions([]) == []


def test_first_match_wins_earlier_deny_beats_later_allow():
    deny = Rule(
        protocol=Protocol.TCP,
        source=net("10.0.0.0/24"),
        destination=net("192.0.2.0/24"),
        action=Action.DENY,
        ports=PortRange(0, 65535),
    )
    allow = Rule(
        protocol=Protocol.TCP,
        source=net("10.0.0.0/24"),
        destination=net("192.0.2.0/24"),
        action=Action.ALLOW,
        ports=PortRange(80, 80),
    )
    assert evaluate_allow_regions([deny, allow]) == []
    regions = evaluate_allow_regions([allow, deny])
    assert sum(r.size() for r in regions) == 256 * 256


def test_cidr_includes_network_and_broadcast_addresses():
    allow = Rule(
        protocol=Protocol.ICMP,
        source=net("10.0.0.0/30"),
        destination=net("192.0.2.0/30"),
        action=Action.ALLOW,
    )
    regions = evaluate_allow_regions([allow])
    assert sum(r.size() for r in regions) == 4 * 4


def test_examples_actually_changed():
    old = Rule(
        protocol=Protocol.UDP,
        source=net("10.1.0.0/16"),
        destination=net("192.0.2.0/24"),
        action=Action.DENY,
        ports=PortRange(53, 53),
    )
    new = Rule(
        protocol=Protocol.UDP,
        source=net("10.1.0.0/16"),
        destination=net("192.0.2.0/24"),
        action=Action.ALLOW,
        ports=PortRange(53, 53),
    )
    result = diff_policies([old], [new])
    assert result.newly_allowed.count == 65536 * 256
    packet = result.newly_allowed.examples[0]
    assert packet.protocol is Protocol.UDP
    assert packet.port == 53
