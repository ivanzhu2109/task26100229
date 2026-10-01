"""由有序规则列表计算允许区域（按具体协议分组的互不相交盒子）。"""
from __future__ import annotations

from ipaddress import IPv4Address
from typing import Dict, List, Sequence, Tuple

from .boxes import Box, subtract_many
from .model import MAX_PORT, MIN_PORT, Action, Packet, Protocol, Rule

CONCRETE_PROTOCOLS: Tuple[Protocol, ...] = (Protocol.TCP, Protocol.UDP, Protocol.ICMP)


def _rule_boxes(rule: Rule) -> Dict[Protocol, List[Box]]:
    """把一条规则展开为各具体协议下的盒子。"""
    src_lo, src_hi = int(rule.source.network_address), int(rule.source.broadcast_address)
    dst_lo, dst_hi = int(rule.destination.network_address), int(rule.destination.broadcast_address)

    def l4_box(port_lo: int, port_hi: int) -> Box:
        return Box(src_lo, src_hi, dst_lo, dst_hi, port_lo, port_hi)

    if rule.protocol in (Protocol.TCP, Protocol.UDP):
        assert rule.port_range is not None
        return {rule.protocol: [l4_box(rule.port_range[0], rule.port_range[1])]}
    if rule.protocol is Protocol.ICMP:
        return {Protocol.ICMP: [l4_box(0, 0)]}
    # ANY：覆盖 TCP/UDP 全端口与 ICMP。
    return {
        Protocol.TCP: [l4_box(MIN_PORT, MAX_PORT)],
        Protocol.UDP: [l4_box(MIN_PORT, MAX_PORT)],
        Protocol.ICMP: [l4_box(0, 0)],
    }


def allow_boxes(rules: Sequence[Rule]) -> Dict[Protocol, List[Box]]:
    """按规则顺序匹配，返回策略允许区域的互不相交盒子（按协议分组）。"""
    matched: Dict[Protocol, List[Box]] = {p: [] for p in CONCRETE_PROTOCOLS}
    allowed: Dict[Protocol, List[Box]] = {p: [] for p in CONCRETE_PROTOCOLS}
    for rule in rules:
        for protocol, boxes in _rule_boxes(rule).items():
            remaining = subtract_many(boxes, matched[protocol])
            matched[protocol].extend(remaining)
            if rule.action is Action.ALLOW:
                allowed[protocol].extend(remaining)
    return allowed


def count_packets(allowed: Dict[Protocol, List[Box]]) -> int:
    return sum(box.size() for boxes in allowed.values() for box in boxes)


def sample_packet(protocol: Protocol, box: Box) -> Packet:
    """从盒子中取一个确定性的示例报文（各维度取下界）。"""
    port = None if protocol is Protocol.ICMP else box.port_lo
    return Packet(
        protocol=protocol,
        source=IPv4Address(box.src_lo),
        destination=IPv4Address(box.dst_lo),
        port=port,
    )
