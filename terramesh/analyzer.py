"""策略求值与新旧策略差量分析。"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Action, Packet, Protocol, Rule
from .region import Region, subtract, subtract_all


@dataclass(frozen=True)
class PacketChange:
    """一类变化：精确数量 + 若干实际变化的报文示例。"""

    count: int
    examples: tuple[Packet, ...] = ()


@dataclass(frozen=True)
class DiffResult:
    """差量分析结果：新增允许与新增拒绝。"""

    newly_allowed: PacketChange
    newly_denied: PacketChange


def evaluate_allow_regions(rules: list[Rule]) -> list[Region]:
    """按首条匹配语义求出策略允许的报文空间（互不相交区域列表）。"""
    allowed: list[Region] = []
    matched: list[Region] = []
    for rule in rules:
        for region in _rule_regions(rule):
            remainder = subtract(region, matched)
            if rule.action is Action.ALLOW:
                allowed.extend(remainder)
            matched.extend(remainder)
    return allowed


def _rule_regions(rule: Rule) -> list[Region]:
    """把一条规则展开为各协议下的区域（ANY 展开为 TCP/UDP/ICMP）。"""
    src_lo = int(rule.source.network_address)
    src_hi = int(rule.source.broadcast_address)
    dst_lo = int(rule.destination.network_address)
    dst_hi = int(rule.destination.broadcast_address)

    if rule.protocol in (Protocol.TCP, Protocol.UDP):
        assert rule.ports is not None
        return [
            Region(
                rule.protocol, src_lo, src_hi, dst_lo, dst_hi,
                rule.ports.low, rule.ports.high,
            )
        ]
    if rule.protocol is Protocol.ICMP:
        return [Region(Protocol.ICMP, src_lo, src_hi, dst_lo, dst_hi)]
    return [
        Region(Protocol.TCP, src_lo, src_hi, dst_lo, dst_hi, 0, 65535),
        Region(Protocol.UDP, src_lo, src_hi, dst_lo, dst_hi, 0, 65535),
        Region(Protocol.ICMP, src_lo, src_hi, dst_lo, dst_hi),
    ]


def diff_policies(
    old_rules: list[Rule],
    new_rules: list[Rule],
    max_examples: int = 5,
) -> DiffResult:
    """比较新旧两份策略，给出新增允许/新增拒绝的精确数量与示例。"""
    old_allowed = evaluate_allow_regions(old_rules)
    new_allowed = evaluate_allow_regions(new_rules)
    return DiffResult(
        newly_allowed=_change(new_allowed, old_allowed, max_examples),
        newly_denied=_change(old_allowed, new_allowed, max_examples),
    )


def _change(
    gained: list[Region], lost: list[Region], max_examples: int
) -> PacketChange:
    regions = subtract_all(gained, lost)
    count = sum(region.size() for region in regions)
    examples = tuple(region.first_packet() for region in regions[:max_examples])
    return PacketChange(count=count, examples=examples)
