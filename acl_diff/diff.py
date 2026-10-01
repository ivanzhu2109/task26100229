"""新旧策略的差量分析。

新增允许 = 新策略允许而旧策略拒绝的报文；
新增拒绝 = 旧策略允许而新策略拒绝的报文。
两份策略结论一致的报文不计入差量。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from .boxes import Box, subtract_many
from .model import Packet, Rule
from .policy import CONCRETE_PROTOCOLS, allow_boxes, sample_packet
from .model import Protocol

MAX_SAMPLES = 16


@dataclass(frozen=True)
class DiffResult:
    new_allows: int = 0
    new_denies: int = 0
    new_allow_samples: List[Packet] = field(default_factory=list)
    new_deny_samples: List[Packet] = field(default_factory=list)


def _region_diff(
    minus: Dict[Protocol, List[Box]],
    minus_from: Dict[Protocol, List[Box]],
) -> Dict[Protocol, List[Box]]:
    """按协议计算 minus_from \\ minus 的盒子集合。"""
    return {
        protocol: subtract_many(list(minus_from[protocol]), minus[protocol])
        for protocol in CONCRETE_PROTOCOLS
    }


def _samples(region: Dict[Protocol, List[Box]]) -> List[Packet]:
    packets: List[Packet] = []
    for protocol in CONCRETE_PROTOCOLS:
        for box in region[protocol]:
            if len(packets) >= MAX_SAMPLES:
                return packets
            packets.append(sample_packet(protocol, box))
    return packets


def analyze_diff(old_rules: Sequence[Rule], new_rules: Sequence[Rule]) -> DiffResult:
    old_allow = allow_boxes(old_rules)
    new_allow = allow_boxes(new_rules)

    gained = _region_diff(old_allow, new_allow)
    lost = _region_diff(new_allow, old_allow)

    return DiffResult(
        new_allows=sum(b.size() for boxes in gained.values() for b in boxes),
        new_denies=sum(b.size() for boxes in lost.values() for b in boxes),
        new_allow_samples=_samples(gained),
        new_deny_samples=_samples(lost),
    )
