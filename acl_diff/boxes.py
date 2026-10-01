"""三维整数盒子（源地址段 x 目的地址段 x 端口段）及其差集运算。

所有区间均为闭区间。ICMP 盒子的端口维度退化为单点 [0, 0]，
计数时由调用方决定是否把端口维度计入（见 policy 模块）。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class Box:
    src_lo: int
    src_hi: int
    dst_lo: int
    dst_hi: int
    port_lo: int
    port_hi: int

    def size(self) -> int:
        return (
            (self.src_hi - self.src_lo + 1)
            * (self.dst_hi - self.dst_lo + 1)
            * (self.port_hi - self.port_lo + 1)
        )

    def intersection(self, other: "Box") -> Optional["Box"]:
        src_lo, src_hi = max(self.src_lo, other.src_lo), min(self.src_hi, other.src_hi)
        dst_lo, dst_hi = max(self.dst_lo, other.dst_lo), min(self.dst_hi, other.dst_hi)
        port_lo, port_hi = max(self.port_lo, other.port_lo), min(self.port_hi, other.port_hi)
        if src_lo > src_hi or dst_lo > dst_hi or port_lo > port_hi:
            return None
        return Box(src_lo, src_hi, dst_lo, dst_hi, port_lo, port_hi)


def subtract(box: Box, other: Box) -> List[Box]:
    """返回 box \\ other，结果为若干互不相交的盒子。"""
    inter = box.intersection(other)
    if inter is None:
        return [box]
    pieces: List[Box] = []
    # 源维度：交集左侧与右侧的剩余部分（覆盖全部目的/端口范围）。
    if box.src_lo < inter.src_lo:
        pieces.append(Box(box.src_lo, inter.src_lo - 1, box.dst_lo, box.dst_hi, box.port_lo, box.port_hi))
    if inter.src_hi < box.src_hi:
        pieces.append(Box(inter.src_hi + 1, box.src_hi, box.dst_lo, box.dst_hi, box.port_lo, box.port_hi))
    # 目的维度：在源维度交集内的上下剩余部分。
    if box.dst_lo < inter.dst_lo:
        pieces.append(Box(inter.src_lo, inter.src_hi, box.dst_lo, inter.dst_lo - 1, box.port_lo, box.port_hi))
    if inter.dst_hi < box.dst_hi:
        pieces.append(Box(inter.src_lo, inter.src_hi, inter.dst_hi + 1, box.dst_hi, box.port_lo, box.port_hi))
    # 端口维度：在源、目的维度交集内的剩余部分。
    if box.port_lo < inter.port_lo:
        pieces.append(Box(inter.src_lo, inter.src_hi, inter.dst_lo, inter.dst_hi, box.port_lo, inter.port_lo - 1))
    if inter.port_hi < box.port_hi:
        pieces.append(Box(inter.src_lo, inter.src_hi, inter.dst_lo, inter.dst_hi, inter.port_hi + 1, box.port_hi))
    return pieces


def subtract_many(boxes: List[Box], others: List[Box]) -> List[Box]:
    """从 boxes 中扣除 others 覆盖的全部区域。"""
    result = list(boxes)
    for other in others:
        next_result: List[Box] = []
        for box in result:
            next_result.extend(subtract(box, other))
        result = next_result
        if not result:
            break
    return result
