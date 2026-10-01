"""报文空间的多维矩形区域表示与集合运算。

一个 Region 表示某一协议下，源地址区间 x 目的地址区间 x 端口区间
的笛卡尔积（ICMP 无端口维度）。所有运算只依赖整数区间，结果精确。
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Packet, Protocol


@dataclass(frozen=True)
class Region:
    protocol: Protocol
    src_lo: int
    src_hi: int
    dst_lo: int
    dst_hi: int
    port_lo: int = 0
    port_hi: int = 0

    def size(self) -> int:
        """区域内报文的精确种数。"""
        addresses = (self.src_hi - self.src_lo + 1) * (self.dst_hi - self.dst_lo + 1)
        if self.protocol is Protocol.ICMP:
            return addresses
        return addresses * (self.port_hi - self.port_lo + 1)

    def first_packet(self) -> Packet:
        """区域内按字典序的第一份报文，用作变化示例。"""
        import ipaddress

        port = None if self.protocol is Protocol.ICMP else self.port_lo
        return Packet(
            protocol=self.protocol,
            source=ipaddress.IPv4Address(self.src_lo),
            destination=ipaddress.IPv4Address(self.dst_lo),
            port=port,
        )

    def _intersect(self, other: Region) -> Region | None:
        if self.protocol is not other.protocol:
            return None
        src_lo = max(self.src_lo, other.src_lo)
        src_hi = min(self.src_hi, other.src_hi)
        dst_lo = max(self.dst_lo, other.dst_lo)
        dst_hi = min(self.dst_hi, other.dst_hi)
        port_lo = max(self.port_lo, other.port_lo)
        port_hi = min(self.port_hi, other.port_hi)
        if src_lo > src_hi or dst_lo > dst_hi or port_lo > port_hi:
            return None
        return Region(
            self.protocol, src_lo, src_hi, dst_lo, dst_hi, port_lo, port_hi
        )

    def _minus(self, cut: Region) -> list[Region]:
        """从本区域中扣除 cut（cut 必须是本区域的子集），返回不相交区域。"""
        pieces: list[Region] = []
        dims = (
            ("src_lo", "src_hi"),
            ("dst_lo", "dst_hi"),
            ("port_lo", "port_hi"),
        )
        remaining = self
        for lo_attr, hi_attr in dims:
            lo = getattr(remaining, lo_attr)
            hi = getattr(remaining, hi_attr)
            cut_lo = getattr(cut, lo_attr)
            cut_hi = getattr(cut, hi_attr)
            if cut_lo > lo:
                pieces.append(remaining._replace_dim(lo_attr, hi_attr, lo, cut_lo - 1))
            if cut_hi < hi:
                pieces.append(remaining._replace_dim(lo_attr, hi_attr, cut_hi + 1, hi))
            remaining = remaining._replace_dim(lo_attr, hi_attr, cut_lo, cut_hi)
        return pieces

    def _replace_dim(self, lo_attr: str, hi_attr: str, lo: int, hi: int) -> Region:
        values = {
            "src_lo": self.src_lo,
            "src_hi": self.src_hi,
            "dst_lo": self.dst_lo,
            "dst_hi": self.dst_hi,
            "port_lo": self.port_lo,
            "port_hi": self.port_hi,
        }
        values[lo_attr] = lo
        values[hi_attr] = hi
        return Region(self.protocol, **values)


def subtract(region: Region, others: list[Region]) -> list[Region]:
    """从 region 中扣除 others 的并集，返回互不相交的区域列表。"""
    remaining = [region]
    for other in others:
        next_remaining: list[Region] = []
        for piece in remaining:
            overlap = piece._intersect(other)
            if overlap is None:
                next_remaining.append(piece)
            else:
                next_remaining.extend(piece._minus(overlap))
        remaining = next_remaining
        if not remaining:
            break
    return remaining


def subtract_all(regions: list[Region], others: list[Region]) -> list[Region]:
    """对一组区域逐个扣除 others，返回互不相交的区域列表。"""
    result: list[Region] = []
    for region in regions:
        result.extend(subtract(region, others))
    return result
