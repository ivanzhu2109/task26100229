"""TerraMesh 入站 ACL 策略的数据模型定义。"""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass


class Protocol(enum.Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class Action(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class PortRange:
    """TCP/UDP 目的端口闭区间，单端口时 low == high。"""

    low: int
    high: int

    def __post_init__(self) -> None:
        if not (0 <= self.low <= self.high <= 65535):
            raise ValueError(f"非法端口区间: {self.low}-{self.high}")


@dataclass(frozen=True)
class Rule:
    """一条入站 ACL 规则。

    protocol 为 TCP/UDP 时必须给出 ports；ICMP/ANY 不设端口。
    ANY 覆盖 TCP、UDP、ICMP 三种协议的全部报文。
    """

    protocol: Protocol
    source: ipaddress.IPv4Network
    destination: ipaddress.IPv4Network
    action: Action
    ports: PortRange | None = None

    def __post_init__(self) -> None:
        if self.protocol in (Protocol.TCP, Protocol.UDP):
            if self.ports is None:
                raise ValueError("TCP/UDP 规则必须指定目的端口区间")
        else:
            if self.ports is not None:
                raise ValueError("ICMP/ANY 规则不接受端口区间")


@dataclass(frozen=True)
class Packet:
    """一份报文：协议 + 源/目的 IPv4 + 目的端口（ICMP 无端口）。"""

    protocol: Protocol
    source: ipaddress.IPv4Address
    destination: ipaddress.IPv4Address
    port: int | None = None
