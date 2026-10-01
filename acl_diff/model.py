"""数据模型：协议、动作、规则、报文。"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Optional, Tuple

MIN_PORT = 0
MAX_PORT = 65535


class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class Action(Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Rule:
    """一条入站 ACL 规则。

    TCP/UDP 规则必须提供目的端口闭区间 port_range；ICMP/ANY 规则不设端口。
    ANY 覆盖 TCP、UDP、ICMP 三种协议的全部报文。
    """

    action: Action
    protocol: Protocol
    source: IPv4Network
    destination: IPv4Network
    port_range: Optional[Tuple[int, int]] = None

    def __post_init__(self) -> None:
        if not isinstance(self.action, Action):
            raise TypeError("action 必须是 Action 枚举")
        if not isinstance(self.protocol, Protocol):
            raise TypeError("protocol 必须是 Protocol 枚举")
        for field_name, network in (("source", self.source), ("destination", self.destination)):
            if not isinstance(network, IPv4Network):
                raise TypeError(f"{field_name} 必须是 IPv4Network")
        if self.protocol in (Protocol.TCP, Protocol.UDP):
            if self.port_range is None:
                raise ValueError("TCP/UDP 规则必须提供目的端口区间")
            lo, hi = self.port_range
            if not (MIN_PORT <= lo <= hi <= MAX_PORT):
                raise ValueError(f"非法端口区间: {self.port_range}")
        else:
            if self.port_range is not None:
                raise ValueError("ICMP/ANY 规则不应设置端口区间")


@dataclass(frozen=True)
class Packet:
    """一个具体报文。ICMP 报文 port 为 None。"""

    protocol: Protocol
    source: IPv4Address
    destination: IPv4Address
    port: Optional[int] = None
