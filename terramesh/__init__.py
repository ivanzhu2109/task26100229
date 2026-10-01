"""TerraMesh 入站 ACL 变更分析库。

策略与分析结果仅保存在进程内存中，供上层发布检查直接调用。
"""

from .analyzer import DiffResult, PacketChange, diff_policies, evaluate_allow_regions
from .model import Action, Packet, PortRange, Protocol, Rule

__all__ = [
    "Action",
    "DiffResult",
    "Packet",
    "PacketChange",
    "PortRange",
    "Protocol",
    "Rule",
    "diff_policies",
    "evaluate_allow_regions",
]
