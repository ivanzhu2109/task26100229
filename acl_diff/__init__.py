"""TerraMesh 入站 ACL 变更分析库（纯进程内存）。"""
from .diff import DiffResult, analyze_diff
from .model import Action, Packet, Protocol, Rule

__all__ = [
    "Action",
    "DiffResult",
    "Packet",
    "Protocol",
    "Rule",
    "analyze_diff",
]
