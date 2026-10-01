# TerraMesh 入站 ACL 变更分析库

对单个子网的 IPv4 入站 ACL 策略做新旧差量分析：精确计算新增允许 / 新增拒绝的报文种数，并给出实际发生变化的报文示例。策略与分析结果仅保存在进程内存中，无任何外部依赖。

## 模型

- 策略是有序规则列表，首条同时匹配源 CIDR、目的 CIDR、协议（及端口）的规则决定结果，未匹配默认拒绝。
- 协议支持 `TCP`、`UDP`、`ICMP`、`ANY`。TCP/UDP 规则必须带目的端口闭区间（0–65535，单端口两端相同）；ICMP/ANY 不设端口。`ANY` 覆盖前三种协议。
- 一个报文由（协议, 源 IPv4, 目的 IPv4, 目的端口）区分；ICMP 无端口，同一源目的地址对只计一种报文。
- 分析范围为完整 IPv4 地址空间，CIDR 包含网络地址与广播地址。

## 用法

```python
from ipaddress import IPv4Network
from acl_diff import Action, Protocol, Rule, analyze_diff

old = [
    Rule(Action.DENY,  Protocol.TCP, IPv4Network("10.0.0.0/31"), IPv4Network("192.0.2.0/30"), (80, 81)),
    Rule(Action.ALLOW, Protocol.TCP, IPv4Network("10.0.0.0/30"), IPv4Network("192.0.2.0/31"), (81, 82)),
]
new = list(reversed(old))

result = analyze_diff(old, new)
result.new_allows          # 4  —— 由拒绝变为允许的报文种数（精确整数）
result.new_denies          # 0  —— 由允许变为拒绝的报文种数
result.new_allow_samples   # 实际变为允许的报文示例（Packet 列表）
result.new_deny_samples    # 实际变为拒绝的报文示例
```

`DiffResult` 字段：

| 字段 | 含义 |
| --- | --- |
| `new_allows` | 旧拒绝、新允许的报文种数 |
| `new_denies` | 旧允许、新拒绝的报文种数 |
| `new_allow_samples` / `new_deny_samples` | 对应变化的报文示例（每类最多 16 条） |

## 实现说明

每条规则展开为各具体协议下的三维整数盒子（源地址段 × 目的地址段 × 端口段，ICMP 端口维退化为单点）。按规则顺序维护"已匹配"区域并做盒子差集，得到策略允许区域的互不相交盒子；新旧允许区域互相做差即得两类差量，计数与取样均在盒子上完成，因此大网段（如 `0.0.0.0/0`）也能瞬时得出精确结果。

## 测试

```bash
python3 -m pytest tests/ -q
```
