# task26100229

## TerraMesh 入站 ACL 变更分析库

纯进程内存的 Python 库，供上层发布检查调用：比较新旧两份 IPv4 入站
ACL 策略，精确给出**新增允许**与**新增拒绝**的报文种数，并提供实际发生
变化的报文示例。

### 语义

- 策略是有序规则列表，每条规则含源 CIDR、目的 CIDR、协议（TCP/UDP/ICMP/ANY）
  和允许/拒绝动作；按顺序首条匹配生效，未匹配默认拒绝。
- TCP/UDP 规则带目的端口闭区间（0–65535，单端口两端相同）；ICMP/ANY 不设端口。
- ANY 覆盖 TCP、UDP、ICMP 三种协议的全部报文，不是第四种协议。
- 报文由（协议、源 IPv4、目的 IPv4、目的端口）区分；ICMP 无端口，同一源目的
  地址对只计一种报文。CIDR 包含网络地址与广播地址，分析范围为完整 IPv4 空间。

### 用法

```python
import ipaddress
from terramesh import Action, PortRange, Protocol, Rule, diff_policies

net = ipaddress.IPv4Network

old = [
    Rule(Protocol.TCP, net("10.0.0.0/31"), net("192.0.2.0/30"),
         Action.DENY, PortRange(80, 81)),
    Rule(Protocol.TCP, net("10.0.0.0/30"), net("192.0.2.0/31"),
         Action.ALLOW, PortRange(81, 82)),
]
new = [old[1], old[0]]  # 调整顺序：允许在前

result = diff_policies(old, new)
result.newly_allowed.count     # 4（精确整数）
result.newly_allowed.examples  # 实际变化的报文示例 (Packet, ...)
result.newly_denied.count      # 0
```

- `diff_policies(old_rules, new_rules, max_examples=5)` 返回 `DiffResult`，
  含 `newly_allowed` / `newly_denied` 两个 `PacketChange`（`count` + `examples`）。
- `evaluate_allow_regions(rules)` 单独求一份策略允许的报文空间（区域列表）。
- 数量为精确大整数（如全地址 ANY 允许为 `2**81 + 2**64`），示例数由
  `max_examples` 控制。

### 实现原理

每条规则展开为各协议下的多维矩形区域（源地址 × 目的地址 × 端口，ICMP 无
端口维度）。按规则顺序维护"已匹配"区域集合，逐条扣除后余下的允许区域即
策略的允许空间；对新旧允许空间做区域差集即得差量。全部为整数区间运算，
无采样、无近似。

### 测试

```bash
python3 -m pytest tests -q
```
