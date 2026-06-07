---
description: eBPF 项目深度分析 · 阶段三 · eBPF Maps 与数据流分析
argument-hint: <项目名> <仓库 URL>
---

继续分析 $1 项目。

请对项目中 **所有 eBPF Maps** 进行详细分析：

1. **Map 清单**（表格形式）
   | Map 名称 | Map 类型 | Key 类型 | Value 类型 | 最大条目数 | 用途说明 | 读写方 |

   特别关注以下 Map 类型：
   - BPF_MAP_TYPE_HASH / PERCPU_HASH / LRU_HASH
   - BPF_MAP_TYPE_ARRAY / PERCPU_ARRAY
   - BPF_MAP_TYPE_RINGBUF / PERF_EVENT_ARRAY
   - BPF_MAP_TYPE_LPM_TRIE
   - BPF_MAP_TYPE_PROG_ARRAY（尾调用）

2. **数据流全景图**
   - 从事件产生到最终处理的完整数据路径
   - 内核空间 → 用户空间的数据传输机制（Ring Buffer / Perf Buffer / Map 轮询）
   - 是否使用尾调用（tail call）？调用链是什么？
   - 用 mermaid 画出完整的数据流图

3. **Map 设计分析**
   - 为什么选择这种 Map 类型？（如 LRU vs 普通 Hash）
   - Map 大小的设计依据
   - 并发访问策略（per-CPU vs 全局锁 vs RCU）
   - 内存占用估算

4. **内核态过滤策略**
   - 是否在内核中做了事件预过滤？机制是什么？
   - 过滤效率如何？（类似 Datadog 的 Approver/Discarder）
   - 哪些数据在内核中丢弃，哪些传递到用户空间？
