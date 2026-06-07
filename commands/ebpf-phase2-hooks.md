---
description: eBPF 项目深度分析 · 阶段二 · eBPF Hook 点全景分析
argument-hint: <项目名> <仓库 URL>
---

继续分析 $1 项目。

请对项目中 **所有 eBPF Hook 点** 进行全景式梳理：

1. **Hook 点清单**（请以表格形式输出）
   | Hook 类型 | 具体挂钩点 | 所在源文件 | 触发条件 | 捕获的数据 | 作用说明 |

   Hook 类型包括但不限于：
   - kprobe / kretprobe
   - tracepoint / raw_tracepoint
   - LSM（security_*）
   - XDP / TC
   - uprobe / uretprobe
   - USDT
   - fentry / fexit
   - cgroup
   - perf_event
   - socket_filter
   - struct_ops

2. **Hook 之间的关系**
   - 哪些 Hook 是配对使用的（entry + return）？
   - 哪些 Hook 共享同一个 eBPF Map 进行数据传递？
   - 是否存在 Hook 链（一个事件触发多个 Hook 的级联处理）？
   - 用 mermaid 画出 Hook 之间的数据流关系图

3. **Hook 选择的技术决策分析**
   - 为什么选择这个 Hook 点而不是其他替代方案？
   - 是否存在 ABI 稳定性风险？如何应对？
   - 各 Hook 点的性能开销评估

4. **每个 Hook 的详细参数解析**
   - 函数签名及各参数的含义
   - 如何从参数中提取目标数据（struct 成员访问路径）
   - 使用了哪些 BPF Helper 函数
