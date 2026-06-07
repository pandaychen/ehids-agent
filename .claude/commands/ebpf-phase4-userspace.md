---
description: eBPF 项目深度分析 · 阶段四 · 用户空间处理逻辑分析
argument-hint: <项目名> <仓库 URL>
---

继续分析 $1 项目。

请对 **用户空间程序** 进行详细分析：

1. **程序入口与初始化流程**
   - main 函数的执行流程
   - eBPF 程序的加载和附加顺序
   - 配置文件解析逻辑
   - 信号处理和优雅退出机制

2. **事件处理管线**
   - 从 Ring Buffer / Perf Buffer 读取事件的回调逻辑
   - 事件反序列化和解析
   - 事件富化（enrichment）：如何添加进程名、容器 ID、用户名等上下文？
   - 事件过滤和规则匹配引擎

3. **规则/策略引擎**（如果有）
   - 规则的定义格式（YAML / JSON / DSL）
   - 规则的编译和下发到内核的流程
   - 规则匹配算法

4. **输出与告警**
   - 事件的输出格式和目标（stdout / 文件 / gRPC / Webhook）
   - 告警机制
   - 与外部系统的集成方式

5. **编程语言特定分析**
   - 如果是 Go：使用的 eBPF 库（cilium/ebpf / libbpfgo / gobpf）
   - 如果是 Rust：使用的 eBPF 库（aya / libbpf-rs / redbpf）
   - 如果是 C/C++：直接使用 libbpf 还是有封装层？
