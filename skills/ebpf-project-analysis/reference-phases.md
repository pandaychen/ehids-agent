# Cursor 深度分析 eBPF 项目：通用提示词模版

> **Skill 说明**：本文件为仓库内 `ebpf/cursor-ebpf-project-analysis-prompt-template.md` 的副本，便于将 Skill 复制到 `~/.claude/skills/ebpf-project-analysis/` 后全局离线使用；在 **本仓库内** 以 `ebpf/cursor-ebpf-project-analysis-prompt-template.md` 为单一维护源时可只改该文件，并同步副本。

> 创建时间：2026 年 3 月 26 日
> 适用场景：使用 Cursor 系统性拆解任意开源 eBPF 项目的架构、Hook 点、数据流、技术手法

---

## 使用说明

1. 将 `{{PROJECT_NAME}}`、`{{PROJECT_REPO}}` 等占位符替换为实际项目信息
2. 按阶段依次使用，每个阶段是一轮独立对话
3. 建议将项目代码 clone 到本地后在 Cursor 中打开，再使用这些提示词
4. 每个阶段的输出建议保存为独立文档

---

## 阶段一：项目全局架构拆解

```
我正在深度学习 {{PROJECT_NAME}} 项目（{{PROJECT_REPO}}），代码已 clone 到本地。
你是一名专业的 eBPF/Linux 内核/HIDS 专家。

请完成以下分析并输出为中文技术文档：

1. **项目总体架构**
   - 项目的核心目标和设计理念
   - 整体架构图（用 mermaid 表示）
   - 内核空间与用户空间的分层关系
   - 主要模块划分及职责

2. **目录结构分析**
   - 核心源码目录的作用说明
   - eBPF 程序（.bpf.c / .c）文件清单及各自的钩入点
   - 用户空间程序的入口和主要处理逻辑

3. **构建与加载流程**
   - 编译工具链（Clang/LLVM 版本要求、libbpf vs BCC vs cilium/ebpf）
   - eBPF 程序的编译、加载、附加流程
   - 是否使用 CO-RE/BTF，最低内核版本要求

4. **依赖关系**
   - 外部依赖库清单
   - 内核特性依赖（BTF、Ring Buffer、LSM 等）
   - 是否有 vmlinux.h 或自动生成机制

请逐个文件分析，不要遗漏，给出你的分析结论。
```

---

## 阶段二：eBPF Hook 点全景分析

```
继续分析 {{PROJECT_NAME}} 项目。

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
```

---

## 阶段三：eBPF Maps 与数据流分析

```
继续分析 {{PROJECT_NAME}} 项目。

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
```

---

## 阶段四：用户空间处理逻辑分析

```
继续分析 {{PROJECT_NAME}} 项目。

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
```

---

## 阶段五：核心功能深度分析

```
继续分析 {{PROJECT_NAME}} 项目。

请对以下核心功能进行 **逐个深度分析**：

{{列出你关注的具体功能，例如：}}
- 文件完整性监控（FIM）
- 进程行为检测
- 网络流量监控
- 容器/Kubernetes 感知
- 权限提升检测
- 敏感文件访问检测

对每个功能，请分析：

1. **实现原理**
   - 涉及的 Hook 点和 Map
   - 内核中的处理逻辑（伪代码级别）
   - 用户空间的处理逻辑
   - 端到端的事件流（从内核事件到最终输出）

2. **关键代码走读**
   - 标注核心代码段的文件路径和行号
   - 解释关键的结构体定义
   - 解释 BPF Helper 函数的使用方式和原因

3. **技术手法详解**
   - 如何从内核结构体中提取目标字段（dentry 遍历、namespace 获取等）
   - 如何绕过 eBPF 验证器的限制（有界循环、栈大小、指针检查）
   - 如何处理跨内核版本兼容性（CO-RE 读取、条件编译）

4. **局限性和改进空间**
   - 当前实现有哪些已知限制？
   - 可能的绕过/逃逸方式？
   - 你建议的改进方向？
```

---

## 阶段六：安全性与对抗分析

```
继续分析 {{PROJECT_NAME}} 项目。

作为安全专家，请从 **攻防对抗** 视角分析：

1. **检测覆盖面**
   - 该项目能检测哪些 ATT&CK 技术？
   - 有哪些已知的检测盲区？
   - 对于短生命周期进程/容器是否有效？

2. **逃逸分析**
   - 攻击者有哪些方式可以绕过该项目的检测？
   - 是否存在 TOCTOU（Time-of-Check to Time-of-Use）风险？
   - 如果攻击者拥有 root 权限，能否卸载/篡改该项目的 eBPF 程序？

3. **自身安全性**
   - 该项目自身是否可能被 eBPF Rootkit 欺骗？
   - 是否有自我完整性保护机制？
   - Ring Buffer / Perf Buffer 溢出时如何处理？是否会丢失关键事件？

4. **与其他安全工具的对比**
   - 与 Falco / Tetragon / Tracee / Sysdig 的功能对比
   - 独特优势和劣势
```

---

## 阶段七：性能与工程质量分析

```
继续分析 {{PROJECT_NAME}} 项目。

请从 **工程质量和性能** 角度分析：

1. **性能评估**
   - eBPF 程序的指令数和复杂度
   - 预估的 CPU 和内存开销
   - 在高负载场景下的表现（如 10000+ 事件/秒）
   - 是否有性能基准测试？结果如何？

2. **代码质量**
   - 代码组织和模块化程度
   - 错误处理的完善程度
   - 测试覆盖率（单元测试 / 集成测试 / eBPF 程序测试）
   - 文档质量

3. **可维护性**
   - 新增 Hook 点的难度
   - 新增检测规则的难度
   - 内核版本升级的适配成本

4. **部署与运维**
   - 部署方式（二进制 / 容器 / DaemonSet）
   - 配置管理
   - 日志和调试能力
   - 升级和回滚策略
```

---

## 阶段八：综合总结与技术报告

```
基于前面所有阶段的分析，请输出一份 **{{PROJECT_NAME}} 项目深度技术分析报告**，包含：

1. 执行摘要（1 页）
2. 架构总览图（mermaid）
3. Hook 点全景表
4. 数据流全景图（mermaid）
5. 核心功能实现详解
6. 安全性评估
7. 性能评估
8. 与同类项目对比矩阵
9. 优缺点总结
10. 改进建议

文档使用 Markdown 格式，核心流程用 mermaid 表示。
文件名格式：{{PROJECT_NAME}}-深度技术分析-{{日期}}.md
保存到 ebpf/ 目录下。
```

---

## 补充：针对特定类型项目的附加提示词

### A. 如果是 HIDS/运行时安全项目（Falco / Tetragon / Tracee 等）

```
补充分析以下 HIDS 特定方面：
- 系统调用监控的覆盖范围（哪些 syscall 被监控？）
- 容器运行时感知机制（如何获取容器 ID、镜像名、Pod 信息？）
- 策略引擎的表达力和灵活性
- 是否支持内联执行/阻断（Kill / Override）？
- 与 Kubernetes 的集成方式（CRD / Webhook / Operator）
```

### B. 如果是网络安全/可观测项目（Cilium / Pixie / Calico 等）

```
补充分析以下网络特定方面：
- XDP / TC 程序的处理逻辑
- 网络策略的下发和生效机制
- 连接跟踪（conntrack）的实现方式
- DNS / HTTP / TLS 协议解析逻辑
- 负载均衡和服务发现机制
```

### C. 如果是 FIM 项目

```
补充分析以下 FIM 特定方面：
- 监控的文件操作类型（创建/修改/删除/读取/属性变更）
- 路径过滤机制（前缀匹配 / 正则 / inode）
- 是否支持递归目录监控？
- Who-data 能力（用户/进程上下文）
- 文件哈希和内容捕获能力
- 与 inotify / fanotify / auditd 的对比
- TOCTOU 攻击的防护能力
```

### D. 如果是 Rootkit 检测项目

```
补充分析以下 Rootkit 检测特定方面：
- 检测的 Rootkit 类型（内核模块 / eBPF / 用户空间）
- 内核完整性检查机制
- 系统调用表完整性验证
- 隐藏进程/文件/网络连接的检测能力
- 自身的抗篡改能力
```

---

## 提示词使用技巧

1. **先 clone 代码再开始分析**——Cursor 需要在本地有完整代码才能进行文件级分析
2. **用 `@` 引用具体文件**——如 `@src/bpf/file_monitor.bpf.c` 可以让 Cursor 聚焦分析
3. **逐阶段进行**——不要一次性提交所有阶段，每阶段确认输出正确后再进入下一阶段
4. **交叉验证**——对 Cursor 给出的 Hook 点分析，可以用 `grep -r "SEC("` 等命令验证
5. **保存每阶段输出**——要求 Cursor 将分析结果保存到文件，便于后续回顾
