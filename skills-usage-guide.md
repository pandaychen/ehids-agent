# Claude Code Skills 使用提示词指南

> 生成日期：2026-03-27
> 适用于：当前 Claude Code 会话中已加载的全部 Skills

---

## 目录

- [一、Skills 全景表](#一skills-全景表)
- [二、eBPF 深度分析系列（8 阶段）](#二ebpf-深度分析系列8-阶段)
- [三、eBPF 补充专项分析（4 类）](#三ebpf-补充专项分析4-类)
- [四、通用工具类 Skills](#四通用工具类-skills)
- [五、使用技巧与注意事项](#五使用技巧与注意事项)

---

## 一、Skills 全景表

| # | Skill 名称 | 触发命令 | 用途 | 输出语言 |
|---|-----------|---------|------|---------|
| 1 | `ebpf-project-analysis` | 分析 eBPF 项目 | 总入口：分阶段深度分析 eBPF 项目 | 中文 |
| 2 | `ebpf-phase1-architecture` | 分析架构 | 阶段一：全局架构拆解 | 中文 |
| 3 | `ebpf-phase2-hooks` | 分析 Hook 点 | 阶段二：eBPF Hook 点全景分析 | 中文 |
| 4 | `ebpf-phase3-maps` | 分析 Maps | 阶段三：eBPF Maps 与数据流分析 | 中文 |
| 5 | `ebpf-phase4-userspace` | 分析用户空间 | 阶段四：用户空间处理逻辑分析 | 中文 |
| 6 | `ebpf-phase5-features` | 分析核心功能 | 阶段五：核心功能深度分析 | 中文 |
| 7 | `ebpf-phase6-security` | 分析安全性 | 阶段六：安全性与对抗分析 | 中文 |
| 8 | `ebpf-phase7-quality` | 分析工程质量 | 阶段七：性能与工程质量分析 | 中文 |
| 9 | `ebpf-phase8-report` | 生成总报告 | 阶段八：综合总结与技术报告 | 中文 |
| 10 | `ebpf-supplement-hids` | HIDS 专项 | 补充：HIDS/运行时安全专项分析 | 中文 |
| 11 | `ebpf-supplement-network` | 网络专项 | 补充：网络/可观测专项分析 | 中文 |
| 12 | `ebpf-supplement-fim` | FIM 专项 | 补充：文件完整性监控专项分析 | 中文 |
| 13 | `ebpf-supplement-rootkit` | Rootkit 专项 | 补充：Rootkit 检测专项分析 | 中文 |
| 14 | `update-config` | 更新配置 | 配置 Claude Code settings.json | - |
| 15 | `simplify` | 简化代码 | 审查代码质量和复用性 | - |
| 16 | `loop` | 循环执行 | 按间隔重复运行命令 | - |
| 17 | `claude-api` | Claude API | 辅助构建 Anthropic API 应用 | - |

---

## 二、eBPF 深度分析系列（8 阶段）

### 推荐工作流

```
总入口（可选）
  /ebpf-project-analysis
  │
  └─ 依次执行 8 个阶段：
     /ebpf-phase1-architecture  →  阶段一
     /ebpf-phase2-hooks         →  阶段二
     /ebpf-phase3-maps          →  阶段三
     /ebpf-phase4-userspace     →  阶段四
     /ebpf-phase5-features      →  阶段五
     /ebpf-phase6-security      →  阶段六
     /ebpf-phase7-quality       →  阶段七
     /ebpf-phase8-report        →  阶段八（汇总）
     │
     └─ 按需追加补充专项：
        /ebpf-supplement-hids
        /ebpf-supplement-network
        /ebpf-supplement-fim
        /ebpf-supplement-rootkit
```

> **关键原则**：每阶段一轮对话，确认输出正确后再进入下一阶段。

---

### 阶段一：全局架构拆解

**Skill 名称**：`ebpf-phase1-architecture`

**触发提示词**：

```
请使用 /ebpf-phase1-architecture 分析 ehids-agent 项目（https://github.com/ehids/ehids-agent）。

代码已在当前工作区。请完成以下分析并输出中文技术文档：

1. 项目总体架构（含 mermaid 架构图）
2. 目录结构分析（逐文件说明）
3. 构建与加载流程（编译工具链、CO-RE/BTF、最低内核版本）
4. 依赖关系（外部库、内核特性、vmlinux.h）

保存为：ehids-agent-phase1-architecture.md
```

**输出内容**：
- 整体架构图（mermaid）
- 内核空间与用户空间分层关系
- 主要模块划分及职责
- eBPF 程序文件清单及各自钩入点
- 编译工具链和加载流程
- 外部依赖库清单

---

### 阶段二：eBPF Hook 点全景分析

**Skill 名称**：`ebpf-phase2-hooks`

**触发提示词**：

```
请使用 /ebpf-phase2-hooks 分析 ehids-agent 的全部 eBPF Hook 点。

请完成：
1. Hook 点清单（表格：Hook类型 | 挂钩点 | 源文件 | 触发条件 | 捕获数据 | 作用）
2. Hook 之间的关系（配对使用、共享 Map、级联处理、mermaid 关系图）
3. Hook 选择的技术决策分析（为什么选这个而不是其他？ABI 稳定性？性能开销？）
4. 每个 Hook 的详细参数解析（函数签名、struct 成员访问路径、BPF Helper）

保存为：ehids-agent-phase2-hooks.md
```

---

### 阶段三：eBPF Maps 与数据流分析

**Skill 名称**：`ebpf-phase3-maps`

**触发提示词**：

```
请使用 /ebpf-phase3-maps 分析 ehids-agent 的全部 eBPF Maps 和数据流。

请完成：
1. Map 清单（表格：名称 | 类型 | Key | Value | 最大条目 | 用途 | 读写方）
2. 数据流全景图（事件产生→最终处理完整路径，mermaid 图）
3. Map 设计分析（类型选择原因、大小依据、并发策略、内存估算）
4. 内核态过滤策略（预过滤机制、过滤效率、丢弃 vs 传递）

保存为：ehids-agent-phase3-maps.md
```

---

### 阶段四：用户空间处理逻辑分析

**Skill 名称**：`ebpf-phase4-userspace`

**触发提示词**：

```
请使用 /ebpf-phase4-userspace 分析 ehids-agent 的用户空间程序。

请完成：
1. 程序入口与初始化流程（main 执行流程、加载顺序、信号处理）
2. 事件处理管线（读取回调、反序列化、事件富化、过滤匹配）
3. 规则/策略引擎（如果有）
4. 输出与告警（输出格式、告警机制、外部集成）
5. Go 语言特定分析（cilium/ebpf / ebpfmanager 使用方式）

保存为：ehids-agent-phase4-userspace.md
```

---

### 阶段五：核心功能深度分析

**Skill 名称**：`ebpf-phase5-features`

**触发提示词**：

```
请使用 /ebpf-phase5-features 对 ehids-agent 的以下核心功能逐个深度分析：

- 进程行为检测（fork/exec）
- TCP 连接追踪
- DNS 查询监控（uprobe + UDP 双模式）
- Socket 连接监控
- Java RASP 命令执行检测
- BPF 系统调用追踪

对每个功能分析：
1. 实现原理（Hook 点 + Map + 内核逻辑 + 用户态逻辑 + 端到端事件流）
2. 关键代码走读（标注文件路径和行号）
3. 技术手法详解（结构体提取、验证器规避、跨版本兼容）
4. 局限性和改进空间

保存为：ehids-agent-phase5-features.md
```

---

### 阶段六：安全性与对抗分析

**Skill 名称**：`ebpf-phase6-security`

**触发提示词**：

```
请使用 /ebpf-phase6-security 从攻防对抗视角分析 ehids-agent。

请完成：
1. 检测覆盖面（能检测哪些 ATT&CK 技术？检测盲区？短生命周期进程？）
2. 逃逸分析（绕过方式？TOCTOU 风险？root 权限卸载？）
3. 自身安全性（eBPF Rootkit 欺骗？自我完整性保护？Buffer 溢出处理？）
4. 与 Falco / Tetragon / Tracee / Sysdig 的功能对比

保存为：ehids-agent-phase6-security.md
```

---

### 阶段七：性能与工程质量分析

**Skill 名称**：`ebpf-phase7-quality`

**触发提示词**：

```
请使用 /ebpf-phase7-quality 从工程质量和性能角度分析 ehids-agent。

请完成：
1. 性能评估（指令数、CPU/内存开销、高负载表现、基准测试）
2. 代码质量（模块化、错误处理、测试覆盖、文档质量）
3. 可维护性（新增 Hook 难度、新增规则难度、内核升级适配成本）
4. 部署与运维（部署方式、配置管理、日志调试、升级回滚）

保存为：ehids-agent-phase7-quality.md
```

---

### 阶段八：综合总结与技术报告

**Skill 名称**：`ebpf-phase8-report`

**触发提示词**：

```
请使用 /ebpf-phase8-report 基于前 7 个阶段的分析，输出 ehids-agent 的综合技术分析报告。

报告包含：
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

保存为：ehids-agent-深度技术分析-2026-03-27.md
```

---

## 三、eBPF 补充专项分析（4 类）

> 根据项目类型选用，不是每个项目都需要全部补充专项。

### HIDS / 运行时安全专项

**Skill 名称**：`ebpf-supplement-hids`

**适用项目**：Falco、Tetragon、Tracee、ehids-agent 等安全检测类项目

**触发提示词**：

```
请使用 /ebpf-supplement-hids 对 ehids-agent 进行 HIDS 专项补充分析：

- 系统调用监控的覆盖范围（哪些 syscall 被监控？）
- 容器运行时感知机制（如何获取容器 ID、镜像名、Pod 信息？）
- 策略引擎的表达力和灵活性
- 是否支持内联执行/阻断（Kill / Override）？
- 与 Kubernetes 的集成方式（CRD / Webhook / Operator）

保存为：ehids-agent-supplement-hids.md
```

---

### 网络 / 可观测专项

**Skill 名称**：`ebpf-supplement-network`

**适用项目**：Cilium、Pixie、Calico、网络监控类项目

**触发提示词**：

```
请使用 /ebpf-supplement-network 对本项目进行网络专项补充分析：

- XDP / TC 程序的处理逻辑
- 网络策略的下发和生效机制
- 连接跟踪（conntrack）的实现方式
- DNS / HTTP / TLS 协议解析逻辑
- 负载均衡和服务发现机制

保存为：xxx-supplement-network.md
```

---

### FIM 文件完整性专项

**Skill 名称**：`ebpf-supplement-fim`

**适用项目**：文件完整性监控类项目

**触发提示词**：

```
请使用 /ebpf-supplement-fim 对本项目进行 FIM 专项补充分析：

- 监控的文件操作类型（创建/修改/删除/读取/属性变更）
- 路径过滤机制（前缀匹配 / 正则 / inode）
- 是否支持递归目录监控？
- Who-data 能力（用户/进程上下文）
- 文件哈希和内容捕获能力
- 与 inotify / fanotify / auditd 的对比
- TOCTOU 攻击的防护能力

保存为：xxx-supplement-fim.md
```

---

### Rootkit 检测专项

**Skill 名称**：`ebpf-supplement-rootkit`

**适用项目**：内核安全检测、Rootkit 检测类项目

**触发提示词**：

```
请使用 /ebpf-supplement-rootkit 对本项目进行 Rootkit 检测专项补充分析：

- 检测的 Rootkit 类型（内核模块 / eBPF / 用户空间）
- 内核完整性检查机制
- 系统调用表完整性验证
- 隐藏进程/文件/网络连接的检测能力
- 自身的抗篡改能力

保存为：xxx-supplement-rootkit.md
```

---

## 四、通用工具类 Skills

### update-config — 配置管理

**触发场景**：修改 Claude Code 的 settings.json（hooks、权限、环境变量）

```
# 添加命令权限
请使用 /update-config 允许执行 npm 命令

# 设置环境变量
请使用 /update-config 设置 DEBUG=true

# 配置自动行为（hooks）
请使用 /update-config 在每次 Claude 停止时显示 git status

# 修改权限位置
请使用 /update-config 将 bq 权限移到全局 settings
```

---

### simplify — 代码简化审查

**触发场景**：代码写完后，审查复用性、质量和效率

```
# 审查刚修改的代码
/simplify

# 审查指定文件
请使用 /simplify 审查 user/imodule.go 的代码质量
```

**输出内容**：发现的复用问题、质量问题、效率问题，并自动修复。

---

### loop — 循环执行

**触发场景**：需要定期重复执行某个命令

```
# 每 5 分钟检查部署状态
/loop 5m 检查 deploy 状态

# 每 10 分钟运行测试
/loop 10m /test

# 持续监控 PR
/loop 5m /babysit-prs
```

---

### claude-api — Claude API 辅助

**触发场景**：代码中使用了 `anthropic` / `@anthropic-ai/sdk` / `claude_agent_sdk`

```
# 帮助构建 Claude API 应用
请使用 /claude-api 帮我实现一个使用 Anthropic SDK 的聊天应用

# Agent SDK 相关
请使用 /claude-api 帮我用 claude_agent_sdk 构建一个多步骤 Agent
```

**注意**：只在代码涉及 Anthropic/Claude SDK 时触发，普通编程任务不要使用。

---

## 五、使用技巧与注意事项

### 1. 正确的触发方式

```
# 方式一：直接使用斜杠命令
/ebpf-phase1-architecture

# 方式二：在自然语言中引用
请使用 /ebpf-phase2-hooks 分析这个项目的 Hook 点

# 方式三：描述需求让 Claude 自动匹配
帮我分析这个 eBPF 项目   →  Claude 会匹配到 ebpf-project-analysis
```

### 2. eBPF 分析的推荐顺序

```
1. 先执行阶段一（架构），建立全局认知
2. 按顺序执行阶段二到七，逐层深入
3. 最后执行阶段八，汇总为完整报告
4. 根据项目类型选择性执行补充专项

不建议：跳过阶段、乱序执行、一次性执行全部阶段
```

### 3. 自定义阶段五的关注功能

```
# 阶段五允许自定义分析目标
# 默认模板中的功能列表可以替换：

请使用 /ebpf-phase5-features 分析以下功能：
- 我关注的功能 A
- 我关注的功能 B
- 我关注的功能 C
```

### 4. 占位符替换

在使用提示词模板时，记得替换：
- `{{PROJECT_NAME}}` → 实际项目名（如 `ehids-agent`）
- `{{PROJECT_REPO}}` → 实际仓库地址
- `{{日期}}` → 当前日期

### 5. 配合 Agent 使用

```
# 先用 Explore Agent 快速了解项目
# 再用 Skills 做深度分析

# 步骤一：快速探索
帮我探索这个项目的目录结构和关键文件

# 步骤二：深度分析
/ebpf-phase1-architecture
```

### 6. 输出保存

每个 Skill 都支持将输出保存为 Markdown 文件，建议在提示词末尾加：

```
保存为：<文件名>.md
保存到：<目标目录>/
```
