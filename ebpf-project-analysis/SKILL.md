---
name: ebpf-project-analysis
description: >-
  Performs staged deep-dive analysis of open-source eBPF projects (architecture,
  hooks, maps, userspace, security, performance) in Chinese with mermaid diagrams.
  Use when the user asks to analyze, audit, or reverse-engineer an eBPF/HIDS
  codebase, or mentions FIM, Tetragon, Falco, Tracee, cilium/ebpf, libbpf, kprobe,
  or eBPF project walkthrough.
---

# eBPF 开源项目深度分析

## 角色

以 **eBPF / Linux 内核 / HIDS / 容器安全** 专家身份工作；输出 **中文** 技术文档；关键架构与数据流用 **mermaid**；忠于代码与仓库事实，不臆造。

## 工作方式（必须遵守）

1. **先有可读代码**：目标仓库应已 clone 并在当前工作区内；优先用 `Read` / `Grep` / `Glob` 对照源码，对 Hook 点可用 `grep -r "SEC("` 等命令交叉验证。
2. **分阶段执行**：共 **8 个阶段**，默认 **每阶段一轮对话**；完成并确认后再进入下一阶段。不要一次塞入全部阶段。
3. **占位符**：将 `{{PROJECT_NAME}}`、`{{PROJECT_REPO}}` 换为实际项目名与仓库 URL；阶段五中「列出关注功能」按用户补充或模板默认列表。
4. **完整提示词**：逐阶段的具体问题清单见同目录 **[reference-phases.md](reference-phases.md)**。在本仓库（a_technical_report_collection）中也可直接阅读 **`ebpf/cursor-ebpf-project-analysis-prompt-template.md`**（与 reference 内容一致，便于单一维护源）。
5. **补充维度**（按需）：在 reference 末尾的 **HIDS / 网络 / FIM / Rootkit** 四类补充提示中，按项目类型选用。
6. **产出物**：每阶段可要求保存为独立 Markdown；阶段八为综合报告。保存路径按用户仓库约定（如 `docs/`、`ebpf/`）。

## 阶段一览（用于编排）

| 阶段 | 主题 |
|------|------|
| 一 | 全局架构、目录、构建加载、依赖 |
| 二 | 全部 eBPF Hook 点全景与关系 |
| 三 | Maps 与数据流、内核过滤 |
| 四 | 用户空间、事件管线、策略与输出 |
| 五 | 核心功能深度分析（可定制关注项） |
| 六 | 安全与攻防对抗 |
| 七 | 性能与工程质量 |
| 八 | 综合技术报告 |

## 何时读取 reference

在开始某一阶段时，打开 **[reference-phases.md](reference-phases.md)** 中对应阶段的代码块，将其作为**用户可发送的提示词模板**（替换占位符后使用），并严格按其章节完成分析。
