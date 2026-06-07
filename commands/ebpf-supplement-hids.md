---
description: eBPF 项目分析 · 补充 · HIDS/运行时安全专项
argument-hint: <项目名>
---

针对 $1 项目，补充分析以下 HIDS 特定方面：

- 系统调用监控的覆盖范围（哪些 syscall 被监控？）
- 容器运行时感知机制（如何获取容器 ID、镜像名、Pod 信息？）
- 策略引擎的表达力和灵活性
- 是否支持内联执行/阻断（Kill / Override）？
- 与 Kubernetes 的集成方式（CRD / Webhook / Operator）
