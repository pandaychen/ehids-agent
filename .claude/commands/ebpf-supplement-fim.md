---
description: eBPF 项目分析 · 补充 · FIM 文件完整性专项
argument-hint: <项目名>
---

针对 $1 项目，补充分析以下 FIM 特定方面：

- 监控的文件操作类型（创建/修改/删除/读取/属性变更）
- 路径过滤机制（前缀匹配 / 正则 / inode）
- 是否支持递归目录监控？
- Who-data 能力（用户/进程上下文）
- 文件哈希和内容捕获能力
- 与 inotify / fanotify / auditd 的对比
- TOCTOU 攻击的防护能力
