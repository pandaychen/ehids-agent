---
description: eBPF 项目深度分析 · 阶段六 · 安全性与对抗分析
argument-hint: <项目名> <仓库 URL>
---

继续分析 $1 项目。

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
