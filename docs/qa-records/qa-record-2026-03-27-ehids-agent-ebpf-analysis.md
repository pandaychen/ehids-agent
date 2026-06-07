# ehids-agent 项目深度分析 - 技术对话记录

> 日期：2026-03-27 ~ 2026-03-30
> 会话主题：使用 eBPF Skills 全阶段深度分析 ehids-agent HIDS 项目
> 参与方：用户（pandaychen）+ Claude Code（Opus 4.6）

---

## 会话概要

本次会话围绕美团安全团队开源的 ehids-agent eBPF HIDS 项目进行了完整的 **8 阶段 + 1 补充专项**技术深度分析。过程中使用了项目内配置的 10 个 eBPF 分析 Skills，通过 6 个并行 Agent 实现高效分析，最终产出 13 个技术文档（共 9,000+ 行 / ~400KB+）。同时为用户编写了 Skills 使用提示词指南，并将 Skills 部署到全局目录实现跨项目复用。最后新增了 `save-qa-record` Skill 用于保存对话记录。

---

## 使用的工具 / Skills

### Skills 调用清单

| # | Skill 名称 | 调用方式 | 产出文件 |
|---|-----------|---------|---------|
| 1 | `ebpf-project-analysis` | 手动触发 `/ebpf-project-analysis` | 加载 Skill 上下文 |
| 2 | `ebpf-phase1-architecture` | 手动触发 `/ebpf-phase1-architecture` | `ehids-agent-phase1-architecture.md` |
| 3 | `ebpf-phase2-hooks` | Agent 后台执行 | `ehids-agent-phase2-hooks.md` |
| 4 | `ebpf-phase3-maps` | Agent 后台执行 | `ehids-agent-phase3-maps.md` |
| 5 | `ebpf-phase4-userspace` | Agent 后台执行 | `ehids-agent-phase4-userspace.md` |
| 6 | `ebpf-phase5-features` | Agent 后台执行（拆分为 Part1+Part2） | `ehids-agent-phase5-features.md` |
| 7 | `ebpf-phase6-security` | Agent 后台执行 | `ehids-agent-phase6-security.md` |
| 8 | `ebpf-phase7-quality` | Agent 后台执行 | `ehids-agent-phase7-quality.md` |
| 9 | `ebpf-phase8-report` | Agent 后台执行 | `ehids-agent-深度技术分析-2026-03-27.md` |
| 10 | `ebpf-supplement-hids` | Agent 后台执行 | `ehids-agent-supplement-hids.md` |

### 其他工具使用

- **Agent (Explore)**：初始项目探索，读取全部源码文件
- **Agent (general-purpose)**：8 个后台 Agent 并行执行分析任务
- **Bash**：目录操作、文件合并、统计
- **Read / Grep / Glob**：源码阅读和交叉验证（`grep SEC(` 验证 Hook 点等）
- **Write**：生成文档文件
- **TaskCreate / TaskUpdate / TaskList**：任务进度追踪

---

## 详细对话记录

### Q1: 告诉我你加载了哪些 Skill

**用户提问：**
> 告诉我你加载了哪些 skill

**分析过程：**
检查系统加载的 Skill 列表。

**结论/输出：**
列出了全部 17 个已加载 Skills：
- 通用工具类 4 个：`update-config`、`simplify`、`loop`、`claude-api`
- eBPF 深度分析系列 8 个：`ebpf-phase1-architecture` ~ `ebpf-phase8-report`
- eBPF 补充专项 4 个：`ebpf-supplement-network`、`ebpf-supplement-fim`、`ebpf-supplement-hids`、`ebpf-supplement-rootkit`
- 总入口 1 个：`ebpf-project-analysis`

---

### Q2: 帮我详细从开发专业角度分析/拆解这个项目的实现，保存为技术文档

**用户提问：**
> 帮我详细从开发专业角度，分析/拆解下这个项目的实现，保存为技术文档

**分析过程：**
1. 使用 `Bash` 查看项目目录结构和 git 历史
2. 启动 `Agent (Explore)` 全面探索项目，读取所有关键源码文件：
   - `main.go`（入口）
   - `kern/*.c`（7 个 eBPF 内核态 C 文件）
   - `user/*.go`（21 个用户态 Go 文件）
   - `go.mod`（依赖）
   - `Makefile`（构建脚本）
3. 基于读取结果撰写 15 章节的技术分析文档

**结论/输出：**
生成 `ehids-agent-technical-analysis.md`（54KB），包含：
- 项目概览、目录结构、构建系统、依赖分析
- 总体架构设计（分层图）
- 核心接口与设计模式（模板方法、策略、工厂、适配器）
- 7 个内核态探针详解（数据结构 + 关键代码逻辑）
- 用户态模块详解（注册机制、加载流程、事件解码链）
- 端到端数据流分析
- 关键实现技巧（栈限制规避、HashMap 状态追踪等）
- CO-RE 机制、资源打包、性能约束、应用场景

⚠️ **此次分析未使用任何 eBPF Skills**，而是直接通过 Explore Agent + 手动撰写完成。

---

### Q3: 你在分析中使用了哪些 Skill 的技能？

**用户提问：**
> 你在分析中，使用了哪些 skill 的技能，请详细的列出来

**分析过程：**
回顾 Q2 的分析过程。

**结论/输出：**
坦诚说明 Q2 中**没有调用任何 Skill**，仅使用了 Agent (Explore)、Bash、Write 等通用工具。列出了本可以使用但未使用的 10 个 eBPF Skills，并建议用户如果需要更系统更深入的分析，可以逐阶段调用这些 Skills。

---

### Q4: 需要使用 Skills 重新分析，并给我一份 Skills 使用提示词

**用户提问：**
> 需要，另外请给我一份用到我 skills 的提示词

**分析过程：**
1. 调用 `/ebpf-project-analysis` 加载 Skill 上下文
2. 读取 `reference-phases.md` 了解完整的 8 阶段提示词模板
3. 编写 Skills 使用提示词指南文档
4. 调用 `/ebpf-phase1-architecture` 启动阶段一分析
5. 读取所有源码文件（`main.go`、7 个 C 文件、`imodule.go`、`ievent.go`、`register.go`、`common.go`、`ehids_agent.h`、`common.h`、`Makefile`、`go.mod`）
6. 启动 Explore Agent 读取所有 `probe_*.go` 和 `event_*.go` 文件
7. 撰写阶段一完整文档

**结论/输出：**

**产出 1**：`skills-usage-guide.md`（484 行 / 13KB）
- 17 个 Skills 全景表
- 8 个阶段的完整触发提示词模板
- 4 个补充专项的触发提示词
- 4 个通用工具类 Skills 使用方法
- 使用技巧和注意事项

**产出 2**：`ehids-agent-phase1-architecture.md`（706 行 / 33KB）
- 整体架构图（Mermaid）
- 6 层分层架构图
- 9 个 BPF 程序入口清单（`grep SEC(` 交叉验证）
- 完整构建流水线（3 阶段）
- CO-RE vs NOCORE 双模式对比
- 依赖库 + 内核特性依赖矩阵
- vmlinux.h 头文件引用关系图
- 逐文件分析表（7 个 C + 21 个 Go）
- 架构优势 / 待改进点 / 技术亮点总结

---

### Q5: 继续使用剩下的 eBPF Skills 完成所有分析

**用户提问：**
> 继续使用剩下的 ebpf skills 完成所有分析

**分析过程：**
采用**最大并行策略**：
1. 创建 8 个任务（阶段二~八 + HIDS 专项），设置依赖关系（阶段八依赖二~七，HIDS 依赖阶段八）
2. 同时启动 **6 个后台 Agent** 并行执行阶段二~七
3. 各 Agent 完成情况：
   - 阶段三最先完成（243s）：16 个 Map，6 种类型，内存约 18MB
   - 阶段六完成（230s）：覆盖约 10 个 ATT&CK 技术，缺失 execve 监控
   - 阶段四完成（290s）：Close() 未调用、readEvents() 永久阻塞等问题
   - 阶段二完成（307s）：9 个 Hook 点，DNS 双层监控
   - 阶段七完成（274s）：综合评分 3.2/10，PerfEvent buffer 仅 4KB
   - **阶段五超时**（3543s）：任务过大，拆分重做
4. 阶段五拆分为 Part1（功能 1-4）+ Part2（功能 5-7）两个 Agent 并行执行
   - Part1 完成（293s）：进程/TCP/DNS/UDP 4 个功能
   - Part2 完成（306s）：Socket/Java/BPF 3 个功能
   - 合并为完整的 `ehids-agent-phase5-features.md`（1723 行 / 70KB）
5. 阶段二~七全部完成后，并行启动阶段八和 HIDS 专项
   - HIDS 专项完成（280s）：系统调用覆盖率仅 ~15%
   - 阶段八完成（334s）：综合报告 10 章节

**结论/输出：**

| 阶段 | 文件 | 行数 | 大小 | 关键发现 |
|------|------|------|------|---------|
| 阶段二 | `ehids-agent-phase2-hooks.md` | 831 | 39K | 9 个 Hook，两组 entry/return 配对，Java RASP 最高 ABI 风险 |
| 阶段三 | `ehids-agent-phase3-maps.md` | 586 | 27K | 16 个 Map，`make_event()` 堆分配是亮点，内存约 18MB |
| 阶段四 | `ehids-agent-phase4-userspace.md` | 824 | 35K | Close() 未调用、readEvents() 阻塞、IClose 未使用 |
| 阶段五 | `ehids-agent-phase5-features.md` | 1723 | 70K | 7 功能逐个走读，发现 Decode 偏移错位、rport 字节序等 Bug |
| 阶段六 | `ehids-agent-phase6-security.md` | 388 | 21K | ATT&CK 覆盖约 15%，12 种绕过方式，零自我保护 |
| 阶段七 | `ehids-agent-phase7-quality.md` | 477 | 23K | 评分 3.2/10，PerfEvent 4KB 致命瓶颈，debug 始终启用 |
| 阶段八 | `ehids-agent-深度技术分析-2026-03-27.md` | 504 | 31K | 10 章节综合报告，20 条改进建议（P0×4/P1×7/P2×9） |
| HIDS | `ehids-agent-supplement-hids.md` | 810 | 31K | syscall 覆盖 ~15%，缺 execve/openat/ptrace，零阻断能力 |

---

### Q6: 当前项目的 Skills 在哪个位置？

**用户提问：**
> 当前项目的 skills 在那个位置，告诉我路径

**分析过程：**
使用 `find` 搜索所有 skill 相关文件。

**结论/输出：**
Skills 存放在两个位置（互为副本）：
1. **Claude Code 生效位置**：`/Users/pandaychen/claude-code/ebpf/ehids-agent/.claude/skills/ebpf-project-analysis/`
2. **项目根目录副本**：`/Users/pandaychen/claude-code/ebpf/ehids-agent/skills/ebpf-project-analysis/`

每个目录包含 3 个文件：`SKILL.md`、`reference-phases.md`、`README.md`

---

### Q7: 要分析其他项目，最快的复用 Skills 的方法

**用户提问：**
> 我现在要使用你分析其他项目，最快的复用 skills 的方法给我

**分析过程：**
将 Skills 复制到全局目录 `~/.claude/skills/`。

**结论/输出：**
执行了：
```bash
cp -r .claude/skills/ebpf-project-analysis/ ~/.claude/skills/ebpf-project-analysis/
```
之后在任何项目中启动 Claude Code 都可以直接使用这 10 个 eBPF 分析 Skills。

---

### Q8: 增加一个保存对话记录的 Skill，全局生效

**用户提问：**
> 需要增加一个 skill，在项目中保存我们直接的详细的对话（qa）记录，请更新至全局生效

**分析过程：**
在 `~/.claude/skills/save-qa-record/` 创建 `SKILL.md`。

**结论/输出：**
创建了 `~/.claude/skills/save-qa-record/SKILL.md`，定义了：
- 触发方式：`保存对话记录` / `保存QA` / `记录下来` / `存档`
- 文件名格式：`qa-record-YYYY-MM-DD-[主题].md`
- 默认保存路径：项目 `docs/qa-records/`
- 文档结构：会话概要 → Skills 清单 → 逐轮 QA → 产物清单 → 待办

当前全局 Skills：
```
~/.claude/skills/
├── ebpf-project-analysis/    # eBPF 项目分析
└── save-qa-record/           # 对话记录保存
```

---

### Q9: 保存对话记录

**用户提问：**
> 保存对话记录

**分析过程：**
尝试调用 `/save-qa-record` Skill（因需新会话加载未生效），改为手动按 Skill 定义的格式执行。回溯整个会话历史，结构化整理。

**结论/输出：**
即本文档。

---

## 生成的产物清单

| # | 文件名 | 类型 | 大小 | 说明 |
|---|--------|------|------|------|
| 1 | `ehids-agent-technical-analysis.md` | 技术文档 | 54K | 初始分析（未用 Skills） |
| 2 | `skills-usage-guide.md` | 使用指南 | 13K | 17 个 Skills 使用提示词 |
| 3 | `ehids-agent-phase1-architecture.md` | 分析文档 | 33K | 阶段一：全局架构拆解 |
| 4 | `ehids-agent-phase2-hooks.md` | 分析文档 | 39K | 阶段二：Hook 点全景分析 |
| 5 | `ehids-agent-phase3-maps.md` | 分析文档 | 27K | 阶段三：Maps 与数据流分析 |
| 6 | `ehids-agent-phase4-userspace.md` | 分析文档 | 35K | 阶段四：用户空间处理逻辑 |
| 7 | `ehids-agent-phase5-features.md` | 分析文档 | 70K | 阶段五：核心功能深度分析（7 个功能） |
| 8 | `ehids-agent-phase5-features-part1.md` | 分析文档 | 32K | 阶段五上半（功能 1-4） |
| 9 | `ehids-agent-phase5-features-part2.md` | 分析文档 | 38K | 阶段五下半（功能 5-7） |
| 10 | `ehids-agent-phase6-security.md` | 分析文档 | 21K | 阶段六：安全性与对抗分析 |
| 11 | `ehids-agent-phase7-quality.md` | 分析文档 | 23K | 阶段七：性能与工程质量 |
| 12 | `ehids-agent-深度技术分析-2026-03-27.md` | 综合报告 | 31K | 阶段八：综合技术报告 |
| 13 | `ehids-agent-supplement-hids.md` | 专项分析 | 31K | HIDS 补充专项 |
| 14 | `~/.claude/skills/save-qa-record/SKILL.md` | Skill 定义 | 2.4K | 新增全局 Skill |

**总产出**：14 个文件，约 9,500 行 / ~450KB

---

## 核心技术结论摘要

### ehids-agent 项目评估

| 维度 | 评分 | 说明 |
|------|------|------|
| **架构设计** | ⭐⭐⭐⭐ | 模块化 IModule 接口 + init() 注册 + CO-RE 双模式，设计优秀 |
| **内核态实现** | ⭐⭐⭐ | `make_event()` 堆分配、TCP 状态机追踪等技巧值得学习，但缺 execve |
| **用户态实现** | ⭐⭐ | 模板方法框架好，但 Close() 未调用、readEvents() 阻塞、无配置系统 |
| **工程质量** | ⭐⭐ | 零测试、零文档、PerfEvent 4KB buffer、debug 始终开启 |
| **安全覆盖** | ⭐⭐ | ATT&CK 覆盖 ~15%，与 Falco/Tetragon/Tracee 存在代际差距 |
| **综合评分** | **3.2/10** | 定位为优秀的 eBPF HIDS 教学/PoC 项目 |

### 最关键的 4 个改进建议（P0）

1. **添加 execve 监控**：tracepoint/syscalls/sys_enter_execve，HIDS 最基础能力
2. **PerfEvent buffer 扩大到 256KB+**：当前 4KB 高负载丢 99%+ 事件
3. **修复 readEvents() 阻塞**：导致 context 取消无法传播
4. **关闭 `bpf_call_kern.c` 的 `print_debug()`**：`#if 1` 改为 `#if 0`

---

## 后续待办

- [ ] 将 eBPF Skills 应用到下一个目标项目进行分析
- [ ] `save-qa-record` Skill 在新会话中验证是否自动加载生效
- [ ] 考虑为 ehids-agent 提交 PR 修复 P0 级别问题
- [ ] 考虑增加更多 eBPF 补充专项 Skills（如 `ebpf-supplement-performance` 性能调优专项）
