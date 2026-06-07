# ebpf-project-analysis · 安装与生效

## 是什么

本目录为 **Claude Code Skill**（`SKILL.md` + `reference-phases.md`），内容来自仓库内 `ebpf/cursor-ebpf-project-analysis-prompt-template.md`。

## 项目内生效（本仓库已就绪）

将仓库克隆或拉取后，Claude Code 会读取 **项目根目录** 下的：

` .claude/skills/ebpf-project-analysis/ `

无需额外配置（以你方 `claude-internal` / Claude Code 版本是否支持 Skills 为准）。

## 全局生效（本机所有项目）

将整个目录复制到用户级 Skills 目录：

```bash
mkdir -p ~/.claude/skills
cp -R /path/to/a_technical_report_collection/.claude/skills/ebpf-project-analysis \
  ~/.claude/skills/
```

然后 **完全重启** Claude Code / `claude-internal`（或按内部文档操作），使 Skills 被重新加载。

## 与模板同步

- **权威模板**：`ebpf/cursor-ebpf-project-analysis-prompt-template.md`
- **Skill 内副本**：`reference-phases.md`（供全局目录离线使用）

修改分析流程时优先改模板，再同步更新 `reference-phases.md`（或重新 `cp`）。

## Cursor Agent Skills（可选）

若使用 **Cursor** 的 Agent Skills（非 Claude Code），对应目录为：

- 项目级：`.cursor/skills/ebpf-project-analysis/`（本仓库已复制一份）
- 全局：`~/.cursor/skills/ebpf-project-analysis/`

```bash
mkdir -p ~/.cursor/skills
cp -R /path/to/a_technical_report_collection/.cursor/skills/ebpf-project-analysis \
  ~/.cursor/skills/
```

勿写入 `~/.cursor/skills-cursor/`（该目录为 Cursor 内置保留）。
