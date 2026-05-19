# Skill Registry — NetSentinelAI

Generated: 2026-05-19

## Project Conventions

| File | Purpose |
|------|---------|
| `CLAUDE.md` (global) | Agent orchestrator rules, SDD workflow |
| `~/.claude/CLAUDE.md` | Global personality, language, memory protocol |

## User Skills

| Skill | Trigger | Path |
|-------|---------|------|
| `sdd-explore` | `/sdd-explore`, explore idea, investigate feature | `~/.claude/skills/sdd-explore/SKILL.md` |
| `sdd-propose` | `/sdd-propose`, create proposal | `~/.claude/skills/sdd-propose/SKILL.md` |
| `sdd-spec` | `/sdd-spec`, write spec, write requirements | `~/.claude/skills/sdd-spec/SKILL.md` |
| `sdd-design` | `/sdd-design`, write design, architecture doc | `~/.claude/skills/sdd-design/SKILL.md` |
| `sdd-tasks` | `/sdd-tasks`, break down tasks | `~/.claude/skills/sdd-tasks/SKILL.md` |
| `sdd-apply` | `/sdd-apply`, implement tasks, write code | `~/.claude/skills/sdd-apply/SKILL.md` |
| `sdd-verify` | `/sdd-verify`, validate implementation | `~/.claude/skills/sdd-verify/SKILL.md` |
| `sdd-archive` | `/sdd-archive`, archive change | `~/.claude/skills/sdd-archive/SKILL.md` |
| `sdd-onboard` | `/sdd-onboard`, learn SDD workflow | `~/.claude/skills/sdd-onboard/SKILL.md` |
| `branch-pr` | create PR, pull request, open PR | `~/.claude/skills/branch-pr/SKILL.md` |
| `issue-creation` | create issue, report bug, feature request | `~/.claude/skills/issue-creation/SKILL.md` |
| `judgment-day` | judgment day, adversarial review, dual review | `~/.claude/skills/judgment-day/SKILL.md` |
| `go-testing` | Go tests, Bubbletea TUI testing | `~/.claude/skills/go-testing/SKILL.md` |
| `skill-creator` | create new skill, add agent instructions | `~/.claude/skills/skill-creator/SKILL.md` |
| `context7-mcp` | library docs, framework API reference | `~/.claude/skills/context7-mcp/SKILL.md` |

## Compact Rules

### Python ML Project (netsentinelai)

- **Test runner**: `python -m pytest tests/ -v`
- **No linter** configured — follow existing code style (4-space indent, docstrings on classes/public methods)
- **No type checker** — add type hints to new public functions only
- **Dependency management**: add to `requirements.txt` (no pinned versions, use `>=`)
- **Module separation**: training (main.py, train_and_compare.py) NEVER imports from inference/live modules; inference (inference_pipeline.py) NEVER imports training code
- **Thread safety**: all shared state in Scapy callback path must use `threading.Lock`
- **Feature vectors**: always use `align_features()` from `feature_schema.py` before calling any scaler/model
- **CIC-IDS2017 units**: Flow Duration in microseconds, IAT in microseconds, bytes as-is
- **No inline ML prediction** — always delegate to `InferencePipeline` via `ml_engine` shim
