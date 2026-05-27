# Skills and Claude workflow notes (2026-05-25)

Done — `~/canon/design/claude_three_layer_architecture_unhedged.{md,html}`. Hedged version stays in `~/Downloads/` as the prior artifact.

**On the `~/ai/claude` cleanup:** holding for your explicit go-ahead. The REORG report's plan still matches reality — same 15 items in `~/ai/claude/` today as on 2026-05-23. Ready to execute when you say.

**On Skills and right-way-to-use-Claude practices:**

What I see in your setup that's worth applying, given current workflow:

1. **Custom skills for repetitive structured artifacts.** You're hand-rolling memory pins each session (frontmatter + name slug + body + Connects-to graph). A `pin` skill would enforce structure and remove drift. Same for `lab-init` (scaffolds `labs/NNN_name/` with HYPOTHESIS/manifest/run/validate/RESULT) — directly supports the v-next lab discipline. And `memory-trim` for when MEMORY.md grows over 24KB (we did that by hand today).

2. **Project-level `CLAUDE.md` files.** You have a global `~/.claude/CLAUDE.md` with strong instructions. Per-project files in `forge/`, `mathabc/`, `tasc/` (or future `canon/<package>/`) would codify conventions specific to each — so parallel instances inherit the right context immediately instead of rediscovering it. Particularly load-bearing once the architecture is multi-package.

3. **Hooks for safety/convention.** A post-Write hook on `MEMORY.md` that warns when size exceeds 24KB would prevent the bloat we just cleaned. A pre-Edit hook on `main` branch in any repo that asks "did you mean to commit to a branch?" would enforce `feedback_branch_before_changes` automatically rather than relying on my recall.

4. **Plan mode for non-trivial work.** The `ExitPlanMode` tool exists; using it deliberately on architecture changes (instead of jumping to edits) gives you an approval step. The dev2 migration is a candidate for this pattern.

5. **Subagents in single session via `Agent` tool.** Different from parallel-instance pattern — these are scoped helpers inside one conversation (e.g., `Explore` for codebase research, `Plan` for design steps). Useful when a topic deserves isolated context.

Want me to spin up the `claude-code-guide` agent for a thorough survey of Skills/hooks/MCP patterns specifically tailored to your workflow? Or would you prefer I just propose 2-3 specific skill drafts (e.g., `pin`, `lab-init`, `memory-trim`) and you decide which to install?
