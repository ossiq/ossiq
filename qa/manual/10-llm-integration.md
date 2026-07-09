# 10 — LLM Integration: `install skills` & MCP Server

Covers the AI-tool integration surface: the `install skills` command (skill file + MCP
registration for Claude Code / Codex / Copilot), the stdio MCP server, and the agent
JSON contract documented in `SKILL.md`.

Run from repo root. MCP `tools/call` and agent-format tests require network (registry lookups).

**Warning:** `install skills` writes to your real `~/.claude`, `~/.codex`, `~/.copilot`,
and `~/.ossiq/config`. Back up `~/.claude/mcp.json` and `~/.ossiq/config` before testing,
or point `HOME` at a scratch dir for TC-L02–TC-L04.

**Precondition:**

```bash
uv run hatch run ossiq-cli install --help
uv run hatch run ossiq-cli install skills --help
```

- [ ] `install --help` lists the `skills` subcommand
- [ ] `install skills --help` lists `--github-token` / `-T` and `--dev`

---

## TC-L01: `install skills` argument validation

```bash
uv run hatch run ossiq-cli install skills bogus-tool
echo "exit: $?"
```

- [ ] Clean error naming valid choices (`claude, codex, copilot, all`); no traceback
- [ ] Exit code is non-zero

---

## TC-L02: `install skills claude --dev` writes skill and merges MCP config

```bash
uv run hatch run ossiq-cli install skills claude --dev "$(pwd)"
# press Enter at the token prompt to skip
cat ~/.claude/skills/ossiq/SKILL.md | head -10
cat ~/.claude/mcp.json
```

- [ ] `~/.claude/skills/ossiq/SKILL.md` exists with the `ossiq-dependency-check` frontmatter
- [ ] Skill body references `uvx --from <repo-path> --no-cache ossiq-cli` (dev path substituted, no `uvx --from ossiq`)
- [ ] `~/.claude/mcp.json` has `mcpServers.ossiq` with `command: "uv"` and the repo path in `args`
- [ ] Pre-existing entries in `mcpServers` are preserved (add a dummy entry first to verify)
- [ ] Re-running the command is idempotent — still exactly one `ossiq` entry

---

## TC-L03: GitHub token storage

```bash
uv run hatch run ossiq-cli install skills claude --github-token ghp_qa_test --dev "$(pwd)"
grep OSSIQ_GITHUB_TOKEN ~/.ossiq/config
cat ~/.claude/mcp.json
```

- [ ] `~/.ossiq/config` contains `OSSIQ_GITHUB_TOKEN=ghp_qa_test`
- [ ] `mcpServers.ossiq.env.OSSIQ_GITHUB_TOKEN` is `ghp_qa_test`
- [ ] Without `--github-token`, an interactive prompt appears; blank input skips both writes
- [ ] Remove the test token from `~/.ossiq/config` afterwards

---

## TC-L04: Copilot instructions block is idempotent

```bash
uv run hatch run ossiq-cli install skills copilot
uv run hatch run ossiq-cli install skills copilot
grep -c "ossiq-skill:start" ~/.copilot/copilot-instructions.md
```

- [ ] After two runs, exactly one `<!-- ossiq-skill:start -->` block
- [ ] Content outside the ossiq markers (pre-existing user instructions) is untouched

---

## TC-L05: MCP handshake — initialize & tools/list over stdio

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | uv run hatch run ossiq-cli mcp
```

- [ ] Exactly two response lines (the notification gets no reply), each valid JSON
- [ ] Response 1: `serverInfo.name` is `ossiq`, `capabilities.tools` present
- [ ] Response 2: tools list contains `ossiq_evaluate_dependency` and `ossiq_evaluate_updates`
- [ ] Nothing except JSON-RPC on stdout (no progress/log lines)

---

## TC-L06: MCP `tools/call` — evaluate a dependency (network)

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ossiq_evaluate_dependency","arguments":{"package":"requests","project_path":"testdata/pypi/uv"}}}' \
  | uv run hatch run ossiq-cli mcp
```

- [ ] Response 2 has `result.content[0].text` containing a JSON verdict with `"operation": "add"`, `verdict` in ok/warn/block, `recommended_version`, `cves`, `warnings`
- [ ] No `isError` on the result
- [ ] Unknown package (e.g. `definitely-not-a-real-pkg-xyz`) returns `isError: true` with a message — the server stays alive, no crash

---

## TC-L07: MCP `tools/call` — evaluate updates (network)

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ossiq_evaluate_updates","arguments":{"project_path":"testdata/pypi/version-constraint"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}' \
  | uv run hatch run ossiq-cli mcp
```

- [ ] Response 2 verdict JSON has `"operation": "update"` and an `updates` array with `package`, `from`, `to`, `verdict` per entry
- [ ] Response 3 (unknown tool) has `isError: true`; server answered it rather than crashing

---

## TC-L08: Agent format CLI — the SKILL.md contract (network)

The skill instructs agents to call these when no MCP server is connected:

```bash
uv run hatch run ossiq-cli info requests testdata/pypi/uv --format agent | python3 -m json.tool
uv run hatch run ossiq-cli status testdata/pypi/version-constraint --format agent | python3 -m json.tool
```

- [ ] `info --format agent` output is valid JSON with `operation: "add"`, `verdict`, `recommended_version`, `reasons`, `cves`, `warnings` (matches the SKILL.md example)
- [ ] `status --format agent` output is valid JSON with `operation: "update"` and `updates` list
- [ ] Output is pure JSON — no tables, spinners, or progress text mixed in

---

## TC-L09: Live agent smoke test (optional)

After TC-L02, in a fresh Claude Code session in any project:

- [ ] `/mcp` shows the `ossiq` server connected; its two tools are listed
- [ ] The `ossiq` skill appears in the skills list
- [ ] Prompt "check if it's safe to add left-pad to this project" — the agent invokes the skill or MCP tool and reports a verdict
