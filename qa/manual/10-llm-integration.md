# 10 — LLM Integration: `install skills` & MCP Server

Covers the AI-tool integration surface: the `install skills` command (skill file + MCP
registration for Claude Code / Codex / Copilot), the stdio MCP server, and the agent
JSON contract documented in `SKILL.md`.

Run from repo root. MCP `tools/call` and agent-format tests require network (registry lookups).

**Warning:** `install skills` writes to your real `~/.claude`, `~/.codex` and `~/.copilot`.
Back up `~/.claude/mcp.json` before testing, or point `HOME` at a scratch dir for TC-L02–TC-L04 (TC-L11 and TC-L12 do this themselves).

**Log in first** (`uv run ossiq auth login`) or set `OSSIQ_GITHUB_AUTH=off` for TC-L05–TC-L09.
Otherwise the first `tools/call` returns the login challenge (TC-L10), and the CLI cases stop to
show a login code.

**Precondition:**

```bash
uv run hatch run ossiq install --help
uv run hatch run ossiq install skills --help
```

- [ ] `install --help` lists the `skills` subcommand
- [ ] `install skills --help` lists `--dev` and `--via` and says no GitHub token is asked for or stored; it does
      not list `--github-token`

---

## TC-L01: `install skills` argument validation

```bash
uv run hatch run ossiq install skills bogus-tool
echo "exit: $?"
```

- [ ] Clean error naming valid choices (`claude, codex, copilot, all`); no traceback
- [ ] Exit code is non-zero

---

## TC-L02: `install skills claude --dev` writes skill and merges MCP config

```bash
uv run hatch run ossiq install skills claude --dev "$(pwd)"
cat ~/.claude/skills/ossiq/SKILL.md | head -10
cat ~/.claude/mcp.json
```

- [ ] `~/.claude/skills/ossiq/SKILL.md` exists with the `ossiq-dependency-check` frontmatter
- [ ] Skill body references `uvx --from <repo-path> --no-cache ossiq` (dev path substituted, no `uvx --from ossiq`, no `{{ossiq}}` left)
- [ ] `~/.claude/mcp.json` has `mcpServers.ossiq` with `command: "uv"` and the repo path in `args`
- [ ] Pre-existing entries in `mcpServers` are preserved (add a dummy entry first to verify)
- [ ] Re-running the command is idempotent — still exactly one `ossiq` entry

---

## TC-L03: `install skills` stores no token

```bash
uv run hatch run ossiq install skills claude --dev "$(pwd)"
cat ~/.claude/mcp.json
```

- [ ] The command asks for no token and prints `uvx --from <repo-path> --no-cache ossiq auth login` as the next step
- [ ] `mcpServers.ossiq` has no `env` block holding `OSSIQ_GITHUB_TOKEN`
- [ ] `~/.config/ossiq/config` (if present) gained no `OSSIQ_GITHUB_TOKEN` line

---

## TC-L04: Copilot instructions block is idempotent

```bash
uv run hatch run ossiq install skills copilot
uv run hatch run ossiq install skills copilot
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
  | uv run hatch run ossiq mcp
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
  | uv run hatch run ossiq mcp
```

- [ ] Response 2 has `result.content[0].text` containing a JSON decision with `"operation": "add"`, `next_action` in install / install with caution / do not install, `recommended_version`, `cves`, `warnings`
- [ ] No `isError` on the result
- [ ] Unknown package (e.g. `definitely-not-a-real-pkg-xyz`) returns `isError: true` with a message — the server stays alive, no crash

---

## TC-L07: MCP `tools/call` — evaluate updates (network)

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ossiq_evaluate_updates","arguments":{"project_path":"testdata/pypi/version-constraint"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}' \
  | uv run hatch run ossiq mcp
```

- [ ] Response 2 decision JSON has `"operation": "update"`, a top-level `next_action`, and an `updates` array with `package`, `next_action`, `from`, `to` per entry
- [ ] Response 3 (unknown tool) has `isError: true`; server answered it rather than crashing

---

## TC-L08: Agent format CLI — the SKILL.md contract (network)

The skill instructs agents to call these when no MCP server is connected:

```bash
uv run hatch run ossiq info requests testdata/pypi/uv --format agent | python3 -m json.tool
uv run hatch run ossiq status testdata/pypi/version-constraint --format agent | python3 -m json.tool
```

- [ ] `info --format agent` output is valid JSON with `operation: "add"`, `next_action`, `recommended_version`, `reasons`, `cves`, `warnings` (matches the SKILL.md example)
- [ ] `status --format agent` output is valid JSON with `operation: "update"`, a top-level `next_action`, and an `updates` list where each entry has a `next_action`
- [ ] Output is pure JSON — no tables, spinners, or progress text mixed in

---

## TC-L09: Live agent smoke test (optional)

After TC-L02, in a fresh Claude Code session in any project:

- [ ] `/mcp` shows the `ossiq` server connected; its two tools are listed
- [ ] The `ossiq` skill appears in the skills list
- [ ] Prompt "check if it's safe to add left-pad to this project" — the agent invokes the skill or MCP tool and reports a decision

---

## TC-L10: MCP login challenge (network, GitHub account)

Start logged out, with no token in the environment:

```bash
unset CI OSSIQ_GITHUB_TOKEN GITHUB_TOKEN OSSIQ_GITHUB_AUTH
uv run ossiq auth logout
uv run hatch run ossiq mcp
```

The server reads stdin until it closes. Paste these lines one at a time, and read each response
before the next:

```text
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ossiq_evaluate_dependency","arguments":{"package":"requests","project_path":"testdata/pypi/uv"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ossiq_evaluate_dependency","arguments":{"package":"requests","project_path":"testdata/pypi/uv"}}}
```

Approve the code on GitHub, then paste the `id` 3 line again with `"id":4`.

- [ ] Response 2 has `isError: false`, `_meta.auth_status: "PENDING_USER_ACTION"`, `verification_uri`
      and `user_code`; the text tells the agent to show the code, wait, and call the tool again
- [ ] No response contains a `device_code`
- [ ] Response 3 (before approval) carries the **same** `user_code`, with a smaller `expires_in`
- [ ] Response 4 (after approval) is the normal add decision; `uv run ossiq auth status` shows the login
- [ ] stdout holds one JSON object per line throughout

---

## TC-L11: The skill runs ossiq the way `install skills` ran

```bash
SCRATCH=$(mktemp -d)
HOME=$SCRATCH uv run ossiq install skills claude
grep -n "auth login\|--format agent" $SCRATCH/.claude/skills/ossiq/SKILL.md
cat $SCRATCH/.claude/mcp.json
HOME=$SCRATCH uv run ossiq install skills claude --via npx
grep -n "auth login\|--format agent\|uvx" $SCRATCH/.claude/skills/ossiq/SKILL.md
cat $SCRATCH/.claude/mcp.json
HOME=$SCRATCH uv run ossiq install skills claude --via ossiq
cat $SCRATCH/.claude/mcp.json
HOME=$SCRATCH uv run ossiq install skills claude --via npx --dev "$(pwd)"; echo "exit: $?"
```

- [ ] Default run prints `the skill runs ossiq as: uvx ossiq`; every matched line reads `uvx ossiq …`;
      `mcpServers.ossiq` is `<path to uvx>` with `args: ["ossiq", "mcp"]`
- [ ] `--via npx` prints `the skill runs ossiq as: npx --yes @ossiq/cli`; every matched line reads
      `npx --yes @ossiq/cli …` and no line mentions `uvx`; `mcpServers.ossiq` is `<path to npx>` with
      `args: ["--yes", "@ossiq/cli", "mcp"]`
- [ ] `--via ossiq` writes bare `ossiq …` commands and an absolute path to the `ossiq` binary in
      `mcpServers.ossiq`
- [ ] `--via` together with `--dev` exits 1 with "cannot be combined" and changes nothing

---

## TC-L12: An npm install writes npx commands (released package, network)

Run after the release is approved on npm, on macOS, Linux and Windows if you can.

```bash
SCRATCH=$(mktemp -d)
HOME=$SCRATCH npx --yes @ossiq/cli@X.Y.Z install skills claude
grep -n "auth login\|--format agent\|uvx" $SCRATCH/.claude/skills/ossiq/SKILL.md
cat $SCRATCH/.claude/mcp.json
```

- [ ] Prints `the skill runs ossiq as: npx --yes @ossiq/cli`
- [ ] Every matched line reads `npx --yes @ossiq/cli …`; no line mentions `uvx`
- [ ] `mcpServers.ossiq` is `<path to npx> --yes @ossiq/cli mcp` (Windows: `cmd /c npx --yes @ossiq/cli mcp`),
      not a path inside the `_npx` cache
