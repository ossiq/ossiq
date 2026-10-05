"""Tests for the `install skills` command."""

import json
import re
from pathlib import PurePosixPath, PureWindowsPath

import pytest
from typer.testing import CliRunner

from ossiq.cli import app
from ossiq.commands import install
from ossiq.commands.install import Invocation, Runner

SKILL_CONTENT = "# ossiq skill\nbody\n"
MCP_ENTRY = {"command": "/usr/local/bin/ossiq", "args": ["mcp"]}
OLD_TOKEN_ENTRY = {"command": "ossiq", "args": ["mcp"], "env": {"OSSIQ_GITHUB_TOKEN": "ghp_old_secret"}}

NPX_CACHE = PurePosixPath("/Users/dev/.npm/_npx/96e567c458e7803e/node_modules/@ossiq/cli-darwin-arm64/bin/ossiq/ossiq")
NPM_GLOBAL = PurePosixPath(
    "/opt/homebrew/lib/node_modules/@ossiq/cli/node_modules/@ossiq/cli-darwin-arm64/bin/ossiq/ossiq"
)
NPM_LOCAL = PurePosixPath("/home/dev/app/node_modules/@ossiq/cli-linux-x64/bin/ossiq/ossiq")
PNPM = PurePosixPath(
    "/home/dev/app/node_modules/.pnpm/@ossiq+cli-linux-x64@0.1.14/node_modules/@ossiq/cli-linux-x64/bin/ossiq/ossiq"
)
NPM_WINDOWS = PureWindowsPath(
    r"C:\Users\dev\AppData\Roaming\npm\node_modules\@ossiq\cli\node_modules\@ossiq\cli-win32-x64\bin\ossiq\ossiq.exe"
)


def use_home(tmp_path, monkeypatch):
    monkeypatch.setattr(install.Path, "home", classmethod(lambda cls: tmp_path))


def which_finds(monkeypatch, **found: str):
    monkeypatch.setattr(install.shutil, "which", lambda name: found.get(name))


@pytest.mark.parametrize("executable", [NPX_CACHE, NPM_GLOBAL, NPM_LOCAL, PNPM, NPM_WINDOWS])
def test_a_binary_from_any_npm_layout_runs_through_npx(executable):
    assert install.is_npm_binary(executable)
    assert install.detect_runner(executable, frozen=True, uvx_available=True) is Runner.NPX


@pytest.mark.parametrize(
    "executable",
    [PurePosixPath("/usr/local/bin/ossiq"), PurePosixPath("/home/dev/app/node_modules/other/bin/ossiq/ossiq")],
)
def test_a_standalone_binary_runs_as_bare_ossiq(executable):
    assert not install.is_npm_binary(executable)
    assert install.detect_runner(executable, frozen=True, uvx_available=True) is Runner.OSSIQ


def test_a_python_install_runs_through_uvx_when_uv_is_there():
    python = PurePosixPath("/Users/dev/.cache/uv/archive-v0/MFvk8Fo1OonRHFTC/bin/python")
    assert install.detect_runner(python, frozen=False, uvx_available=True) is Runner.UVX
    assert install.detect_runner(python, frozen=False, uvx_available=False) is Runner.OSSIQ


def test_uvx_invocation_keeps_the_path_entry_rather_than_its_symlink_target(tmp_path, monkeypatch):
    target = tmp_path / "Cellar" / "uv" / "0.12.10" / "bin" / "uvx"
    target.parent.mkdir(parents=True)
    target.touch()
    link = tmp_path / "bin" / "uvx"
    link.parent.mkdir()
    link.symlink_to(target)
    which_finds(monkeypatch, uvx=str(link))

    invocation = install.resolve_invocation(Runner.UVX)

    assert invocation.skill_command == "uvx ossiq"
    assert invocation.mcp_entry() == {"command": str(link), "args": ["ossiq", "mcp"]}


def test_npx_invocation(monkeypatch):
    which_finds(monkeypatch, npx="/usr/local/bin/npx")
    monkeypatch.setattr(install.sys, "platform", "linux")

    invocation = install.resolve_invocation(Runner.NPX)

    assert invocation.skill_command == "npx --yes @ossiq/cli"
    assert invocation.mcp_entry() == {"command": "/usr/local/bin/npx", "args": ["--yes", "@ossiq/cli", "mcp"]}


def test_npx_invocation_on_windows_goes_through_cmd(monkeypatch):
    which_finds(monkeypatch, npx=r"C:\Program Files\nodejs\npx.cmd")
    monkeypatch.setattr(install.sys, "platform", "win32")

    entry = install.resolve_invocation(Runner.NPX).mcp_entry()

    assert entry == {"command": "cmd", "args": ["/c", "npx", "--yes", "@ossiq/cli", "mcp"]}


def test_runners_missing_from_path_are_written_by_name(monkeypatch):
    which_finds(monkeypatch)
    monkeypatch.setattr(install.sys, "platform", "linux")

    assert install.resolve_invocation(Runner.UVX).mcp_command == "uvx"
    assert install.resolve_invocation(Runner.NPX).mcp_command == "npx"


def test_bare_ossiq_starts_the_server_from_the_absolute_binary(tmp_path, monkeypatch):
    binary = tmp_path / "ossiq"
    binary.touch()
    which_finds(monkeypatch, ossiq=str(binary))

    assert install.resolve_invocation(Runner.OSSIQ) == Invocation("ossiq", str(binary.resolve()), ("mcp",))


def test_a_dev_checkout_overrides_the_runner():
    invocation = install.resolve_invocation(Runner.NPX, "/src/ossiq")

    assert invocation.skill_command == "uvx --from /src/ossiq --no-cache ossiq"
    assert invocation.mcp_entry() == {"command": "uv", "args": ["run", "--directory", "/src/ossiq", "ossiq", "mcp"]}


def test_merge_mcp_config_creates_new_file(tmp_path):
    path = tmp_path / "mcp.json"
    assert install.merge_mcp_config(path, MCP_ENTRY) is False
    config = json.loads(path.read_text(encoding="utf-8"))
    assert config["mcpServers"]["ossiq"] == MCP_ENTRY


def test_merge_mcp_config_preserves_existing_entries(tmp_path):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"other": {"command": "other"}}}), encoding="utf-8")
    install.merge_mcp_config(path, MCP_ENTRY)
    config = json.loads(path.read_text(encoding="utf-8"))
    assert config["mcpServers"]["other"] == {"command": "other"}
    assert config["mcpServers"]["ossiq"] == MCP_ENTRY


@pytest.mark.parametrize("dev_path", [None, "/dev/checkout"])
@pytest.mark.parametrize("runner", list(Runner))
def test_the_mcp_entry_never_carries_a_token(runner, dev_path):
    assert "env" not in install.resolve_invocation(runner, dev_path).mcp_entry()


def test_merge_mcp_config_scrubs_a_token_an_earlier_install_stored(tmp_path):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"ossiq": OLD_TOKEN_ENTRY}}), encoding="utf-8")

    assert install.merge_mcp_config(path, MCP_ENTRY) is True

    text = path.read_text(encoding="utf-8")
    assert "ghp_old_secret" not in text
    assert "env" not in json.loads(text)["mcpServers"]["ossiq"]


def test_install_claude_writes_skill_and_mcp(tmp_path):
    assert install.install_claude(tmp_path, SKILL_CONTENT, MCP_ENTRY) is None
    assert (tmp_path / ".claude" / "skills" / "ossiq" / "SKILL.md").read_text(encoding="utf-8") == SKILL_CONTENT
    config = json.loads((tmp_path / ".claude" / "mcp.json").read_text(encoding="utf-8"))
    assert config["mcpServers"]["ossiq"] == MCP_ENTRY


def test_install_codex_writes_skill_and_mcp(tmp_path):
    assert install.install_codex(tmp_path, SKILL_CONTENT, MCP_ENTRY) is None
    assert (tmp_path / ".codex" / "skills" / "ossiq" / "SKILL.md").read_text(encoding="utf-8") == SKILL_CONTENT
    config = json.loads((tmp_path / ".codex" / "mcp.json").read_text(encoding="utf-8"))
    assert config["mcpServers"]["ossiq"] == MCP_ENTRY


def test_installers_report_which_file_they_scrubbed(tmp_path):
    for tool, relative in (("claude", ".claude/mcp.json"), ("codex", ".codex/mcp.json")):
        path = tmp_path / relative
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"mcpServers": {"ossiq": OLD_TOKEN_ENTRY}}), encoding="utf-8")

        assert install.INSTALLERS[tool](tmp_path, SKILL_CONTENT, MCP_ENTRY) == path


def test_install_copilot_writes_instructions(tmp_path):
    assert install.install_copilot(tmp_path, SKILL_CONTENT, MCP_ENTRY) is None
    text = (tmp_path / ".copilot" / "copilot-instructions.md").read_text(encoding="utf-8")
    assert SKILL_CONTENT in text


def test_install_copilot_is_idempotent_and_updates_block(tmp_path):
    install.install_copilot(tmp_path, SKILL_CONTENT, MCP_ENTRY)
    install.install_copilot(tmp_path, "# ossiq skill\nupdated body\n", MCP_ENTRY)
    text = (tmp_path / ".copilot" / "copilot-instructions.md").read_text()
    assert text.count(install.COPILOT_START) == 1
    assert "updated body" in text
    assert "body\n" not in text.replace("updated body\n", "")


def test_install_copilot_preserves_unrelated_content(tmp_path):
    path = tmp_path / ".copilot" / "copilot-instructions.md"
    path.parent.mkdir(parents=True)
    path.write_text("# My custom instructions\n", encoding="utf-8")
    install.install_copilot(tmp_path, SKILL_CONTENT, MCP_ENTRY)
    text = path.read_text(encoding="utf-8")
    assert "# My custom instructions" in text
    assert SKILL_CONTENT in text


def test_skills_command_unknown_tool_exits_nonzero():
    runner = CliRunner()
    result = runner.invoke(app, ["install", "skills", "bogus"])
    assert result.exit_code == 1


def test_skills_command_installs_single_tool(tmp_path, monkeypatch):
    use_home(tmp_path, monkeypatch)
    runner = CliRunner()
    result = runner.invoke(app, ["install", "skills", "claude"])
    assert result.exit_code == 0
    assert (tmp_path / ".claude" / "skills" / "ossiq" / "SKILL.md").exists()
    assert not (tmp_path / ".codex").exists()


def test_skills_command_default_installs_all_tools(tmp_path, monkeypatch):
    use_home(tmp_path, monkeypatch)
    runner = CliRunner()
    result = runner.invoke(app, ["install", "skills"])
    assert result.exit_code == 0
    assert (tmp_path / ".claude" / "skills" / "ossiq" / "SKILL.md").exists()
    assert (tmp_path / ".codex" / "skills" / "ossiq" / "SKILL.md").exists()
    assert (tmp_path / ".copilot" / "copilot-instructions.md").exists()


def test_skills_command_does_not_ask_for_a_token(tmp_path, monkeypatch):
    use_home(tmp_path, monkeypatch)
    runner = CliRunner()

    result = runner.invoke(app, ["install", "skills", "claude"])  # no input: a prompt would abort

    assert result.exit_code == 0
    assert "GitHub token (leave blank" not in result.output
    config = json.loads((tmp_path / ".claude" / "mcp.json").read_text(encoding="utf-8"))
    assert "env" not in config["mcpServers"]["ossiq"]


def test_skills_command_points_at_the_login(tmp_path, monkeypatch):
    use_home(tmp_path, monkeypatch)
    runner = CliRunner()

    result = runner.invoke(app, ["install", "skills", "claude"])

    assert "ossiq auth login" in result.stdout


def test_skills_command_no_longer_stores_a_token_passed_on_the_command_line(tmp_path, monkeypatch):
    use_home(tmp_path, monkeypatch)
    runner = CliRunner()

    result = runner.invoke(app, ["install", "skills", "claude", "--github-token", "ghp_abc"])

    assert result.exit_code == 0
    assert "no longer stored" in result.stderr
    config_text = (tmp_path / ".claude" / "mcp.json").read_text(encoding="utf-8")
    assert "ghp_abc" not in config_text
    assert not list(tmp_path.rglob("config"))  # no config file written anywhere under home


def test_skills_command_scrubs_an_old_token_and_says_so(tmp_path, monkeypatch):
    use_home(tmp_path, monkeypatch)
    path = tmp_path / ".claude" / "mcp.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"mcpServers": {"ossiq": OLD_TOKEN_ENTRY}}), encoding="utf-8")
    runner = CliRunner()

    result = runner.invoke(app, ["install", "skills", "claude"])

    assert "ghp_old_secret" not in path.read_text(encoding="utf-8")
    assert f"removed the GitHub token an earlier install stored in {path}" in result.stdout


def test_skills_command_never_edits_the_legacy_config_file(tmp_path, monkeypatch):
    use_home(tmp_path, monkeypatch)
    legacy = tmp_path / ".ossiq" / "config"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("OSSIQ_GITHUB_TOKEN=ghp_legacy\n", encoding="utf-8")
    runner = CliRunner()

    runner.invoke(app, ["install", "skills", "claude", "--github-token", "ghp_abc"])

    assert legacy.read_text(encoding="utf-8") == "OSSIQ_GITHUB_TOKEN=ghp_legacy\n"


def test_load_skill_content_bundles_agent_contract():
    content = install.load_skill_content()
    assert "name: ossiq-dependency-check" in content
    assert install.SKILL_COMMAND_PLACEHOLDER in content
    assert "ossiq_evaluate_dependency" in content


def test_the_bundled_skill_runs_every_command_through_the_placeholder():
    content = install.load_skill_content()

    # A bare `ossiq <subcommand>` fails for anyone who runs ossiq through uvx or npx, and a literal
    # uvx would send npm users to a runner they may not have.
    assert not re.search(r"(`|^)ossiq ", content, re.MULTILINE)
    assert "uvx" not in content


def test_render_skill_fills_every_command():
    rendered = install.render_skill(install.load_skill_content(), "npx --yes @ossiq/cli")

    assert install.SKILL_COMMAND_PLACEHOLDER not in rendered
    assert "npx --yes @ossiq/cli auth login --no-wait" in rendered
    assert "npx --yes @ossiq/cli info <package> <project_path> --format agent" in rendered


def test_skills_command_via_npx_writes_npx_commands_and_entry(tmp_path, monkeypatch):
    use_home(tmp_path, monkeypatch)
    which_finds(monkeypatch, npx="/usr/local/bin/npx")
    monkeypatch.setattr(install.sys, "platform", "linux")
    runner = CliRunner()

    result = runner.invoke(app, ["install", "skills", "claude", "--via", "npx"])

    assert result.exit_code == 0
    skill = (tmp_path / ".claude" / "skills" / "ossiq" / "SKILL.md").read_text(encoding="utf-8")
    assert "npx --yes @ossiq/cli status <project_path> --format agent" in skill
    config = json.loads((tmp_path / ".claude" / "mcp.json").read_text(encoding="utf-8"))
    assert config["mcpServers"]["ossiq"] == {"command": "/usr/local/bin/npx", "args": ["--yes", "@ossiq/cli", "mcp"]}
    assert "the skill runs ossiq as: npx --yes @ossiq/cli" in result.stdout
    assert "npx --yes @ossiq/cli auth login" in result.stdout


def test_skills_command_detects_a_binary_installed_from_npm(tmp_path, monkeypatch):
    use_home(tmp_path, monkeypatch)
    monkeypatch.setattr(install.sys, "frozen", True, raising=False)
    monkeypatch.setattr(install.sys, "executable", str(NPX_CACHE))
    runner = CliRunner()

    result = runner.invoke(app, ["install", "skills", "claude"])

    assert result.exit_code == 0
    skill = (tmp_path / ".claude" / "skills" / "ossiq" / "SKILL.md").read_text(encoding="utf-8")
    assert "npx --yes @ossiq/cli info <package>" in skill


def test_skills_command_rejects_via_together_with_dev(tmp_path, monkeypatch):
    use_home(tmp_path, monkeypatch)
    runner = CliRunner()

    result = runner.invoke(app, ["install", "skills", "claude", "--via", "npx", "--dev", "/src/ossiq"])

    assert result.exit_code == 1
    assert "cannot be combined" in result.stderr
    assert not (tmp_path / ".claude").exists()
