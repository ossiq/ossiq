"""Tests for the `install skills` command."""

import json

from typer.testing import CliRunner

from ossiq.cli import app
from ossiq.commands import install

SKILL_CONTENT = "# ossiq skill\nbody\n"
OLD_TOKEN_ENTRY = {"command": "ossiq", "args": ["mcp"], "env": {"OSSIQ_GITHUB_TOKEN": "ghp_old_secret"}}


def use_home(tmp_path, monkeypatch):
    monkeypatch.setattr(install.Path, "home", classmethod(lambda cls: tmp_path))


def test_merge_mcp_config_creates_new_file(tmp_path):
    path = tmp_path / "mcp.json"
    assert install.merge_mcp_config(path) is False
    config = json.loads(path.read_text(encoding="utf-8"))
    assert config["mcpServers"]["ossiq"] == install.build_mcp_entry()


def test_merge_mcp_config_preserves_existing_entries(tmp_path):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"other": {"command": "other"}}}), encoding="utf-8")
    install.merge_mcp_config(path)
    config = json.loads(path.read_text(encoding="utf-8"))
    assert config["mcpServers"]["other"] == {"command": "other"}
    assert config["mcpServers"]["ossiq"] == install.build_mcp_entry()


def test_the_mcp_entry_never_carries_a_token():
    assert "env" not in install.build_mcp_entry()
    assert "env" not in install.build_mcp_entry("/dev/checkout")


def test_merge_mcp_config_scrubs_a_token_an_earlier_install_stored(tmp_path):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"ossiq": OLD_TOKEN_ENTRY}}), encoding="utf-8")

    assert install.merge_mcp_config(path) is True

    text = path.read_text(encoding="utf-8")
    assert "ghp_old_secret" not in text
    assert "env" not in json.loads(text)["mcpServers"]["ossiq"]


def test_install_claude_writes_skill_and_mcp(tmp_path):
    assert install.install_claude(tmp_path, SKILL_CONTENT) is None
    assert (tmp_path / ".claude" / "skills" / "ossiq" / "SKILL.md").read_text(encoding="utf-8") == SKILL_CONTENT
    config = json.loads((tmp_path / ".claude" / "mcp.json").read_text(encoding="utf-8"))
    assert config["mcpServers"]["ossiq"] == install.build_mcp_entry()


def test_install_codex_writes_skill_and_mcp(tmp_path):
    assert install.install_codex(tmp_path, SKILL_CONTENT) is None
    assert (tmp_path / ".codex" / "skills" / "ossiq" / "SKILL.md").read_text(encoding="utf-8") == SKILL_CONTENT
    config = json.loads((tmp_path / ".codex" / "mcp.json").read_text(encoding="utf-8"))
    assert config["mcpServers"]["ossiq"] == install.build_mcp_entry()


def test_installers_report_which_file_they_scrubbed(tmp_path):
    for tool, relative in (("claude", ".claude/mcp.json"), ("codex", ".codex/mcp.json")):
        path = tmp_path / relative
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"mcpServers": {"ossiq": OLD_TOKEN_ENTRY}}), encoding="utf-8")

        assert install.INSTALLERS[tool](tmp_path, SKILL_CONTENT) == path


def test_install_copilot_writes_instructions(tmp_path):
    assert install.install_copilot(tmp_path, SKILL_CONTENT) is None
    text = (tmp_path / ".copilot" / "copilot-instructions.md").read_text(encoding="utf-8")
    assert SKILL_CONTENT in text


def test_install_copilot_is_idempotent_and_updates_block(tmp_path):
    install.install_copilot(tmp_path, SKILL_CONTENT)
    install.install_copilot(tmp_path, "# ossiq skill\nupdated body\n")
    text = (tmp_path / ".copilot" / "copilot-instructions.md").read_text()
    assert text.count(install.COPILOT_START) == 1
    assert "updated body" in text
    assert "body\n" not in text.replace("updated body\n", "")


def test_install_copilot_preserves_unrelated_content(tmp_path):
    path = tmp_path / ".copilot" / "copilot-instructions.md"
    path.parent.mkdir(parents=True)
    path.write_text("# My custom instructions\n", encoding="utf-8")
    install.install_copilot(tmp_path, SKILL_CONTENT)
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
    assert install.SKILL_UVX_PROD in content
    assert "ossiq_evaluate_dependency" in content
