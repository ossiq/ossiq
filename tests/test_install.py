"""Tests for the `install skills` command."""

import json

import pytest
from typer.testing import CliRunner

from ossiq.cli import app
from ossiq.commands import install

SKILL_CONTENT = "# ossiq skill\nbody\n"


@pytest.fixture(autouse=True)
def patch_config_path(tmp_path, monkeypatch):
    """Keep token writes out of the developer's real ~/.ossiq/config."""
    monkeypatch.setattr(install, "CONFIG_PATH", tmp_path / ".ossiq" / "config")


def test_merge_mcp_config_creates_new_file(tmp_path):
    path = tmp_path / "mcp.json"
    install.merge_mcp_config(path, None)
    config = json.loads(path.read_text())
    assert config["mcpServers"]["ossiq"] == install.build_mcp_entry(None)


def test_merge_mcp_config_preserves_existing_entries(tmp_path):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"other": {"command": "other"}}}))
    install.merge_mcp_config(path, None)
    config = json.loads(path.read_text())
    assert config["mcpServers"]["other"] == {"command": "other"}
    assert config["mcpServers"]["ossiq"] == install.build_mcp_entry(None)


def test_merge_mcp_config_injects_github_token(tmp_path):
    path = tmp_path / "mcp.json"
    install.merge_mcp_config(path, "ghp_test123")
    config = json.loads(path.read_text())
    assert config["mcpServers"]["ossiq"]["env"] == {"OSSIQ_GITHUB_TOKEN": "ghp_test123"}


def test_install_claude_writes_skill_and_mcp(tmp_path):
    install.install_claude(tmp_path, SKILL_CONTENT, None)
    assert (tmp_path / ".claude" / "skills" / "ossiq" / "SKILL.md").read_text() == SKILL_CONTENT
    config = json.loads((tmp_path / ".claude" / "mcp.json").read_text())
    assert config["mcpServers"]["ossiq"] == install.build_mcp_entry(None)


def test_install_codex_writes_skill_and_mcp(tmp_path):
    install.install_codex(tmp_path, SKILL_CONTENT, None)
    assert (tmp_path / ".codex" / "skills" / "ossiq" / "SKILL.md").read_text() == SKILL_CONTENT
    config = json.loads((tmp_path / ".codex" / "mcp.json").read_text())
    assert config["mcpServers"]["ossiq"] == install.build_mcp_entry(None)


def test_install_copilot_writes_instructions(tmp_path):
    install.install_copilot(tmp_path, SKILL_CONTENT, None)
    text = (tmp_path / ".copilot" / "copilot-instructions.md").read_text()
    assert SKILL_CONTENT in text


def test_install_copilot_is_idempotent_and_updates_block(tmp_path):
    install.install_copilot(tmp_path, SKILL_CONTENT, None)
    install.install_copilot(tmp_path, "# ossiq skill\nupdated body\n", None)
    text = (tmp_path / ".copilot" / "copilot-instructions.md").read_text()
    assert text.count(install.COPILOT_START) == 1
    assert "updated body" in text
    assert "body\n" not in text.replace("updated body\n", "")


def test_install_copilot_preserves_unrelated_content(tmp_path):
    path = tmp_path / ".copilot" / "copilot-instructions.md"
    path.parent.mkdir(parents=True)
    path.write_text("# My custom instructions\n")
    install.install_copilot(tmp_path, SKILL_CONTENT, None)
    text = path.read_text()
    assert "# My custom instructions" in text
    assert SKILL_CONTENT in text


def test_skills_command_unknown_tool_exits_nonzero():
    runner = CliRunner()
    result = runner.invoke(app, ["install", "skills", "bogus"])
    assert result.exit_code == 1


def test_skills_command_installs_single_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(install.Path, "home", classmethod(lambda cls: tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["install", "skills", "claude"], input="\n")
    assert result.exit_code == 0
    assert (tmp_path / ".claude" / "skills" / "ossiq" / "SKILL.md").exists()
    assert not (tmp_path / ".codex").exists()


def test_skills_command_stores_token_in_mcp(tmp_path, monkeypatch):
    monkeypatch.setattr(install.Path, "home", classmethod(lambda cls: tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["install", "skills", "claude", "--github-token", "ghp_abc"])
    assert result.exit_code == 0
    config = json.loads((tmp_path / ".claude" / "mcp.json").read_text())
    assert config["mcpServers"]["ossiq"]["env"] == {"OSSIQ_GITHUB_TOKEN": "ghp_abc"}


def test_skills_command_writes_config_file(tmp_path, monkeypatch):
    monkeypatch.setattr(install.Path, "home", classmethod(lambda cls: tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["install", "skills", "claude", "--github-token", "ghp_stored"])
    assert result.exit_code == 0
    config_text = (tmp_path / ".ossiq" / "config").read_text()
    assert "OSSIQ_GITHUB_TOKEN=ghp_stored" in config_text


def test_build_mcp_entry_dev_path():
    entry = install.build_mcp_entry(None, dev_path="/path/to/ossiq")
    assert entry["command"] == "uv"
    assert "--directory" in entry["args"]
    assert "/path/to/ossiq" in entry["args"]


def test_apply_dev_path_substitutes_invocation():
    content = f"run {install.SKILL_UVX_PROD} info pkg ."
    result = install.apply_dev_path(content, "/path/to/ossiq")
    assert "uvx --from /path/to/ossiq ossiq-cli" in result
    assert install.SKILL_UVX_PROD not in result


def test_skills_command_dev_flag_patches_skill_and_mcp(tmp_path, monkeypatch):
    monkeypatch.setattr(install.Path, "home", classmethod(lambda cls: tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["install", "skills", "claude", "--dev", "/path/to/ossiq"], input="\n")
    assert result.exit_code == 0
    skill = (tmp_path / ".claude" / "skills" / "ossiq" / "SKILL.md").read_text()
    assert "uvx --from /path/to/ossiq ossiq-cli" in skill
    assert install.SKILL_UVX_PROD not in skill
    config = json.loads((tmp_path / ".claude" / "mcp.json").read_text())
    assert config["mcpServers"]["ossiq"]["command"] == "uv"
    assert "/path/to/ossiq" in config["mcpServers"]["ossiq"]["args"]
