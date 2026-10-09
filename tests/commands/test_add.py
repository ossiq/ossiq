"""command_add: the gate in front of `install_package`, with the registry and the installer stubbed at
the module boundary and the real renderer and rule evaluation in between."""

from __future__ import annotations

import dataclasses
from unittest.mock import MagicMock, patch

import pytest
import typer

from ossiq.commands.add import CommandAddOptions, command_add
from ossiq.domain.common import ProjectPackagesRegistry, RegistryStatus
from ossiq.domain.package import Package
from ossiq.domain.version import PackageVersion
from ossiq.service.package import (
    RULE_PACKAGE_DEPRECATED,
    PackageDetailResult,
    build_package_insight,
    evaluate_package_rules,
)
from ossiq.settings import Settings

LEFT_PAD_NOTE = "use String.prototype.padStart()"


def release(version: str) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url=f"https://example.com/{version}",
        declared_dependencies={},
        published_date_iso="2016-03-01T00:00:00Z",
    )


def make_detail(status: RegistryStatus | None, message: str | None = None) -> PackageDetailResult:
    package = Package(
        registry=ProjectPackagesRegistry.NPM,
        name="left-pad",
        latest_version="1.3.0",
        next_version=None,
        repo_url=None,
        package_url="https://www.npmjs.com/package/left-pad/",
        registry_status=status,
        deprecation_message=message,
        maintainers_count=2,
    )
    insight = build_package_insight(
        package, [release("1.2.0"), release("1.3.0")], Settings(), recommended_version="1.3.0"
    )
    return PackageDetailResult(
        records=[],
        transitive_cve_groups=[],
        project_name="",
        packages_registry="npm",
        insight=insight,
        warnings=evaluate_package_rules(insight, Settings()),
        is_prospective=True,
        prospective_name="left-pad",
        prospective_package=package,
    )


def make_context() -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = Settings()
    return ctx


def make_options(**overrides) -> CommandAddOptions:
    base = CommandAddOptions(project_path=".", package_name="left-pad", registry_type="npm")
    return dataclasses.replace(base, **overrides)


@pytest.fixture
def add_environment():
    """Stub the registry, the installer and the progress UI; yield (fetch, installer, confirm)."""
    sources = MagicMock()
    sources.packages_manager.install_package.return_value = 0
    with (
        patch("ossiq.commands.add.project_sources.ProjectSources", return_value=sources),
        patch("ossiq.commands.add.show_operation_progress"),
        patch("ossiq.commands.add.fetch_prospective_detail") as fetch,
        patch("ossiq.commands.add.typer.confirm", return_value=True) as confirm,
    ):
        yield fetch, sources.packages_manager.install_package, confirm


def test_a_package_the_registry_deprecated_is_blocked_and_nothing_is_installed(add_environment, capsys):
    fetch, install, confirm = add_environment
    fetch.return_value = make_detail(RegistryStatus.DEPRECATED, LEFT_PAD_NOTE)
    assert {w.rule_id for w in fetch.return_value.warnings} == {RULE_PACKAGE_DEPRECATED}

    with pytest.raises(typer.Exit) as blocked:
        command_add(make_context(), make_options())

    assert blocked.value.exit_code == 1
    install.assert_not_called()
    confirm.assert_not_called()
    captured = capsys.readouterr()
    output = captured.out + captured.err
    # The warnings panel wraps the sentence inside its border, so check the unbroken pieces.
    assert "Deprecated on npm" in output
    assert "String.prototype.padStart()" in output
    assert "Blocked" in output


def test_force_goes_past_the_block_to_the_recommended_version(add_environment):
    fetch, install, _ = add_environment
    fetch.return_value = make_detail(RegistryStatus.DEPRECATED, LEFT_PAD_NOTE)

    command_add(make_context(), make_options(force=True))

    install.assert_called_once_with("left-pad", "1.3.0")


def test_a_package_that_is_fine_is_installed_after_confirmation(add_environment):
    fetch, install, confirm = add_environment
    fetch.return_value = make_detail(RegistryStatus.ACTIVE)

    command_add(make_context(), make_options())

    confirm.assert_called_once()
    install.assert_called_once_with("left-pad", "1.3.0")


def test_the_version_the_user_named_is_judged_and_then_installed(add_environment):
    fetch, install, _ = add_environment
    fetch.return_value = make_detail(RegistryStatus.ACTIVE)

    command_add(make_context(), make_options(version="1.2.0"))

    assert fetch.call_args.kwargs["requested_version"] == "1.2.0"
    install.assert_called_once_with("left-pad", "1.2.0")


def test_no_named_version_is_passed_on_as_none(add_environment):
    fetch, _, _ = add_environment
    fetch.return_value = make_detail(RegistryStatus.ACTIVE)

    command_add(make_context(), make_options())

    assert fetch.call_args.kwargs["requested_version"] is None
