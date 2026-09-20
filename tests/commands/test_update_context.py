"""End-to-end test for command_update_context: real command function, JSON-only stdout, with
scan/sources/build_installed_detail mocked at the module boundary (mirrors test_export.py's
stdout-hygiene style, plus assembly of the real build_update_context/renderer path)."""

from __future__ import annotations

import dataclasses
import json
from unittest.mock import MagicMock, patch

import typer
from packaging.version import Version

from ossiq.commands.update_context import CommandUpdateContextOptions, command_update_context
from ossiq.domain.common import ConstraintType, ModuleSystem, ProjectPackagesRegistry
from ossiq.domain.compatibility import CompatibilityFacts
from ossiq.domain.project import ConstraintSource
from ossiq.domain.version import PackageVersion, VersionsDifference
from ossiq.mcp.server import evaluate_update_context
from ossiq.service.package import PackageDetailResult
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.settings import Settings


def pv(version: str, module_system: ModuleSystem | None = None) -> PackageVersion:
    return PackageVersion(
        version=version,
        license=None,
        package_url=f"https://example.com/{version}",
        declared_dependencies={},
        published_date_iso="2024-01-01T00:00:00Z",
        module_system=module_system,
    )


def make_record() -> ScanRecord:
    return ScanRecord(
        package_name="chalk",
        dependency_name="chalk",
        is_optional_dependency=False,
        installed_version="4.1.2",
        latest_version="6.0.0",
        versions_diff_index=VersionsDifference("4.1.2", "6.0.0", 5, diff_name="MAJOR"),
        time_lag_days=None,
        releases_lag=2,
        cve=[],
        constraint_info=ConstraintSource(type=ConstraintType.DECLARED, source_file="package.json"),
        compatibility=CompatibilityFacts(module_system=ModuleSystem.CJS),
    )


def make_context() -> typer.Context:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = Settings()
    return ctx


def make_options(**overrides) -> CommandUpdateContextOptions:
    base = CommandUpdateContextOptions(project_path=".", package_name="chalk", to_version="6.0.0")
    return dataclasses.replace(base, **overrides)


def test_update_context_end_to_end_stdout_is_json(capsys):
    record = make_record()
    scan_result = ScanResult(
        project_name="proj",
        packages_registry="NPM",
        project_path=".",
        production_packages=[record],
        optional_packages=[],
    )
    detail = PackageDetailResult(
        records=[record],
        transitive_cve_groups=[],
        project_name="proj",
        packages_registry="NPM",
        is_prospective=False,
    )
    releases = [pv("4.1.2", module_system=ModuleSystem.CJS), pv("6.0.0", module_system=ModuleSystem.ESM_ONLY)]

    mock_sources = MagicMock()
    mock_sources.packages_registry.package_registry = ProjectPackagesRegistry.NPM
    mock_sources.packages_registry.package_versions.return_value = releases

    with (
        patch("ossiq.service.update_context.project_sources.build_project_sources", return_value=mock_sources),
        patch("ossiq.service.update_context.scan", return_value=scan_result),
        patch("ossiq.service.update_context.build_installed_detail", return_value=detail),
    ):
        command_update_context(make_context(), make_options())

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["package"] == "chalk"
    assert data["from_version"] == "4.1.2"
    assert data["to_version"] == "6.0.0"
    assert data["breaking_change"] == "ESM-only from 6.0.0"


def test_update_context_prospective_package_uses_fetch_prospective_detail(capsys):
    scan_result = ScanResult(
        project_name="proj",
        packages_registry="NPM",
        project_path=".",
        production_packages=[],
        optional_packages=[],
    )
    detail = PackageDetailResult(
        records=[],
        transitive_cve_groups=[],
        project_name="proj",
        packages_registry="NPM",
        is_prospective=True,
        prospective_name="newpkg",
    )
    releases = [pv("1.0.0", module_system=ModuleSystem.CJS)]

    mock_sources = MagicMock()
    mock_sources.packages_registry.package_registry = ProjectPackagesRegistry.NPM
    mock_sources.packages_registry.package_versions.return_value = releases
    mock_sources.packages_registry.newest_version.side_effect = lambda candidates: max(
        candidates, key=lambda p: Version(p.version), default=None
    )

    with (
        patch("ossiq.service.update_context.project_sources.build_project_sources", return_value=mock_sources),
        patch("ossiq.service.update_context.scan", return_value=scan_result),
        patch("ossiq.service.update_context.fetch_prospective_detail", return_value=detail) as fetch_mock,
    ):
        command_update_context(make_context(), make_options(package_name="newpkg", to_version="1.0.0"))

    fetch_mock.assert_called_once()
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["from_version"] is None
    assert data["to_version"] == "1.0.0"


def test_cli_and_mcp_produce_the_same_payload(capsys):
    """Both front doors call service.update_context.build_update_context_payload and nothing else,
    so the same project and target must give byte-identical output. They used to own a copy of
    this orchestration each, and had already diverged on how they build ProjectSources."""
    record = make_record()
    scan_result = ScanResult(
        project_name="proj",
        packages_registry="NPM",
        project_path=".",
        production_packages=[record],
        optional_packages=[],
    )
    detail = PackageDetailResult(
        records=[record],
        transitive_cve_groups=[],
        project_name="proj",
        packages_registry="NPM",
        is_prospective=False,
    )
    releases = [pv("4.1.2", module_system=ModuleSystem.CJS), pv("6.0.0", module_system=ModuleSystem.ESM_ONLY)]

    def patches():
        mock_sources = MagicMock()
        mock_sources.packages_registry.package_registry = ProjectPackagesRegistry.NPM
        mock_sources.packages_registry.package_versions.return_value = releases
        return (
            patch("ossiq.service.update_context.project_sources.build_project_sources", return_value=mock_sources),
            patch("ossiq.service.update_context.scan", return_value=scan_result),
            patch("ossiq.service.update_context.build_installed_detail", return_value=detail),
        )

    sources_patch, scan_patch, detail_patch = patches()
    with sources_patch, scan_patch, detail_patch:
        command_update_context(make_context(), make_options())
    cli_payload = json.loads(capsys.readouterr().out)

    sources_patch, scan_patch, detail_patch = patches()
    with sources_patch, scan_patch, detail_patch:
        mcp_payload = evaluate_update_context(
            Settings(), {"package": "chalk", "project_path": ".", "target_version": "6.0.0"}
        )

    assert cli_payload == mcp_payload
