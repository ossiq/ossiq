# src/ossiq/domain/ecosystem.py
from dataclasses import dataclass
from enum import StrEnum

from ossiq.domain.common import ProjectPackagesRegistry


class PackageManagerCli(StrEnum):
    """The command-line tool a project's package manager is driven through.

    Coarser than `PackageManagerType.name`: pylock, pep621 and pip-classic projects all install
    with `pip`, and the export schema reports the tool, not OSS IQ's adapter for it.
    """

    UV = "uv"
    PIP = "pip"
    NPM = "npm"
    PNPM = "pnpm"


@dataclass(frozen=True)
class Manifest:
    """Represents a dependency manifest file."""

    name: str


@dataclass(frozen=True)
class Lockfile:
    """Represents a dependency lockfile."""

    name: str


@dataclass(frozen=True)
class PackageManagerType:
    """Represents a package manager or dependency tool."""

    # On npm-registry managers `name` is also the `engines` key (engine probing reads it).
    name: str
    package_registry: ProjectPackagesRegistry
    primary_manifest: Manifest
    lockfile: Lockfile | None
    cli: PackageManagerCli


# --- PyPI Package Managers ---

UV_PYPROJECT = Manifest(name="pyproject.toml")
UV_LOCKFILE = Lockfile(name="uv.lock")
UV = PackageManagerType(
    name="uv",
    package_registry=ProjectPackagesRegistry.PYPI,
    primary_manifest=UV_PYPROJECT,
    lockfile=UV_LOCKFILE,
    cli=PackageManagerCli.UV,
)

PIP_PYPROJECT = Manifest(name="pyproject.toml")
PIP_LOCKFILE = Lockfile(name="pylock.toml")
PIP = PackageManagerType(
    name="pylock",
    package_registry=ProjectPackagesRegistry.PYPI,
    primary_manifest=PIP_PYPROJECT,
    lockfile=PIP_LOCKFILE,
    cli=PackageManagerCli.PIP,
)

PIP_REQUIREMENTS_TXT = Manifest(name="requirements.txt")
PIP_CLASSIC = PackageManagerType(
    name="pip-classic",
    package_registry=ProjectPackagesRegistry.PYPI,
    primary_manifest=PIP_REQUIREMENTS_TXT,
    lockfile=None,
    cli=PackageManagerCli.PIP,
)

PEP621_PYPROJECT = Manifest(name="pyproject.toml")
PEP621 = PackageManagerType(
    name="pep621",
    package_registry=ProjectPackagesRegistry.PYPI,
    primary_manifest=PEP621_PYPROJECT,
    lockfile=None,
    cli=PackageManagerCli.PIP,
)

# --- NPM Package Managers ---

NPM_PACKAGE_JSON = Manifest(name="package.json")
NPM_LOCKFILE = Lockfile(name="package-lock.json")
NPM = PackageManagerType(
    name="npm",
    package_registry=ProjectPackagesRegistry.NPM,
    primary_manifest=NPM_PACKAGE_JSON,
    lockfile=NPM_LOCKFILE,
    cli=PackageManagerCli.NPM,
)

PNPM_LOCKFILE = Lockfile(name="pnpm-lock.yaml")
PNPM = PackageManagerType(
    name="pnpm",
    package_registry=ProjectPackagesRegistry.NPM,
    primary_manifest=NPM_PACKAGE_JSON,  # Uses package.json
    lockfile=PNPM_LOCKFILE,
    cli=PackageManagerCli.PNPM,
)
