# src/ossiq/domain/ecosystem.py
from dataclasses import dataclass

from ossiq.domain.common import ProjectPackagesRegistry


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

    name: str
    ecosystem: ProjectPackagesRegistry
    primary_manifest: Manifest
    lockfile: Lockfile | None


# --- PyPI Package Managers ---

UV_PYPROJECT = Manifest(name="pyproject.toml")
UV_LOCKFILE = Lockfile(name="uv.lock")
UV = PackageManagerType(
    name="uv",
    ecosystem=ProjectPackagesRegistry.PYPI,
    primary_manifest=UV_PYPROJECT,
    lockfile=UV_LOCKFILE,
)

PIP_PYPROJECT = Manifest(name="pyproject.toml")
PIP_LOCKFILE = Lockfile(name="pylock.toml")
PIP = PackageManagerType(
    name="pylock",
    ecosystem=ProjectPackagesRegistry.PYPI,
    primary_manifest=PIP_PYPROJECT,
    lockfile=PIP_LOCKFILE,
)

POETRY_PYPROJECT = Manifest(name="pyproject.toml")
POETRY_LOCKFILE = Lockfile(name="poetry.lock")
POETRY = PackageManagerType(
    name="Poetry",
    ecosystem=ProjectPackagesRegistry.PYPI,
    primary_manifest=POETRY_PYPROJECT,
    lockfile=POETRY_LOCKFILE,
)

PDM_PYPROJECT = Manifest(name="pyproject.toml")
PDM_LOCKFILE = Lockfile(name="pdm.lock")
PDM = PackageManagerType(
    name="PDM",
    ecosystem=ProjectPackagesRegistry.PYPI,
    primary_manifest=PDM_PYPROJECT,
    lockfile=PDM_LOCKFILE,
)

PIP_REQUIREMENTS_TXT = Manifest(name="requirements.txt")
PIP_CLASSIC = PackageManagerType(
    name="pip-classic",
    ecosystem=ProjectPackagesRegistry.PYPI,
    primary_manifest=PIP_REQUIREMENTS_TXT,
    lockfile=None,
)

# --- NPM Package Managers (for future use) ---

NPM_PACKAGE_JSON = Manifest(name="package.json")
NPM_LOCKFILE = Lockfile(name="package-lock.json")
NPM = PackageManagerType(
    name="npm",
    ecosystem=ProjectPackagesRegistry.NPM,
    primary_manifest=NPM_PACKAGE_JSON,
    lockfile=NPM_LOCKFILE,
)

YARN_LOCKFILE = Lockfile(name="yarn.lock")
YARN = PackageManagerType(
    name="Yarn",
    ecosystem=ProjectPackagesRegistry.NPM,
    primary_manifest=NPM_PACKAGE_JSON,  # Uses package.json
    lockfile=YARN_LOCKFILE,
)

PNPM_LOCKFILE = Lockfile(name="pnpm-lock.yaml")
PNPM = PackageManagerType(
    name="pnpm",
    ecosystem=ProjectPackagesRegistry.NPM,
    primary_manifest=NPM_PACKAGE_JSON,  # Uses package.json
    lockfile=PNPM_LOCKFILE,
)

# A list to hold all supported managers for easier lookup
PYPI_MANAGERS = [UV, POETRY, PDM, PIP, PIP_CLASSIC]
NPM_MANAGERS = [NPM, YARN, PNPM]
ALL_MANAGERS = PYPI_MANAGERS + NPM_MANAGERS
