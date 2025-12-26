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

PIPENV_FILE = Manifest(name="Pipfile")
PIPENV_LOCKFILE = Lockfile(name="Pipfile.lock")
PIPENV = PackageManagerType(
    name="Pipenv",
    ecosystem=ProjectPackagesRegistry.PYPI,
    primary_manifest=PIPENV_FILE,
    lockfile=PIPENV_LOCKFILE,
)

PIP_REQUIREMENTS = Manifest(name="requirements.txt")
PIP = PackageManagerType(
    name="pip",
    ecosystem=ProjectPackagesRegistry.PYPI,
    primary_manifest=PIP_REQUIREMENTS,
    lockfile=None,  # pip doesn't have a standard lockfile by default
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
PYPI_MANAGERS = [UV, POETRY, PDM, PIPENV, PIP]
NPM_MANAGERS = [NPM, YARN, PNPM]
ALL_MANAGERS = PYPI_MANAGERS + NPM_MANAGERS
