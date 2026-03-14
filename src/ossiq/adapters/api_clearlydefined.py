from ossiq.clients.clearlydefined import ClearlyDefinedSession
from ossiq.domain.common import ProjectPackagesRegistry
from ossiq.domain.package import Package

from .api_interfaces import AbstractLicenseDatabaseApi

REGISTRY_MAPPING = {
    ProjectPackagesRegistry.PYPI: ("pypi", "pypi"),
    ProjectPackagesRegistry.NPM: ("npm", "npmjs"),
}


class LicenseApiClearlyDefined(AbstractLicenseDatabaseApi):
    """
    An AbstractLicenseDatabaseApi implementation using ClearlyDefined.
    Uses POST /definitions to fetch normalized SPDX licenses for all packages in one request.
    """

    def __init__(self, session: ClearlyDefinedSession):
        self.base_url = "https://api.clearlydefined.io"
        self.session = session

    def __repr__(self):
        return f"LicenseApiClearlyDefined(base_url='{self.base_url}')"

    def get_licenses_batch(
        self, packages_with_versions: list[tuple[Package, str]]
    ) -> dict[tuple[str, str], str | None]:
        if not packages_with_versions:
            return {}

        coordinates = [self._build_coordinate(pkg, version) for pkg, version in packages_with_versions]

        resp = self.session.post(f"{self.base_url}/definitions", json=coordinates, timeout=120)
        resp.raise_for_status()

        data = resp.json()
        results: dict[tuple[str, str], str | None] = {}
        for (pkg, version), coord in zip(packages_with_versions, coordinates, strict=True):
            definition = data.get(coord, {})
            results[(pkg.name, version)] = self._extract_license(definition)

        return results

    def _build_coordinate(self, pkg: Package, version: str) -> str:
        pkg_type, provider = REGISTRY_MAPPING[pkg.registry]

        if pkg.registry == ProjectPackagesRegistry.NPM and pkg.name.startswith("@"):
            # Scoped package: @scope/name → namespace=@scope, name=name
            scope, name = pkg.name.split("/", 1)
            return f"{pkg_type}/{provider}/{scope}/{name}/{version}"

        return f"{pkg_type}/{provider}/-/{pkg.name}/{version}"

    def _extract_license(self, definition: dict) -> str | None:
        licensed = definition.get("licensed", {})

        declared = licensed.get("declared")
        if declared:
            return declared

        expressions = licensed.get("facets", {}).get("core", {}).get("discovered", {}).get("expressions", [])
        if expressions:
            return expressions[0]

        return None
