"""Import boundary: renderers must never reach back into I/O clients."""

import ast
import pathlib

import pytest

# Anchored to this file, not the working directory: a relative path made the
# rglob below silently match nothing whenever pytest ran from outside the repo
# root, so the boundary check passed without inspecting anything.
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
RENDERERS_ROOT = PROJECT_ROOT / "src" / "ossiq" / "ui" / "renderers"
FORBIDDEN_PREFIXES = (
    "ossiq.clients",
    "ossiq.adapters",
    "ossiq.sources",
    "ossiq.solver",
    # A renderer reaching into the pure selector would be re-deriving a verdict the pipeline
    # already wrote onto ScanRecord — the contradictory-surfaces class PLAN.md exists to prevent.
    "ossiq.strategy",
    # The pass a package installs in is written once, by service.install_passes; a renderer
    # sequencing for itself is how `plan` and `apply` would come to disagree on the order.
    "ossiq.sequence",
    # The graph a scan walks is assembled once by the pipeline; a renderer walking or rebuilding
    # it would be doing its own resolution instead of reading ScanResult.
    "ossiq.tree",
)
# Names that carry an adapter or a live registry handle into a renderer even when the module they
# come from is allowed — AgentUpdateContextRenderer used to take one through untyped **kwargs.
FORBIDDEN_NAMES = {
    "ProjectSources",
    "AbstractProjectSources",
    "build_project_sources",
    "AbstractPackageRegistryApi",
}


def _imports_for(path: pathlib.Path) -> list[tuple[str, set[str]]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    results = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                results.append((alias.name, set()))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = {alias.name for alias in node.names}
            results.append((module, names))
    return results


def _collect_violations(path: pathlib.Path) -> list[str]:
    violations = []
    for module, names in _imports_for(path):
        if any(module.startswith(p) for p in FORBIDDEN_PREFIXES):
            violations.append(f"{path}: forbidden import `{module}`")
        bad_names = names & FORBIDDEN_NAMES
        if bad_names:
            violations.append(f"{path}: forbidden name(s) {bad_names} from `{module}`")
    return violations


def test_renderers_import_boundary() -> None:
    # ponytail: encodes the spine-vs-features rule — renderers never reach back into I/O clients
    all_violations: list[str] = []
    py_files = list(RENDERERS_ROOT.rglob("*.py"))
    assert py_files, f"no renderer modules found under {RENDERERS_ROOT}"
    for py_file in py_files:
        all_violations.extend(_collect_violations(py_file))
    assert not all_violations, "\n".join(all_violations)


SRC_ROOT = PROJECT_ROOT / "src"
# Layers that sit above the pure packages in the spine (CLAUDE.md, Architecture): importing one is importing upward.
UPWARD_PREFIXES = (
    "ossiq.adapters",
    "ossiq.clients",
    "ossiq.sources",
    "ossiq.service",
    "ossiq.ui",
    "ossiq.commands",
    "ossiq.mcp",
    "ossiq.settings",
    "ossiq.cli",
)


def imported_modules(path: pathlib.Path) -> set[str]:
    """Absolute dotted names a module imports, with relative imports resolved against its own package."""
    package = list(path.relative_to(SRC_ROOT).with_suffix("").parts[:-1])
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = package[: len(package) - (node.level - 1)] if node.level else []
            module = ".".join([*base, *([node.module] if node.module else [])])
            found.add(module)
            # `from ossiq import settings` names a module through the imported name.
            found.update(f"{module}.{alias.name}" for alias in node.names)
    return found


def under(module: str, prefixes: tuple[str, ...]) -> bool:
    return any(module == prefix or module.startswith(f"{prefix}.") for prefix in prefixes)


def package_files(name: str) -> list[pathlib.Path]:
    files = sorted((SRC_ROOT / "ossiq" / name).rglob("*.py"))
    assert files, f"no modules found under ossiq/{name}"
    return files


def test_domain_imports_nothing_but_itself() -> None:
    violations = [
        f"{path.relative_to(PROJECT_ROOT)}: `{module}`"
        for path in package_files("domain")
        for module in sorted(imported_modules(path))
        if module.startswith("ossiq") and not under(module, ("ossiq.domain",))
    ]
    assert not violations, "\n".join(violations)


@pytest.mark.parametrize("package", ["risk", "solver", "strategy", "sequence", "tree"])
def test_pure_packages_do_not_import_upward(package: str) -> None:
    violations = [
        f"{path.relative_to(PROJECT_ROOT)}: `{module}`"
        for path in package_files(package)
        for module in sorted(imported_modules(path))
        if under(module, UPWARD_PREFIXES)
    ]
    assert not violations, "\n".join(violations)
