"""Import boundary: renderers must never reach back into I/O clients."""

import ast
import pathlib

RENDERERS_ROOT = pathlib.Path("src/ossiq/ui/renderers")
FORBIDDEN_PREFIXES = ("ossiq.clients", "ossiq.adapters", "ossiq.sources", "ossiq.solver")
FORBIDDEN_NAMES = {"ProjectSources", "AbstractProjectSources", "build_project_sources"}


def _imports_for(path: pathlib.Path) -> list[tuple[str, set[str]]]:
    tree = ast.parse(path.read_text())
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
    for py_file in RENDERERS_ROOT.rglob("*.py"):
        all_violations.extend(_collect_violations(py_file))
    assert not all_violations, "\n".join(all_violations)
