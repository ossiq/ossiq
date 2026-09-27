"""Measure D3: where the bytes in `ossiq export` go, per profile, next to the `--format agent` payload.

Runs `ossiq export` (the standard profile), `ossiq export --full` and `ossiq status --format agent`
on each fixture, prints the three sizes, then - for each profile - the size of every top-level field
and the per-field total across all `production_packages` / `transitive_packages` entries, largest
first. The full-profile numbers are the D3 baseline in PLAN.md; the standard ones are what agents get.

Run from the repository root:

    uv run python scripts/repro/export_size.py testdata/npm/small-cjs testdata/pypi/small-py
"""

import argparse
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURES = ("testdata/npm/small-cjs", "testdata/pypi/small-py", "testdata/pypi/uv")
PACKAGE_LISTS = ("production_packages", "development_packages", "transitive_packages")
TOP_FIELDS_SHOWN = 12


def json_size(value: Any) -> int:
    """Bytes of *value* serialised compactly, the way an agent would receive it."""
    return len(json.dumps(value, separators=(",", ":")).encode())


def run_ossiq(args: list[str], cutoff: str) -> subprocess.CompletedProcess[str]:
    ossiq = Path(sys.executable).parent / "ossiq"
    return subprocess.run(
        [str(ossiq), "--cutoff-date", cutoff, *args], capture_output=True, text=True, cwd=REPO_ROOT, check=False
    )


def field_totals(entries: list[dict[str, Any]]) -> Counter[str]:
    """Sum of each field's serialised size across every entry of a package list."""
    totals: Counter[str] = Counter()
    for entry in entries:
        for key, value in entry.items():
            totals[key] += json_size(value)
    return totals


def export_document(fixture: str, cutoff: str, schema_version: str | None, full: bool) -> dict[str, Any] | None:
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "export.json"
        export_args = ["export", f"--output={output}", fixture]
        if schema_version:
            export_args.insert(1, f"--schema-version={schema_version}")
        if full:
            export_args.insert(1, "--full")
        completed = run_ossiq(export_args, cutoff)
        if not output.exists():
            print(f"\n## {fixture}: export failed (exit {completed.returncode})\n{completed.stderr[-400:]}")
            return None
        return json.loads(output.read_text())


def report(fixture: str, cutoff: str, schema_version: str | None) -> None:
    documents = {
        "standard": export_document(fixture, cutoff, schema_version, full=False),
        "full": export_document(fixture, cutoff, schema_version, full=True),
    }
    agent = run_ossiq(["status", fixture, "--format", "agent"], cutoff)
    agent_size = len(agent.stdout.encode()) if agent.returncode == 0 else None

    print(f"\n## {fixture}")
    full_size = json_size(documents["full"]) if documents["full"] else None
    for profile, export in documents.items():
        if export is None:
            continue
        share = f" ({json_size(export) / full_size:.0%} of full)" if full_size else ""
        schema = export.get("metadata", {}).get("schema_version", "?")
        print(f"export {profile:<8}: {json_size(export):>9,} B{share} (schema {schema})")
    print(f"agent          : {agent_size:>9,} B" if agent_size is not None else "agent: failed")
    for profile, export in documents.items():
        if export is not None:
            print(f"\n### {profile}")
            breakdown(export)


def breakdown(export: dict[str, Any]) -> None:
    """Print one document's top-level field sizes, then per-field totals across each package list."""
    print("top-level fields:")
    for key, value in sorted(export.items(), key=lambda item: -json_size(item[1])):
        count = f" ({len(value)} entries)" if isinstance(value, list) else ""
        print(f"  {json_size(value):>9,} B  {key}{count}")

    for list_name in PACKAGE_LISTS:
        entries = export.get(list_name) or []
        if not entries:
            continue
        print(f"{list_name}: top {TOP_FIELDS_SHOWN} fields summed over {len(entries)} entries")
        for key, size in field_totals(entries).most_common(TOP_FIELDS_SHOWN):
            print(f"  {size:>9,} B  {key}")
        cves = [cve for entry in entries for cve in entry.get("cve") or []]
        if cves:
            print(f"  cve subfields summed over {len(cves)} advisories:")
            for key, size in field_totals(cves).most_common(TOP_FIELDS_SHOWN):
                print(f"    {size:>9,} B  {key}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("fixtures", nargs="*", default=list(DEFAULT_FIXTURES))
    parser.add_argument("--cutoff-date", default="2026-09-08")
    parser.add_argument("--schema-version", default=None, help="Export schema to measure (default: latest)")
    args = parser.parse_args()
    for fixture in args.fixtures:
        report(fixture, args.cutoff_date, args.schema_version)


if __name__ == "__main__":
    main()
