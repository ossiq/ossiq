"""Resolve and apply `--override` targets."""

from __future__ import annotations

from ossiq.domain.update_plan import UpdateEntry
from ossiq.service.project.models import ScanRecord, ScanResult
from ossiq.service.update.entries import forced_entry_from_record


def find_override_record(scan_result: ScanResult, name: str) -> ScanRecord | None:
    """Resolve a `--override` target to the record it names, or None when nothing matches.

    Accepts the manifest key (`uuid-v7`, the only unambiguous way to name one of two npm aliases) or the
    registry name (`uuid`), trying the manifest key first so a project declaring both `uuid` and
    `uuid-v7` can address each. Every caller that acts on an `--override` name must resolve it here,
    even when it only wants the registry name: an alias such as `uuid-v11` is not a registry package.

    Args:
        scan_result: The scanned tree to resolve against.
        name: The package name as the user spelled it.

    Returns:
        The matching record, direct before transitive, or None.
    """
    direct = scan_result.production_packages + scan_result.optional_packages
    for record in direct:
        if record.dependency_name == name:
            return record
    for pool in (direct, scan_result.transitive_packages):
        for record in pool:
            if record.package_name == name:
                return record
    return None


def override_alias_siblings(scan_result: ScanResult, name: str) -> list[str]:
    """Return the manifest keys that share registry name *name*, when more than one direct record does.

    `--override uuid==14.0.2` on a project declaring both `uuid-v7` and `uuid-v11` names two installed
    copies but can apply to only one, so the caller reports the alternatives instead of picking.
    """
    keys = sorted(
        {
            record.identity_name
            for record in scan_result.production_packages + scan_result.optional_packages
            if record.package_name == name
        }
    )
    return keys if len(keys) > 1 else []


def apply_forced_overrides(
    scan_result: ScanResult,
    direct_records: list[ScanRecord],
    direct: list[UpdateEntry],
    transitive: list[UpdateEntry],
    forced_overrides: dict[str, str] | None,
) -> tuple[list[UpdateEntry], list[UpdateEntry], list[str]]:
    """Replace the solver's entries with the versions the user forced through `--override`.

    Args:
        scan_result: The scanned tree each override name is resolved against.
        direct_records: The scan's direct records.
        direct: Direct entries the forced ones replace.
        transitive: Transitive entries the forced ones replace.
        forced_overrides: {package: version} from `--override`, or None.

    Returns:
        The direct entries, the transitive entries sorted by package name, and the override names that are
        absent from the dependency tree.
    """
    if not forced_overrides:
        return direct, transitive, []
    forced_names = set(forced_overrides)
    unknown_overrides: list[str] = []
    direct_identities = {r.identity_name for r in direct_records}
    # Drop by whichever spelling the user used: naming an alias replaces only that alias,
    # naming the registry name replaces every entry carrying it.
    direct = [e for e in direct if e.identity not in forced_names and e.package_name not in forced_names]
    transitive = [e for e in transitive if e.package_name not in forced_names]
    for name, version in forced_overrides.items():
        record = find_override_record(scan_result, name)
        if record is None:
            unknown_overrides.append(name)
            continue
        if version == record.installed_version:
            continue
        is_direct = record.identity_name in direct_identities
        entry = forced_entry_from_record(record, version, is_direct)
        if is_direct:
            direct.append(entry)
        else:
            transitive.append(entry)
    transitive.sort(key=lambda e: e.package_name)
    return direct, transitive, unknown_overrides
