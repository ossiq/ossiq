"""Spread an update plan over install passes that never leave a peer range broken mid-install (npm).

npm refuses a tree where an installed package's peer range excludes what another update places next
to it, even when the finished tree would be fine, so a requirer whose old range still forbids its
peer's new version has to be updated first. The pure ordering lives in `ossiq.sequence`; this module
feeds it what each range admits, so it is the only place that reads versions.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Iterable, Mapping
from typing import TYPE_CHECKING

from ossiq.domain.common import PassOrdering, ProjectPackagesRegistry
from ossiq.domain.version import PeerDependency
from ossiq.sequence.passes import PeerLink, sequence_moves
from ossiq.solver.version_matchers import version_satisfies_constraint

if TYPE_CHECKING:
    from ossiq.service.update import UpdateEntry, UpdatePlan


def peer_links(
    entries: list[UpdateEntry],
    peers_of: Callable[[str, str], Mapping[str, PeerDependency]],
    kind: ProjectPackagesRegistry,
) -> dict[PeerLink, str]:
    """Each peer range between two moving packages that constrains their order, with the range.

    The range is the requirer's installed one, which is what a pass has to wait out.
    """
    by_name: dict[str, list[UpdateEntry]] = {}
    for entry in entries:
        by_name.setdefault(entry.package_name, []).append(entry)

    def admits(version: str, spec: str) -> bool:
        return not spec or version_satisfies_constraint(version, spec, kind)

    links: dict[PeerLink, str] = {}
    for requirer in entries:
        old = peers_of(requirer.package_name, requirer.current_version)
        new = peers_of(requirer.package_name, requirer.recommended_version)
        for name in old.keys() | new.keys():
            old_spec = old[name].spec if name in old else ""
            new_spec = new[name].spec if name in new else ""
            # shortcut: links every copy of a nested name, not the one the requirer resolves; narrow if it over-splits.
            for peer in by_name.get(name, ()):
                if peer is requirer:
                    continue
                # A range the installed pair already breaks is drift, not something this plan causes.
                installed_admits_target = admits(peer.recommended_version, old_spec) or not admits(
                    peer.current_version, old_spec
                )
                target_admits_installed = admits(peer.current_version, new_spec)
                if not (installed_admits_target and target_admits_installed):
                    link = PeerLink(requirer.move_key, peer.move_key, installed_admits_target, target_admits_installed)
                    links[link] = old_spec
    return links


def assign_install_passes(
    plan: UpdatePlan,
    peers_of: Callable[[str, str], Mapping[str, PeerDependency]],
    kind: ProjectPackagesRegistry,
) -> UpdatePlan:
    """The single writer of `UpdateEntry.install_pass` and `UpdatePlan.pass_orderings`.

    Args:
        plan: The plan whose entries to spread over passes.
        peers_of: The peers a published release declares, for a package and version.
        kind: Which registry's version grammar the peer ranges are written in.

    Returns:
        The plan with every entry's pass set; unchanged when no peer range separates two entries.
    """
    entries = plan.all_entries
    links = peer_links(entries, peers_of, kind)
    if not links:
        return plan
    sequence = sequence_moves([entry.move_key for entry in entries], list(links))
    by_key = {entry.move_key: entry for entry in entries}

    def ordering(link: PeerLink, honoured: bool) -> PassOrdering:
        requirer, peer = by_key[link.requirer], by_key[link.peer]
        return PassOrdering(
            requirer_key=requirer.move_key,
            requirer=requirer.display_name,
            requirer_version=requirer.current_version,
            peer=peer.display_name,
            peer_version=peer.recommended_version,
            spec=links[link],
            honoured=honoured,
        )

    def in_pass(group: Iterable[UpdateEntry]) -> list[UpdateEntry]:
        return [dataclasses.replace(entry, install_pass=sequence.pass_of[entry.move_key]) for entry in group]

    return dataclasses.replace(
        plan,
        direct_entries=in_pass(plan.direct_entries),
        transitive_entries=in_pass(plan.transitive_entries),
        pass_orderings=[
            *(ordering(link, True) for link in sequence.ordered),
            *(ordering(link, False) for link in sequence.unresolved),
        ],
    )
