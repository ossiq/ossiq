"""Tests for the rules in ossiq.tree.edges that decide what a node reports as declared."""

import pytest

from ossiq.domain.common import ConstraintType
from ossiq.domain.project import ConstraintSource, Dependency, IncomingEdge
from ossiq.tree.edges import apply_requirement

INSTALLED = "2.0.0"


def classify(spec: str | None) -> ConstraintType:
    return ConstraintType.PINNED if spec and spec[0].isdigit() else ConstraintType.DECLARED


def apply_all(child: Dependency, edges: list[tuple[str, bool]]) -> None:
    """Apply (spec, is_peer) edges in order, each from a different requirer."""
    for index, (spec, is_peer) in enumerate(edges):
        edge = IncomingEdge(requirer_name=f"req{index}", requirer_version="1.0.0", spec=spec, is_peer=is_peer)
        apply_requirement(child, edge, from_root=False, classify=classify)


def lib() -> Dependency:
    return Dependency(name="lib", version_installed=INSTALLED, canonical_name="lib")


class TestPeerVersusRealRequirer:
    @pytest.mark.parametrize(
        ("edges", "version_defined", "constraint_type"),
        [
            pytest.param(
                [("^2.0.0", False), ("^1.0.0", True)], "^2.0.0", ConstraintType.DECLARED, id="peer-after-real-yields"
            ),
            pytest.param(
                [("^1.0.0", True), ("^2.0.0", False)],
                "^2.0.0",
                ConstraintType.DECLARED,
                id="real-after-peer-overwrites",
            ),
            pytest.param([("^1.0.0", True)], "^1.0.0", ConstraintType.DECLARED, id="peer-alone-is-the-fallback"),
            pytest.param(
                [("^1.0.0", True), (INSTALLED, False)], None, ConstraintType.PINNED, id="pin-clears-the-peer-fallback"
            ),
            pytest.param(
                [(INSTALLED, False)], None, ConstraintType.PINNED, id="pin-equal-to-installed-records-nothing"
            ),
            pytest.param(
                [("^2.0.0", False), ("~2.0.0", False)], "~2.0.0", ConstraintType.DECLARED, id="last-real-writer-wins"
            ),
        ],
    )
    def test_version_defined_and_classification(self, edges, version_defined, constraint_type):
        child = lib()

        apply_all(child, edges)

        assert child.version_defined == version_defined
        assert child.constraint_info.type == constraint_type
        # Every edge is recorded, whether or not it won the declaration.
        assert child.parent_constraints == [spec for spec, _ in edges]


@pytest.mark.parametrize("decided", [ConstraintType.ADDITIVE, ConstraintType.OVERRIDE])
def test_a_parent_specifier_never_downgrades_a_deliberate_constraint(decided):
    child = lib()
    child.constraint_info = ConstraintSource(type=decided, source_file="package.json")

    apply_all(child, [(INSTALLED, False)])

    assert child.constraint_info.type == decided


def test_the_root_edge_alone_sets_the_declared_constraint():
    child = lib()
    root_edge = IncomingEdge(requirer_name="app", requirer_version="1.0.0", spec="^2.0.0")

    apply_requirement(child, root_edge, from_root=True, classify=classify)
    apply_all(child, [("~2.0.0", False)])

    assert child.version_constraint_declared == "^2.0.0"
