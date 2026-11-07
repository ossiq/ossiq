from __future__ import annotations

from ossiq.sequence.steps import group_steps


def test_unlinked_moves_are_a_step_each_in_the_given_order() -> None:
    assert group_steps(["b", "a", "c"], []) == [["b"], ["a"], ["c"]]


def test_linked_moves_share_a_step_placed_by_its_earliest_member() -> None:
    assert group_steps(["react", "zod", "react-dom"], [("react", "react-dom")]) == [["react", "react-dom"], ["zod"]]


def test_a_rider_shared_by_two_packages_merges_their_steps() -> None:
    links = [("a", "rider"), ("b", "rider")]

    assert group_steps(["a", "x", "b", "rider"], links) == [["a", "b", "rider"], ["x"]]


def test_a_link_naming_an_unknown_move_is_ignored() -> None:
    assert group_steps(["a", "b"], [("a", "ghost")]) == [["a"], ["b"]]


def test_every_move_lands_in_exactly_one_step() -> None:
    moves = [f"m{i}" for i in range(20)]
    links = [(f"m{i}", f"m{i + 5}") for i in range(0, 15, 3)]

    flat = [move for group in group_steps(moves, links) for move in group]

    assert sorted(flat) == sorted(moves)
