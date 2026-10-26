"""Pure cases for the install-pass sequencer: moves and booleans in, passes out."""

import random

from ossiq.sequence.passes import PeerLink, sequence_moves


def link(requirer: str, peer: str, *, installed_admits_target: bool, target_admits_installed: bool) -> PeerLink:
    return PeerLink(requirer, peer, installed_admits_target, target_admits_installed)


# vue-router 5.1.0 only takes pinia ^3, 5.4.0 takes ^3 || ^4; @pinia/nuxt 1.0.3 needs pinia ^4.
VUE_ROUTER_BEFORE_PINIA = link("vue-router", "pinia", installed_admits_target=False, target_admits_installed=True)
PINIA_BEFORE_NUXT = link("@pinia/nuxt", "pinia", installed_admits_target=False, target_admits_installed=False)


def test_no_links_is_one_pass() -> None:
    sequence = sequence_moves(["a", "b"], [])

    assert sequence.pass_of == {"a": 1, "b": 1}
    assert sequence.ordered == () and sequence.unresolved == ()


def test_the_requirer_with_a_stale_range_lands_before_its_peer() -> None:
    sequence = sequence_moves(["pinia", "@pinia/nuxt", "vue-router"], [VUE_ROUTER_BEFORE_PINIA, PINIA_BEFORE_NUXT])

    assert sequence.pass_of == {"vue-router": 1, "pinia": 2, "@pinia/nuxt": 2}
    assert sequence.ordered == (VUE_ROUTER_BEFORE_PINIA,)


def test_a_lockstep_pair_shares_a_pass() -> None:
    sequence = sequence_moves(
        ["vue", "renderer"], [link("renderer", "vue", installed_admits_target=False, target_admits_installed=False)]
    )

    assert sequence.pass_of == {"vue": 1, "renderer": 1}
    assert sequence.ordered == ()


def test_a_range_that_admits_both_ends_constrains_nothing() -> None:
    sequence = sequence_moves(
        ["host", "plugin"], [link("plugin", "host", installed_admits_target=True, target_admits_installed=True)]
    )

    assert sequence.pass_of == {"host": 1, "plugin": 1}


def test_a_peer_whose_requirer_rejects_its_old_version_never_lands_after_it() -> None:
    needs_new_host = link("plugin", "host", installed_admits_target=True, target_admits_installed=False)

    sequence = sequence_moves(["plugin", "host", "other"], [needs_new_host])

    assert sequence.pass_of["host"] <= sequence.pass_of["plugin"]


def test_chained_strict_orders_take_one_pass_each() -> None:
    first = link("a", "b", installed_admits_target=False, target_admits_installed=True)
    second = link("b", "c", installed_admits_target=False, target_admits_installed=True)

    sequence = sequence_moves(["c", "b", "a"], [first, second])

    assert sequence.pass_of == {"a": 1, "b": 2, "c": 3}


def test_a_strict_order_on_a_cycle_is_reported_and_shares_a_pass() -> None:
    strict = link("a", "b", installed_admits_target=False, target_admits_installed=True)
    back = link("a", "b", installed_admits_target=True, target_admits_installed=False)  # b must not land after a

    sequence = sequence_moves(["a", "b"], [strict, back])

    assert sequence.unresolved == (strict,)
    assert sequence.pass_of == {"a": 1, "b": 1}


def test_links_to_unknown_moves_are_ignored() -> None:
    sequence = sequence_moves(["a"], [link("a", "ghost", installed_admits_target=False, target_admits_installed=True)])

    assert sequence.pass_of == {"a": 1}


def test_every_honoured_order_holds_on_random_graphs() -> None:
    rng = random.Random(7)
    for _ in range(200):
        moves = [f"m{i}" for i in range(rng.randint(2, 8))]
        links = [
            link(
                *rng.sample(moves, 2),
                installed_admits_target=rng.random() < 0.5,
                target_admits_installed=rng.random() < 0.5,
            )
            for _ in range(rng.randint(0, 12))
        ]

        sequence = sequence_moves(moves, links)

        assert set(sequence.pass_of) == set(moves)
        assert min(sequence.pass_of.values()) == 1
        for honoured in sequence.ordered:
            assert sequence.pass_of[honoured.requirer] < sequence.pass_of[honoured.peer]
        for each in links:
            if not each.target_admits_installed:
                assert sequence.pass_of[each.peer] <= sequence.pass_of[each.requirer]
            if not each.installed_admits_target and each not in sequence.unresolved:
                assert sequence.pass_of[each.requirer] <= sequence.pass_of[each.peer]
