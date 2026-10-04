"""Tests for pep508 — which declared requirements apply to a project's extras and Python floor."""

from itertools import chain, combinations

import pytest

from ossiq.solver.pep508 import applicable_requirements, marker_reachable, python_floor_minor

ALLAUTH_REQUIRES = [
    "asgiref>=3.8.1",
    "django>=4.2.16",
    'pyjwt[crypto]<3,>=2.0; extra == "headless"',
    'oauthlib<4,>=3.3.0; extra == "idp-oidc"',
    'pyjwt[crypto]<3,>=2.0; extra == "idp-oidc"',
    'oauthlib<4,>=3.3.0; extra == "socialaccount"',
    'requests<3,>=2.0.0; extra == "socialaccount"',
    'pyjwt[crypto]<3,>=2.0; extra == "socialaccount"',
]


class TestExtras:
    def test_an_extra_requirement_is_dropped_when_the_extra_is_off(self) -> None:
        assert applicable_requirements(ALLAUTH_REQUIRES) == {"asgiref": ">=3.8.1", "django": ">=4.2.16"}

    def test_an_extra_requirement_applies_when_the_extra_is_on(self) -> None:
        result = applicable_requirements(ALLAUTH_REQUIRES, extras=["socialaccount"])

        assert result["oauthlib"] == "<4,>=3.3.0"
        assert result["requests"] == "<3,>=2.0.0"
        assert result["pyjwt"] == "<3,>=2.0"

    def test_only_the_enabled_extra_is_applied(self) -> None:
        result = applicable_requirements(ALLAUTH_REQUIRES, extras=["headless"])

        assert "pyjwt" in result
        assert "oauthlib" not in result

    def test_extra_names_are_compared_normalised(self) -> None:
        assert "oauthlib" in applicable_requirements(ALLAUTH_REQUIRES, extras=["IDP_OIDC"])
        assert "requests" in applicable_requirements(['requests; extra == "social-account"'], extras=["Social_Account"])

    def test_enabling_more_extras_never_removes_a_requirement(self) -> None:
        extras = ["headless", "idp-oidc", "socialaccount"]
        subsets = chain.from_iterable(combinations(extras, size) for size in range(len(extras) + 1))
        previous: dict[tuple[str, ...], set[str]] = {}
        for subset in subsets:
            previous[subset] = set(applicable_requirements(ALLAUTH_REQUIRES, extras=subset))
        for smaller, names in previous.items():
            for larger, more_names in previous.items():
                if set(smaller) <= set(larger):
                    assert names <= more_names


class TestPythonMarkers:
    TOMLI = ['tomli>=1.1; python_version < "3.11"']

    def test_a_requirement_for_an_older_python_is_dropped_at_the_floor(self) -> None:
        assert applicable_requirements(self.TOMLI, python_floor="3.12") == {}

    def test_it_is_kept_when_the_floor_still_reaches_that_python(self) -> None:
        assert applicable_requirements(self.TOMLI, python_floor="3.10") == {"tomli": ">=1.1"}

    def test_it_is_kept_without_a_floor(self) -> None:
        assert applicable_requirements(self.TOMLI) == {"tomli": ">=1.1"}

    def test_a_requirement_for_a_newer_python_is_kept(self) -> None:
        assert applicable_requirements(['backports-zstd; python_version >= "3.13"'], python_floor="3.12") == {
            "backports-zstd": ""
        }

    def test_a_marker_on_the_full_version_is_judged_across_the_minor(self) -> None:
        requires = ['shim>=1; python_full_version >= "3.12.4"']

        assert applicable_requirements(requires, python_floor="3.12") == {"shim": ">=1"}
        assert applicable_requirements(requires, python_floor="3.13") == {"shim": ">=1"}

    def test_a_floor_newer_than_the_grid_still_resolves(self) -> None:
        assert applicable_requirements(['late; python_version >= "3.99"'], python_floor="3.99") == {"late": ""}


class TestPlatformMarkers:
    @pytest.mark.parametrize(
        "marker",
        ['sys_platform == "win32"', 'platform_system == "Darwin"', 'platform_machine == "ARM64"', 'os_name == "nt"'],
    )
    def test_a_requirement_for_another_platform_is_kept(self, marker: str) -> None:
        # the project may be installed anywhere, so only an unreachable marker is dropped
        assert applicable_requirements([f"tzdata; {marker}"]) == {"tzdata": ""}

    def test_a_marker_no_environment_reaches_is_dropped(self) -> None:
        assert applicable_requirements(['ghost; sys_platform == "plan9"']) == {}

    def test_an_implementation_marker_is_kept(self) -> None:
        assert applicable_requirements(['cffi; platform_python_implementation == "PyPy"']) == {"cffi": ""}


class TestMerging:
    def test_a_name_declared_twice_gets_the_intersection_of_its_specifiers(self) -> None:
        requires = ["oauthlib>=3.3.0", 'oauthlib<4; extra == "socialaccount"']

        assert applicable_requirements(requires, extras=["socialaccount"]) == {"oauthlib": "<4,>=3.3.0"}

    def test_a_name_whose_second_line_is_inactive_keeps_the_first_alone(self) -> None:
        requires = ["oauthlib>=3.3.0", 'oauthlib<4; extra == "socialaccount"']

        assert applicable_requirements(requires) == {"oauthlib": ">=3.3.0"}

    def test_names_are_canonical(self) -> None:
        assert applicable_requirements(["Django_Allauth>=1"]) == {"django-allauth": ">=1"}

    def test_an_unconstrained_requirement_maps_to_an_empty_specifier(self) -> None:
        assert applicable_requirements(["regex"]) == {"regex": ""}

    def test_a_line_that_does_not_parse_is_skipped(self) -> None:
        assert applicable_requirements(["not a requirement ;;", "requests>=2"]) == {"requests": ">=2"}


class TestPythonFloor:
    @pytest.mark.parametrize(
        ("floor", "expected"),
        [("3.12", (3, 12)), ("3.9.1", (3, 9)), (None, (3, 8)), ("", (3, 8)), ("3", (3, 8)), ("nonsense", (3, 8))],
    )
    def test_floor_parsing(self, floor: str | None, expected: tuple[int, int]) -> None:
        assert python_floor_minor(floor) == expected


def test_marker_reachability_is_cached_per_extras_and_floor() -> None:
    marker_reachable.cache_clear()

    assert marker_reachable('extra == "a"', frozenset({"a"}), (3, 12)) is True
    assert marker_reachable('extra == "a"', frozenset(), (3, 12)) is False
    assert marker_reachable.cache_info().misses == 2
