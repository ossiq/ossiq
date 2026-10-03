"""npm semver ranges, read by a grammar and desugared by node-semver's own rules.

node-semver 7's `Range` (classes/range.js, ranges/min-version.js) in loose mode, so a range means
here what it means to npm. `GRAMMAR` declares the surface syntax - X-ranges, partial versions,
carets, tildes, hyphens, ``||`` unions - and `RangeDesugarer` rewrites each form it parses into
plain comparator sets, so matching is nothing but comparisons against those::

    "^1.2 || >=3.x <4"  ->  [[>=1.2.0, <2.0.0-0], [>=3.0.0, <4.0.0]]

Each rewrite rule mirrors the node-semver function it is named after; keep them that way.
tests/solver/node_semver_conformance.json pins this module to node-semver's own output, and the
fix for a disagreement is to port the rule node-semver applies, not to rewrite the text before it
is parsed. node-semver runs those rules over the range's text; here they run over numbers, so a
zero spelled "00" is still zero: ``^00.1.2`` holds the minor, where node-semver holds the major.
"""

from __future__ import annotations

import functools
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

import semver
from lark import Lark, Token, Transformer, Tree, v_args
from lark.exceptions import UnexpectedInput, VisitError

# node-semver rejects a version component past Number.MAX_SAFE_INTEGER. Python ints never
# overflow, so without this a range npm refuses ("^9007199254740991.0.0") would parse here.
MAX_SAFE_INTEGER = 2**53 - 1
MAX_VERSION_LENGTH = 256

# node-semver's loose-mode syntax (internal/re.js). Text reaches the grammar with its whitespace
# collapsed to single spaces, as node-semver's Range does first, so " " is the only space here.
# A hyphen range must be the whole branch, as HYPHENRANGE's anchors demand, and a word no rule
# reads is junk, which loose mode drops instead of rejecting the range ("latest || ^1" is ^1).
# Character classes are spelled out because JavaScript's \d is ASCII and Python's is not.
GRAMMAR = r"""
    range: branch (_OR branch)*
    branch: (hyphen | terms)?
    hyphen: partial _HYPHEN partial
    terms: term (_SPACE term)*
    ?term: comparator | junk
    comparator: [OPERATOR _SPACE?] partial -> primitive
              | "^" _SPACE? partial        -> caret
              | _TILDE _SPACE? partial     -> tilde
    junk.-1: JUNK

    partial: _PREFIX? component ("." component ("." component PRERELEASE?)?)? BUILD?
    ?component: NUMBER | WILDCARD
    version: _PREFIX? NUMBER "." NUMBER "." NUMBER PRERELEASE? BUILD?

    OPERATOR: /[<>]=?|=/
    _TILDE: /~>?/
    NUMBER: /[0-9]+/
    WILDCARD: /[xX*]/
    PRERELEASE: /-?(?:[0-9]*[a-zA-Z-][a-zA-Z0-9-]*|[0-9]+)(?:\.(?:[0-9]*[a-zA-Z-][a-zA-Z0-9-]*|[0-9]+))*/
    BUILD: /\+[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*/
    JUNK.-1: /(?:[^ |]|\|(?!\|))+/
    _PREFIX: /[v=][v= ]*/
    _OR: / ?\|\| ?/
    _HYPHEN: " - "
    _SPACE: " "
"""

# LALR reads every well-formed range in one deterministic pass. A word that starts like a version
# and turns to junk ("1.2.3.4", ">=latest") stops it, though: loose mode drops just that word, and
# only Earley can back out of the half-read version to read the word as junk instead. JUNK reads
# any word, so Earley always finds a parse.
RANGE_PARSER = Lark(GRAMMAR, start=["range", "version"], parser="lalr")
LOOSE_RANGE_PARSER = Lark(GRAMMAR, start="range", parser="earley", lexer="dynamic", ambiguity="resolve")


class Operator(StrEnum):
    """A comparator's operator; node-semver spells equality as the empty string."""

    EQ = ""
    GT = ">"
    GTE = ">="
    LT = "<"
    LTE = "<="


@dataclass(frozen=True)
class Comparator:
    """One ``<op><version>`` test; a None version is node-semver's ANY, which admits everything."""

    operator: Operator
    version: semver.Version | None

    def admits(self, version: semver.Version) -> bool:
        """Return whether *version* passes this comparator alone, ignoring the prerelease rule."""
        if self.version is None:
            return True
        order = version.compare(self.version)
        match self.operator:
            case Operator.EQ:
                return order == 0
            case Operator.GT:
                return order > 0
            case Operator.GTE:
                return order >= 0
            case Operator.LT:
                return order < 0
            case Operator.LTE:
                return order <= 0

    def __str__(self) -> str:
        return "" if self.version is None else f"{self.operator}{self.version}"


# node-semver's ANY: the comparator with no version, which "*", "" and ">=0.0.0" all desugar to.
ANY = Comparator(Operator.EQ, None)
# The comparator node-semver emits for a range nothing can satisfy (">x", "<*").
NULL_SET = Comparator(Operator.LT, semver.Version(0, 0, 0, "0"))


@dataclass(frozen=True)
class NpmRange:
    """A parsed npm range: satisfied when every comparator in any one set admits the version.

    Build with `parse_npm_range`. *include_prerelease* is node-semver's ``includePrerelease``
    option; it changes the desugared bounds as well as matching, so it is fixed at parse time.
    """

    comparator_sets: tuple[tuple[Comparator, ...], ...]
    include_prerelease: bool

    def satisfied_by(self, version: semver.Version) -> bool:
        """Return whether *version* satisfies the range, by node-semver's `Range.test`.

        Args:
            version: A version from `parse_loose_semver`.

        Returns:
            True when one comparator set admits *version*. Without *include_prerelease*, a
            prerelease additionally needs a comparator in that set naming a prerelease of the
            same major.minor.patch: ``^1.2.3-beta.1`` admits 1.2.3-beta.2 but not 1.2.4-alpha.
        """
        return any(self.set_admits(comparators, version) for comparators in self.comparator_sets)

    def set_admits(self, comparators: tuple[Comparator, ...], version: semver.Version) -> bool:
        """`satisfied_by` for one comparator set - node-semver's `testSet`."""
        if not all(comparator.admits(version) for comparator in comparators):
            return False
        if version.prerelease is None or self.include_prerelease:
            return True
        release = (version.major, version.minor, version.patch)
        return any(
            comparator.version is not None
            and comparator.version.prerelease is not None
            and (comparator.version.major, comparator.version.minor, comparator.version.patch) == release
            for comparator in comparators
        )

    def min_version(self) -> semver.Version | None:
        """Return the lowest version that satisfies the range, by node-semver's `minVersion`.

        Returns:
            The lowest satisfying version - 0.0.0 for a range with no lower bound - or None when
            nothing satisfies it (``>2 <1``).
        """
        for floor in (semver.Version(0, 0, 0), semver.Version(0, 0, 0, "0")):
            if self.satisfied_by(floor):
                return floor
        lowest: semver.Version | None = None
        for comparators in self.comparator_sets:
            set_floor: semver.Version | None = None
            for comparator in comparators:
                bound = comparator.version
                if bound is None or comparator.operator in (Operator.LT, Operator.LTE):
                    continue
                if comparator.operator == Operator.GT:
                    bound = (
                        bound.bump_patch()
                        if bound.prerelease is None
                        else bound.replace(prerelease=f"{bound.prerelease}.0")
                    )
                if set_floor is None or bound > set_floor:
                    set_floor = bound
            if set_floor is not None and (lowest is None or set_floor < lowest):
                lowest = set_floor
        if lowest is not None and self.satisfied_by(lowest):
            return lowest
        return None

    def __str__(self) -> str:
        """The desugared range as node-semver's `Range.range` prints it ("" for any version)."""
        return "||".join(
            " ".join(str(comparator) for comparator in comparators) for comparators in self.comparator_sets
        )


def parse_loose_semver(text: str) -> semver.Version:
    """Parse a version the way node-semver's loose mode does.

    Loose mode accepts what hand-written manifests contain: a leading ``v`` or ``=``, leading
    zeros, and a prerelease without its hyphen ("1.2.3beta" is 1.2.3-beta). Numeric prerelease
    identifiers are normalised ("rc.01" -> "rc.1") so equal versions print and compare alike.

    Args:
        text: A full three-component version; partial versions ("1.2") are ranges, not versions.

    Returns:
        The parsed version, build metadata kept.

    Raises:
        ValueError: When *text* is not a loose semver version.
    """
    text = text.strip()
    if len(text) > MAX_VERSION_LENGTH:
        raise ValueError(f"version longer than {MAX_VERSION_LENGTH} characters: {text[:40]!r}...")
    try:
        tree = RANGE_PARSER.parse(" ".join(text.split()), start="version")
    except UnexpectedInput as error:
        raise ValueError(f"not a semver version: {text!r}") from error
    major, minor, patch, *suffix = (child for child in tree.children if isinstance(child, Token))
    build = next((token[1:] for token in suffix if token.type == "BUILD"), None)
    return safe_version(int(major), int(minor), int(patch), prerelease_of(suffix), build)


@functools.lru_cache(maxsize=4096)
def parse_npm_range(text: str, include_prerelease: bool = False) -> NpmRange:
    """Parse an npm semver range into comparator sets, by node-semver's `Range` constructor.

    Loose mode drops a comparator it cannot read rather than rejecting the whole range, so
    "latest || ^1" is ``^1``; the range is invalid only when no ``||`` branch survives.

    Args:
        text: The range as written in a manifest ("^1.2.3", ">=14.x", "1 - 2 || 4").
        include_prerelease: node-semver's ``includePrerelease``: prereleases inside the bounds
            satisfy the range without the range having to name them.

    Returns:
        The desugared range.

    Raises:
        ValueError: When no part of *text* is a valid range, or a bound overflows.
    """
    raw = " ".join(text.split())
    try:
        tree = RANGE_PARSER.parse(raw, start="range")
    except UnexpectedInput:
        tree = LOOSE_RANGE_PARSER.parse(raw)
    comparator_sets = desugar(tree, include_prerelease)
    if not comparator_sets:
        raise ValueError(f"not an npm semver range: {text!r}")
    return NpmRange(comparator_sets, include_prerelease)


def desugar(tree: Tree[Token], include_prerelease: bool) -> tuple[tuple[Comparator, ...], ...]:
    """Rewrite a `GRAMMAR` range tree into comparator sets by node-semver's rules.

    Args:
        tree: A ``range`` parse from `RANGE_PARSER` or `LOOSE_RANGE_PARSER`.
        include_prerelease: node-semver's ``includePrerelease``.

    Returns:
        The surviving comparator sets; empty when no branch could be read.

    Raises:
        ValueError: When a bound overflows MAX_SAFE_INTEGER.
    """
    try:
        return RangeDesugarer(include_prerelease).transform(tree)
    except VisitError as error:
        # Lark wraps whatever a rule raises; the rule's own error is the contract.
        raise error.orig_exc from None


@dataclass(frozen=True)
class Partial:
    """A version as a range writes it; a None component is a wildcard - missing, ``x``, ``X`` or ``*``."""

    major: int | None
    minor: int | None
    patch: int | None
    prerelease: str | None


@v_args(inline=True)
class RangeDesugarer(Transformer[Token, tuple[tuple[Comparator, ...], ...]]):
    """node-semver's range rewrite rules, one method per `GRAMMAR` rule.

    Each comparator rule returns the plain comparators its form stands for, and `branch` and
    `range` assemble those the way node-semver's `Range` does.
    """

    def __init__(self, include_prerelease: bool) -> None:
        super().__init__()
        self.include_prerelease = include_prerelease
        # With includePrerelease, a floor read off a wildcard admits its line's prereleases:
        # "1.x" starts at 1.0.0-0 instead of 1.0.0.
        self.floor_prerelease = "0" if include_prerelease else None

    def range(self, *branches: tuple[Comparator, ...]) -> tuple[tuple[Comparator, ...], ...]:
        """The `Range` constructor's union: unreadable and null branches go, and a branch matching anything wins."""
        comparator_sets = [comparators for comparators in branches if comparators]
        if len(comparator_sets) > 1:
            comparator_sets = [
                comparators for comparators in comparator_sets if comparators[0] != NULL_SET
            ] or comparator_sets[:1]
        if len(comparator_sets) > 1:
            comparator_sets = next(
                ([comparators] for comparators in comparator_sets if comparators == (ANY,)), comparator_sets
            )
        return tuple(comparator_sets)

    def branch(self, comparators: tuple[Comparator, ...] = (ANY,)) -> tuple[Comparator, ...]:
        """`Range.parseRange` for one ``||`` branch; an empty branch is node-semver's "", any version.

        ``>=0.0.0`` becomes ANY, duplicates go, the null set wins outright, and ANY goes when
        anything else is left.
        """
        lowest = Comparator(Operator.GTE, semver.Version(0, 0, 0, self.floor_prerelease))
        kept: dict[Comparator, None] = {}
        for comparator in comparators:
            if comparator == NULL_SET:
                return (NULL_SET,)
            kept[ANY if comparator == lowest else comparator] = None
        if len(kept) > 1:
            kept.pop(ANY, None)
        return tuple(kept)

    def terms(self, *terms: tuple[Comparator, ...]) -> tuple[Comparator, ...]:
        return tuple(comparator for term in terms for comparator in term)

    def junk(self, word: Token) -> tuple[Comparator, ...]:
        """A word no comparator rule reads, which loose mode drops."""
        return ()

    def caret(self, partial: Partial) -> tuple[Comparator, ...]:
        """`replaceCaret`: ``^1.2.3`` -> ``>=1.2.3 <2.0.0-0``; below 1.0.0 the first non-zero component is held."""
        major, minor, patch = partial.major, partial.minor, partial.patch
        if major is None:
            return (ANY,)
        if minor is None:
            return self.floor(major, 0, 0), below(major + 1, 0, 0)
        if patch is None:
            return self.floor(major, minor, 0), (below(major + 1, 0, 0) if major else below(0, minor + 1, 0))
        floor = at_least(major, minor, patch, partial.prerelease)
        if major:
            return floor, below(major + 1, 0, 0)
        if minor:
            return floor, below(0, minor + 1, 0)
        return floor, below(0, 0, patch + 1)

    def tilde(self, partial: Partial) -> tuple[Comparator, ...]:
        """`replaceTilde`: ``~1.2.3`` -> ``>=1.2.3 <1.3.0-0``; ``~1`` holds the major, anything longer the minor."""
        major, minor, patch = partial.major, partial.minor, partial.patch
        if major is None:
            return (ANY,)
        if minor is None:
            return self.floor(major, 0, 0), below(major + 1, 0, 0)
        if patch is None:
            return self.floor(major, minor, 0), below(major, minor + 1, 0)
        return at_least(major, minor, patch, partial.prerelease), below(major, minor + 1, 0)

    def primitive(self, operator: Token | None, partial: Partial) -> tuple[Comparator, ...]:
        """`replaceXRange`, then the plain comparator: a missing component is a wildcard, so "1" is "1.x.x".

        ``1.2`` -> ``>=1.2.0 <1.3.0-0``, ``>1`` -> ``>=2.0.0``, ``<=1.2`` -> ``<1.3.0-0``; a full
        version is compared as written.
        """
        major, minor, patch = partial.major, partial.minor, partial.patch
        # "1.x.5" and "x.1" are not ranges; node-semver drops them as unreadable comparators.
        if (major is None and minor is not None) or (minor is None and patch is not None):
            return ()
        op = Operator("" if operator in (None, "=") else operator)
        if major is None:
            return (NULL_SET,) if op in (Operator.GT, Operator.LT) else (ANY,)
        if minor is not None and patch is not None:
            return (Comparator(op, safe_version(major, minor, patch, partial.prerelease)),)
        if op == Operator.EQ:
            if minor is None:
                return self.floor(major, 0, 0), below(major + 1, 0, 0)
            return self.floor(major, minor, 0), below(major, minor + 1, 0)
        # Against a wildcard, ">1" means ">=2.0.0" and "<=1.2" means "<1.3.0-0".
        if op in (Operator.GT, Operator.LTE):
            major, minor = (major + 1, 0) if minor is None else (major, minor + 1)
            op = Operator.GTE if op == Operator.GT else Operator.LT
        minor = 0 if minor is None else minor
        return (below(major, minor, 0),) if op == Operator.LT else (self.floor(major, minor, 0),)

    def hyphen(self, low: Partial, high: Partial) -> tuple[Comparator, ...]:
        """`hyphenReplace`: ``1.2 - 3.4`` -> ``>=1.2.0 <3.5.0-0``; a partial upper bound admits its whole line."""
        comparators: list[Comparator] = []
        major, minor, patch = low.major, low.minor, low.patch
        if major is not None:
            if minor is None:
                comparators.append(self.floor(major, 0, 0))
            elif patch is None:
                comparators.append(self.floor(major, minor, 0))
            else:
                comparators.append(at_least(major, minor, patch, low.prerelease or self.floor_prerelease))
        major, minor, patch = high.major, high.minor, high.patch
        if major is not None:
            if minor is None:
                comparators.append(below(major + 1, 0, 0))
            elif patch is None:
                comparators.append(below(major, minor + 1, 0))
            elif high.prerelease or not self.include_prerelease:
                comparators.append(Comparator(Operator.LTE, safe_version(major, minor, patch, high.prerelease)))
            else:
                comparators.append(below(major, minor, patch + 1))
        return tuple(comparators)

    def partial(self, *tokens: Token) -> Partial:
        components = [
            None if token.type == "WILDCARD" else int(token) for token in tokens if token.type in ("NUMBER", "WILDCARD")
        ]
        major, minor, patch = [*components, None, None, None][:3]
        return Partial(major, minor, patch, prerelease_of(tokens))

    def floor(self, major: int, minor: int, patch: int) -> Comparator:
        """The ``>=`` bound a wildcard leaves: ``1.x`` starts at 1.0.0, or 1.0.0-0 with includePrerelease."""
        return at_least(major, minor, patch, self.floor_prerelease)


def at_least(major: int, minor: int, patch: int, prerelease: str | None = None) -> Comparator:
    """The ``>=`` bound a range starts at."""
    return Comparator(Operator.GTE, safe_version(major, minor, patch, prerelease))


def below(major: int, minor: int, patch: int) -> Comparator:
    """The ``<`` bound that ends a line: ``-0`` keeps the next line's prereleases out too."""
    return Comparator(Operator.LT, safe_version(major, minor, patch, "0"))


def safe_version(
    major: int, minor: int, patch: int, prerelease: str | None = None, build: str | None = None
) -> semver.Version:
    """Build a version, refusing a component node-semver would refuse.

    Raises:
        ValueError: When a component is past MAX_SAFE_INTEGER.
    """
    if max(major, minor, patch) > MAX_SAFE_INTEGER:
        raise ValueError(f"version component past MAX_SAFE_INTEGER: {major}.{minor}.{patch}")
    return semver.Version(major, minor, patch, prerelease, build)


def prerelease_of(tokens: Iterable[Token]) -> str | None:
    """The PRERELEASE among *tokens*, its hyphen dropped and numeric identifiers normalised ("rc.01" -> "rc.1")."""
    for token in tokens:
        if token.type == "PRERELEASE":
            return ".".join(
                str(int(identifier)) if identifier.isdigit() and int(identifier) < MAX_SAFE_INTEGER else identifier
                for identifier in token.removeprefix("-").split(".")
            )
    return None
