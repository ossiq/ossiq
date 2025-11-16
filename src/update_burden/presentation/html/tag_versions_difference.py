"""
Filter to format difference in versions.
"""
from dataclasses import dataclass
import semver

from jinja2.ext import Extension
from jinja2 import nodes

from update_burden.domain.version import normalize_version

DIFF_MAJOR = 5
DIFF_MINOR = 4
DIFF_PATCH = 3
DIFF_PRERELEASE = 2
DIFF_BUILD = 1

DIFF_TYPES_MAP = {
    "DIFF_MAJOR": DIFF_MAJOR,
    "DIFF_MINOR": DIFF_MINOR,
    "DIFF_PATCH": DIFF_PATCH,
    "DIFF_PRERELEASE": DIFF_PRERELEASE,
    "DIFF_BUILD": DIFF_BUILD
}


@dataclass
class VersionsDifference:
    version1: str
    version2: str
    diff_index: int


class VersionsDifferenceTagExtension(Extension):
    """
    Implements a custom Jinja2 filter that renders its input using a 
    separate template file for complex formatting (e.g., stylized highlighting).
    """

    TEMPLATE = "tag_versions_difference.html"
    tags = {"versions_difference"}

    def parse(self, parser):
        lineno = parser.stream.expect("name:versions_difference").lineno
        v1 = parser.parse_expression()
        v2 = parser.parse_expression()
        call = self.call_method(
            "_render_versions_difference",
            args=[v1, v2],
            lineno=lineno)

        return nodes.Output([nodes.MarkSafe(call)]).set_lineno(lineno)

    def _compare_versions(self, v1_str: str, v2_str: str) -> VersionsDifference:
        """Helper to split version strings and find the index where they first differ."""
        v1 = semver.Version.parse(v1_str)
        v2 = semver.Version.parse(v2_str)

        diff_index = -1
        if v1.major != v2.major:
            diff_index = DIFF_MAJOR
        elif v1.minor != v2.minor:
            diff_index = DIFF_MINOR
        elif v1.patch != v2.patch:
            diff_index = DIFF_PATCH
        elif v1.prerelease != v2.prerelease:
            diff_index = DIFF_PRERELEASE
        elif v1.build != v2.build:
            diff_index = DIFF_BUILD

        # The diff_index indicates the first differing part of the semantic version.
        # 0: major, 1: minor, 2: patch, 3: prerelease, 4: build.
        # This is used for highlighting the most significant difference in the HTML template.

        return VersionsDifference(
            str(v1),
            str(v2),
            diff_index
        )

    def _render_versions_difference(self, v1_str: str, v2_str: str) -> str:
        """
        The method called by the compiled template. It executes the logic, 
        loads the internal template, and renders the final HTML.
        """

        env = self.environment

        # Load the internal template file
        template = env.get_template(self.TEMPLATE)

        # Compare versions to find the difference
        comparison_data = self._compare_versions(
            normalize_version(v1_str),
            normalize_version(v2_str)
        )
        # Render the template with the necessary data
        rendered_output = template.render(
            v1_str=v1_str,
            v2_str=v2_str,
            comparison=comparison_data,
            diff_types=DIFF_TYPES_MAP
        )

        return rendered_output
