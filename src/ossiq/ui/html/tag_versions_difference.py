"""
Filter to format difference in versions.
"""

from jinja2 import nodes
from jinja2.ext import Extension

from ossiq.domain.version import (
    VERSION_DIFF_TYPES_MAP,
    VersionsDifference,
)


class VersionsDifferenceTagExtension(Extension):
    """
    Implements a custom Jinja2 filter that renders its input using a
    separate template file for complex formatting (e.g., stylized highlighting).
    """

    TEMPLATE = "tag_versions_difference.html"
    tags = {"versions_difference"}

    def parse(self, parser):
        lineno = parser.stream.expect("name:versions_difference").lineno
        version_diff_index = parser.parse_expression()
        call = self.call_method("_render_versions_difference", args=[version_diff_index], lineno=lineno)

        return nodes.Output([nodes.MarkSafe(call)]).set_lineno(lineno)

    def _render_versions_difference(self, version_diff_index: VersionsDifference) -> str:
        """
        The method called by the compiled template. It executes the logic,
        loads the internal template, and renders the final HTML.
        """

        env = self.environment

        # Load the internal template file
        template = env.get_template(self.TEMPLATE)

        # Render the template with the necessary data
        rendered_output = template.render(comparison=version_diff_index, diff_types=VERSION_DIFF_TYPES_MAP)

        return rendered_output
