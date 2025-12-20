"""
Initialize HTML templates engine environment for a specifi command.
"""

import os

from jinja2 import ChoiceLoader, Environment, PackageLoader, select_autoescape

from ossiq.presentation.html.filter_format_highlight_days import FormatHighlightDaysFilterExtension
from ossiq.presentation.html.tag_versions_difference import VersionsDifferenceTagExtension


def configure_template_environment(base_template: str):
    """
    Configure HTML templates engine environment for a specifi command.
    The `base_template` argument implies that the rest of command templates
    located relatively to the base template.
    """

    templates_path = os.path.dirname(base_template)
    base_template_name = os.path.basename(base_template)

    env = Environment(
        loader=ChoiceLoader(
            [
                PackageLoader("ossiq", package_path="./presentation/html_templates"),
                PackageLoader("ossiq", package_path=templates_path),
            ]
        ),
        extensions=[VersionsDifferenceTagExtension, FormatHighlightDaysFilterExtension],
        autoescape=select_autoescape(),
    )

    return env, env.get_template(base_template_name)
