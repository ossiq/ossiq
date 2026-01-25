"""
Initialize HTML templates engine environment for a specifi command.
"""

import os

from jinja2 import ChoiceLoader, Environment, PackageLoader, select_autoescape

from ossiq.ui.html.filter_format_highlight_days import FormatHighlightDaysFilterExtension
from ossiq.ui.html.tag_versions_difference import VersionsDifferenceTagExtension


def configure_template_environment(base_template: str):
    """
    Configures Jinja2 to look inside the installed 'ossiq' package.
    """
    # Extract the directory and filename from the path provided
    # e.g., "html_templates/main.html" -> "html_templates", "main.html"
    templates_subpath = os.path.dirname(base_template)
    base_template_name = os.path.basename(base_template)

    env = Environment(
        loader=ChoiceLoader(
            [
                # 1. Look in the specific UI templates folder
                PackageLoader("ossiq", "ui/html_templates"),
                # 2. Look in the path relative to the ossiq root as a fallback
                PackageLoader("ossiq", templates_subpath),
            ]
        ),
        extensions=[VersionsDifferenceTagExtension, FormatHighlightDaysFilterExtension],
        autoescape=select_autoescape(),
    )

    return env, env.get_template(base_template_name)
