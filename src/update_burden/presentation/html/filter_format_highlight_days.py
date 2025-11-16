"""
Filter to format days into a human-readable string.
"""
from markupsafe import Markup
from jinja2.ext import Extension

from update_burden.timeutil import format_time_days


class FormatHighlightDaysFilterExtension(Extension):
    """
    Implements a custom Jinja2 filter that formats a number of days into a human-readable string.
    """

    TEMPLATE = "filter_format_highlight_days.html"
    filters = {"format_highlight_days"}

    def __init__(self, environment):
        super().__init__(environment)
        environment.filters["format_highlight_days"] = self._format_time_delta

    def _format_time_delta(self,
                           duration_days: int | None,
                           threshold_days: int | None = None) -> str:
        """
        Formats a number of days into a human-readable string (e.g., "2y", "1y", "8m", "3w", "5d").
        TODO: could be a bit nicer implementation/use something similar from somewhere
        """
        # Determine the formatted string and apply highlighting if needed
        formatted_string = "N/A"

        if duration_days is not None:
            formatted_string = format_time_days(duration_days)

        # Load the internal template file
        template = self.environment.get_template(self.TEMPLATE)

        # Render the template with the necessary data
        rendered_output = template.render(
            threshold_days=threshold_days,
            duration_days=duration_days,
            formatted_string=formatted_string
        )

        return Markup(rendered_output)
