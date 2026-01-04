"""
Presentation-related types and Mapping between commands and respective views
"""

from ossiq.domain.common import Command, PresentationType
from ossiq.presentation.scan import view_console, view_html

# Mapping between commands and presentation renderers
PRESENTATION_MAP = {
    Command.SCAN: {
        PresentationType.CONSOLE.value: view_console.display_view,
        PresentationType.HTML.value: view_html.display_view,
    }
}
