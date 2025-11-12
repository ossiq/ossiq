"""
Presentation-related types and Mapping between commands and respective views
"""


from update_burden.domain.common import Command, PresentationType
from update_burden.presentation.overview import view_console, view_html


# Mapping between commands and presentation renderers
PRESENTATION_MAP = {
    Command.OVERVIEW: {
        PresentationType.CONSOLE.value: view_console.display_view,
        PresentationType.HTML.value: view_html.display_view
    }
}
