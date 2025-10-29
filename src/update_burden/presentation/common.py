"""
Presentation-related types and Mapping between commands and respective views
"""


from update_burden.domain.common import Command, PresentationType
from update_burden.presentation.overview import view_console


# Mapping between commands and presentation renderers
PRESENTATION_MAP = {
    Command.OVERVIEW: {
        PresentationType.CONSOLE: view_console.display_view
    }
}
