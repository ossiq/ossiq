"""
Factory to map possile views with respective presentation types
"""

from collections.abc import Callable

from ossiq.domain.common import (
    Command,
    PresentationType,
    UnknownCommandException,
    UnknownPresentationType,
)
from ossiq.presentation.common import PRESENTATION_MAP


# FIXME: overhaul this entire presentation view. Currently there's no precise interface to follow.
def get_presentation_view(command: Command, presentation_type: PresentationType) -> Callable:
    """
    Get presentation layer
    """
    command_presentation = PRESENTATION_MAP.get(command, None)
    if not command_presentation:
        raise UnknownCommandException(f"Unknown command: {command}")

    presentation_view = command_presentation.get(presentation_type, None)
    if not presentation_view:
        raise UnknownPresentationType(f"Unknown presentation requested: {presentation_type}")

    return presentation_view
