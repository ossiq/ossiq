"""
Renderer discovery and registration system.
Mirrors the PACKAGE_MANAGERS tuple pattern from adapters/package_managers/api.py
"""

from ossiq.domain.common import Command, PresentationType, UnknownCommandException, UnknownPresentationType
from ossiq.presentation.interfaces import AbstractPresentationRenderer
from ossiq.settings import Settings

# Registry of all available renderers (populated via register_renderers)
# Similar to PACKAGE_MANAGERS tuple
RENDERERS: tuple[type[AbstractPresentationRenderer], ...] = ()


def register_renderers(*renderers: type[AbstractPresentationRenderer]) -> None:
    """
    Register renderer classes. Called during module initialization.
    Allows for late registration to avoid circular imports.

    Args:
        *renderers: Renderer classes to register
    """
    global RENDERERS
    RENDERERS = renderers


def get_renderer(
    command: Command, presentation_type: PresentationType, settings: Settings
) -> AbstractPresentationRenderer:
    """
    Get appropriate renderers for command and presentation type.

    Similar to create_package_managers() but returns single instance instead of iterable.

    Args:
        command: The command being executed (SCAN, EXPORT, etc.)
        presentation_type: Desired output format (CONSOLE, HTML, etc.)
        settings: Application settings

    Returns:
        Instantiated renderer instances

    Raises:
        UnknownCommandException: No renderer found for command
        UnknownPresentationType: No renderer found for presentation type

    """
    renderer_instances = [
        renderer_class(settings) for renderer_class in RENDERERS if renderer_class.supports(command, presentation_type)
    ]

    if len(renderer_instances) > 1:
        raise TypeError(f"Only single renderer allowed for pair ({command}, {presentation_type})")

    if renderer_instances:
        return renderer_instances[0]

    # Check if command is known (any renderer supports it)
    command_exists = any(
        renderer_class.supports(command, pt) for renderer_class in RENDERERS for pt in PresentationType
    )

    if not command_exists:
        raise UnknownCommandException(f"Unknown command: {command}")

    raise UnknownPresentationType(
        f"Unknown presentation type '{presentation_type.value}' for command '{command.value}'"
    )
