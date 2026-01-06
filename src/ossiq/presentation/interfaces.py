"""
Abstract interface for presentation renderers.
Follows the same pattern as AbstractPackageManagerApi.
"""

import abc
from typing import Any

from ossiq.domain.common import Command, PresentationType
from ossiq.settings import Settings


class AbstractPresentationRenderer(abc.ABC):
    """
    Abstract base class for all presentation renderers.

    Similar to AbstractPackageManagerApi, this provides a common interface
    for all renderers with both static detection and instance methods.
    """

    # Class attributes (to be overridden by subclasses)
    command: Command
    presentation_type: PresentationType
    settings: Settings

    def __init__(self, settings: Settings):
        """Initialize renderer with settings."""
        self.settings = settings

    @staticmethod
    @abc.abstractmethod
    def supports(command: Command, presentation_type: PresentationType) -> bool:
        """
        Check if this renderer supports the given command/presentation combination.

        Similar to has_package_manager() in package manager adapters.

        Args:
            command: The command being executed (SCAN, EXPORT, etc.)
            presentation_type: The output format (CONSOLE, HTML, etc.)

        Returns:
            True if this renderer supports the combination, False otherwise
        """
        pass

    @abc.abstractmethod
    def render(self, data: Any, **kwargs) -> None:
        """
        Render the data according to the presentation format.

        Args:
            data: The data to render (e.g., ProjectMetrics for scan command)
            **kwargs: Additional rendering options (destination, thresholds, etc.)
        """
        pass

    def __repr__(self):
        return f"{self.__class__.__name__}(command={self.command}, type={self.presentation_type})"
