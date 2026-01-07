"""
CSV renderer for export command.
STUB: Not yet implemented. Will be completed when export command is finalized.
"""

from ossiq.domain.common import Command, UserInterfaceType
from ossiq.service.project import ProjectMetrics
from ossiq.ui.interfaces import AbstractUserInterfaceRenderer


class CsvExportRenderer(AbstractUserInterfaceRenderer):
    """CSV renderer for export command."""

    # Note: Command.EXPORT doesn't exist yet in the enum
    # This will be uncommented when export command is ready
    # command = Command.EXPORT
    # user_interface_type = UserInterfaceType.CSV

    @staticmethod
    def supports(command: Command, user_interface_type: UserInterfaceType) -> bool:
        """Check if this renderer handles export/csv combination."""
        # Will be implemented when Command.EXPORT and PresentationType.CSV are added
        return False

    def render(self, data: ProjectMetrics, destination: str = ".", **kwargs) -> None:
        """Export project metrics to CSV file."""
        raise NotImplementedError("CSV export renderer not yet implemented")
