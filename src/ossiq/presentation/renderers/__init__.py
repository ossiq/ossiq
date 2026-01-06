"""
Presentation renderers for all commands.

This module registers all available renderers with the presentation registry.
"""

from ossiq.presentation.registry import register_renderers
from ossiq.presentation.renderers.scan.console import ConsoleScanRenderer
from ossiq.presentation.renderers.scan.html import HtmlScanRenderer

# Note: Export renderers are stubs and not registered yet
# from ossiq.presentation.renderers.export.json import JsonExportRenderer
# from ossiq.presentation.renderers.export.csv import CsvExportRenderer

# Register only implemented renderers
# Order matters - first match wins (similar to PACKAGE_MANAGERS)
register_renderers(
    ConsoleScanRenderer,
    HtmlScanRenderer,
)
