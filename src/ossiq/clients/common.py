"""
Common tools for network clients
"""

from ossiq.domain.common import get_version


def get_user_agent():
    """
    Get HTTP User-Agent
    """
    return f"ossiq-research-tool {get_version()}"
