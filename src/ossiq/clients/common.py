"""
Common tools for network clients
"""

from typing import Any

import pydantic_core
import requests

from ossiq.domain.common import get_version


def get_user_agent():
    """
    Get HTTP User-Agent
    """
    return f"ossiq-research-tool {get_version()}"


def decode_registry_json(resp: requests.Response) -> Any:
    """Parse a registry document faster and smaller than `resp.json()`.

    A packument runs to tens of MB. pydantic_core parses it about twice as fast and, because it
    shares strings of 64 characters or fewer, leaves a third less of it on the heap.

    Raises:
        ValueError: The body is not JSON, which BatchClient reports as an empty response.
    """
    return pydantic_core.from_json(resp.content)
