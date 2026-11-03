"""
Pre-configured HTTP session and batch strategy for the PyPI registry API.
"""

from dataclasses import dataclass
from typing import Any

import requests
from packaging.utils import canonicalize_name

from ossiq.clients.batch import BatchClient, BatchStrategy, BatchStrategySettings, ChunkResult

PYPI_REGISTRY = "https://pypi.org/pypi"
PYPI_SIMPLE = "https://pypi.org/simple"


class PypiBatchStrategy(BatchStrategy):
    """
    BatchStrategy implementation for the PyPI registry.

    Since PyPI has no bulk info endpoint, chunk_size=1 fetches packages
    individually but in parallel across max_workers threads.

    prepare_item  : package name string (identity — used as key in process_response)
    perform_request: GET /{name}/json
    process_response: returns {name: raw_registry_json}
    """

    BASE_URL = PYPI_REGISTRY

    def __init__(self, session: requests.Session):
        self.session = session

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=1,
            max_retries=3,
            max_workers=5,
            request_timeout=15.0,
        )

    def prepare_item(self, item: str) -> str:
        return item

    def perform_request(self, chunk: list) -> requests.Response:
        name = chunk[0]
        return self.session.get(f"{self.BASE_URL}/{name}/json", timeout=self.config.request_timeout)

    def process_response(self, source_items: list, response: ChunkResult) -> dict[str, dict]:  # noqa: ARG002
        return {source_items[0]: response.data[0]}


class PypiVersionBatchStrategy(BatchStrategy):
    """Fetches requires_dist for specific (name, version) pairs from PyPI."""

    BASE_URL = PYPI_REGISTRY

    def __init__(self, session: requests.Session):
        self.session = session

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=1,
            max_retries=3,
            max_workers=5,
            request_timeout=15.0,
        )

    def prepare_item(self, item: tuple[str, str]) -> tuple[str, str]:
        return item

    def perform_request(self, chunk: list) -> requests.Response:
        name, version = chunk[0]
        return self.session.get(
            f"{self.BASE_URL}/{name}/{version}/json",
            timeout=self.config.request_timeout,
        )

    def process_response(self, source_items: list, response: ChunkResult) -> dict:
        name, version = source_items[0]
        info = response.data[0].get("info", {}) if response.data else {}
        return {(name, version): info.get("requires_dist") or []}


@dataclass(frozen=True)
class SimpleIndex:
    """What the Simple API says about one project: its PEP 792 status and each file's attestation."""

    status: dict[str, str]
    """`{"status": ..., "reason": ...}`, with `reason` only when given. Empty when the index declares no
    status, which PEP 792 allows for an active project."""

    provenance: dict[str, str | None]
    """Provenance URL (PEP 740) per file name; None for a file published without an attestation."""


def parse_simple_index(payload: Any) -> SimpleIndex:
    """Read the project status and per-file provenance out of a `simple.v1+json` project page.

    Args:
        payload: The decoded JSON body. Anything that is not an object reads as an empty index.

    Returns:
        The status in the shape the JSON form gives its `project-status` object, and a provenance
        URL (or None) for every named file.
    """
    if not isinstance(payload, dict):
        return SimpleIndex(status={}, provenance={})
    raw_status = payload.get("project-status")
    declared: dict[str, object] = raw_status if isinstance(raw_status, dict) else {}
    status = {key: value for key in ("status", "reason") if isinstance(value := declared.get(key), str)}
    provenance: dict[str, str | None] = {}
    for entry in payload.get("files") or []:
        if not isinstance(entry, dict):
            continue
        filename, url = entry.get("filename"), entry.get("provenance")
        if isinstance(filename, str):
            provenance[filename] = url if isinstance(url, str) else None
    return SimpleIndex(status=status, provenance=provenance)


class PypiSimpleIndexBatchStrategy(BatchStrategy):
    """
    BatchStrategy implementation for the JSON Simple API.

    The legacy JSON API the other strategies use carries neither the PEP 792 project status nor
    the PEP 740 provenance of a file; only the Simple API does.

    prepare_item   : package name string (identity — used as key in process_response)
    perform_request: GET /simple/{name}/ as application/vnd.pypi.simple.v1+json
    process_response: returns {name: SimpleIndex}
    """

    BASE_URL = PYPI_SIMPLE

    def __init__(self, session: requests.Session):
        self.session = session

    @property
    def config(self) -> BatchStrategySettings:
        return BatchStrategySettings(
            chunk_size=1,
            max_retries=3,
            max_workers=5,
            request_timeout=15.0,
        )

    def prepare_item(self, item: str) -> str:
        return item

    def perform_request(self, chunk: list) -> requests.Response:
        name = canonicalize_name(chunk[0])
        return self.session.get(
            f"{self.BASE_URL}/{name}/",
            headers={"Accept": "application/vnd.pypi.simple.v1+json"},
            timeout=self.config.request_timeout,
        )

    def process_response(self, source_items: list, response: ChunkResult) -> dict[str, SimpleIndex]:  # noqa: ARG002
        return {source_items[0]: parse_simple_index(response.data[0])}


__all__ = ("BatchClient", "PypiBatchStrategy", "PypiVersionBatchStrategy")
