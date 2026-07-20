from collections.abc import Iterable

import requests

from ossiq.clients.batch import BatchClient
from ossiq.clients.client_epss import EpssBatchStrategy
from ossiq.clients.common import get_user_agent
from ossiq.settings import Settings


class EpssApiFirstOrg:
    """
    first.org EPSS API client
    """

    session: requests.Session

    def __init__(self, settings: Settings):

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": get_user_agent()})

        self._strategy = EpssBatchStrategy(self.session)
        self._batch_client = BatchClient(self._strategy)

    def __repr__(self):
        return f"EpssApiFirstOrg(base_url='{self._strategy.BASE_URL}')"

    def get_epss_batch(self, cve_ids: Iterable[str]) -> dict[str, float]:
        if not cve_ids:
            return {}

        # sorted to achieve chunk composition stability across scans,
        # so the cache hit next time.
        unique_ids = sorted(set(cve_ids))

        merged: dict[str, float] = {}
        for chunk_data in self._batch_client.run_batch(unique_ids):
            merged.update(chunk_data)

        return merged
