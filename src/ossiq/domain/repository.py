"""
Module to define abstract code Registryike github
"""


class Repository:
    """Class for a Repository."""

    provider: str
    name: str
    owner: str
    description: str | None
    html_url: str | None
    license: str | None
    archived: bool | None
    pushed_at: str | None
    topics: list[str]

    def __init__(
        self,
        provider: str,
        name: str,
        owner: str,
        description: str | None,
        html_url: str | None,
        license: str | None = None,
        archived: bool | None = None,
        pushed_at: str | None = None,
        topics: list[str] | None = None,
    ):
        self.provider = provider
        self.owner = owner
        self.name = name
        self.description = description
        self.html_url = html_url
        self.license = license
        # Abandonment signals, all free from the repository metadata call. archived is the
        # saturating case; pushed_at is the graded one; topics carry an explicit "deprecated"
        # marker when the maintainers set one.
        self.archived = archived
        self.pushed_at = pushed_at
        self.topics = topics or []

    def __repr__(self):
        return f"""{self.provider} Repository(
  name='{self.name}'
  owner='{self.owner}'
  url='{self.html_url}'
)"""
