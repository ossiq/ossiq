"""
Domain-specific exceptions.
"""


class ApplicationError(Exception):
    """Base class for application-specific errors."""

    pass


class GithubRateLimitError(ApplicationError):
    """Raised when the GitHub API rate limit is exceeded."""

    def __init__(self, remaining: str, total: str, reset_time: str):
        self.remaining = remaining
        self.total = total
        self.reset_time = reset_time
        message = f"GitHub API rate limit exceeded. Limit: {remaining} of {total} remaining. Resets at: {reset_time}."
        super().__init__(message)


class DestinationDoesntExist(Exception):
    """
    If there's no destination found
    """

    pass


class ProjectPathNotFoundError(Exception):
    pass


class UnknownProjectPackageManager(Exception):
    pass


class PackageManagerLockfileParsingError(Exception):
    pass
