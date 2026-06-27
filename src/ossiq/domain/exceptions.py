"""
Domain-specific exceptions.
"""


class ApplicationError(Exception):
    """Base class for application-specific errors."""

    title: str = "Error"
    hint: str | None = None

    def __init__(self, message: str = "", hint: str | None = None):
        super().__init__(message)
        if hint is not None:
            self.hint = hint


class GithubRateLimitError(ApplicationError):
    """Raised when the GitHub API rate limit is exceeded."""

    title = "GitHub Rate Limit"
    hint = "Set OSSIQ_GITHUB_TOKEN (or --github-token) to raise the limit to 5,000 requests/hour."

    def __init__(self, remaining: str, total: str, reset_time: str):
        self.remaining = remaining
        self.total = total
        self.reset_time = reset_time
        message = f"GitHub API rate limit exceeded. Limit: {remaining} of {total} remaining. Resets at: {reset_time}."
        super().__init__(message)


class UnableLoadPackage(ApplicationError):
    """
    In case NPM is not available or network is not stable
    """

    title = "Package Load Failed"
    hint = "Check network connectivity and npm/pip availability."

    def __init__(self, package: str):
        self.package = package
        super().__init__(f"Unable to load package: {package}")


class DestinationDoesntExist(ApplicationError):
    """
    If there's no destination found
    """

    title = "Destination Not Found"
    hint = "Verify the output path exists before running."


class ProjectPathNotFoundError(ApplicationError):
    title = "Project Not Found"
    hint = "Verify the path points to a valid npm or PyPI project."


class UnknownProjectPackageManager(ApplicationError):
    title = "Unknown Package Manager"
    hint = "ossiq supports npm (package.json) and PyPI (pyproject.toml / requirements.txt)."


class PackageManagerLockfileParsingError(ApplicationError):
    title = "Lockfile Parse Error"
    hint = "Regenerate the lockfile (e.g. `uv lock` or `npm install`) and try again."


class UnknownPackageVersion(ApplicationError):
    title = "Unknown Package Version"
    hint = "Check the package registry for available versions."


class PackageManagerExecutionError(ApplicationError):
    title = "Update Failed"
    hint = "The manifest has been restored to its original state. Review the output above for details."
