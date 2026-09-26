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

    def render(self) -> str:
        """Render as plain text for a surface that has no panel to draw.

        The title and the hint are the whole point of this exception — dropping them left MCP
        agents staring at a bare class name with no indication of what to do about it. `cli.py`
        renders the same three parts as a Rich panel instead.

        Returns:
            "title: message", plus the hint on its own line when one is set.
        """
        text = f"{self.title}: {self}"
        return f"{text}\n{self.hint}" if self.hint else text


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
    hint = (
        "ossiq supports npm (package.json), PyPI with a lockfile (pyproject.toml + uv.lock or "
        "pylock.toml), PyPI via a plain [project].dependencies section (pyproject.toml, no "
        "lockfile required), and classic pip (requirements.txt)."
    )


class PackageManagerLockfileParsingError(ApplicationError):
    title = "Lockfile Parse Error"
    hint = "Regenerate the lockfile (e.g. `uv lock` or `npm install`) and try again."


class UnknownPackageVersion(ApplicationError):
    title = "Unknown Package Version"
    hint = "Check the package registry for available versions."


class PackageManagerExecutionError(ApplicationError):
    title = "Update Failed"
    hint = "The manifest has been restored to its original state. Review the output above for details."


class UnknownEcosystem(ApplicationError):
    title = "Unknown Ecosystem"
    hint = "Provided ecosystem is not recognized among supported ecosystems (NPM, etc...)"


class SecurityDataIncomplete(ApplicationError):
    title = "Security Data Incomplete"
    hint = (
        "A security-tier run whose vulnerability data did not arrive reports 'nothing to do' "
        "identically to a clean project. Re-run when the source is reachable, or pass "
        "--allow-partial to accept the result as incomplete."
    )


class RuntimeNotProvided(ApplicationError):
    """Raised when an MCP caller omits the runtime its project runs on."""

    title = "Runtime Not Provided"
    hint = (
        'Pass `runtime`, keyed by the project\'s registry: {"node": "<node -v>"} for npm or '
        '{"python": "<python --version>"} for PyPI, taken from the same shell that runs the '
        "project's tests. Pass \"unknown\" if you can't tell; never guess."
    )


class InvalidRuntime(ApplicationError):
    """Raised when a provided runtime doesn't fit the scanned project."""

    title = "Invalid Runtime"
    hint = 'An npm project takes {"node": ...}; a PyPI project takes {"python": ...}.'
