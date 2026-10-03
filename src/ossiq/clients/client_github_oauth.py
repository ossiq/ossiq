"""
HTTP client for GitHub's OAuth device flow: request a code, poll for approval, refresh a token.

Every outcome comes back as a typed value: a failed call is an `OAuthFailure`, never an exception,
and no token or code is ever logged.
"""

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

import requests

from ossiq.clients.client_github import GITHUB_API
from ossiq.clients.common import get_user_agent
from ossiq.domain.github_auth import DeviceChallenge, GithubCredentials

logger = logging.getLogger(__name__)

GITHUB_OAUTH_URL = "https://github.com"
GITHUB_HOST = "github.com"
DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
SLOW_DOWN_STEP_SECONDS = 5
"""How much longer to wait after a `slow_down` that names no interval of its own."""


class OAuthErrorCode(StrEnum):
    """The closed set of ways a device-flow call can fail."""

    AUTHORIZATION_PENDING = "authorization_pending"
    SLOW_DOWN = "slow_down"
    EXPIRED_TOKEN = "expired_token"
    ACCESS_DENIED = "access_denied"
    DEVICE_FLOW_DISABLED = "device_flow_disabled"
    REJECTED = "rejected"
    """GitHub named an error with no code of its own here, e.g. a spent refresh token."""
    UNAUTHORIZED = "unauthorized"
    """A REST call answered 401: the token is revoked or invalid."""
    NETWORK_ERROR = "network_error"
    INVALID_RESPONSE = "invalid_response"


KNOWN_ERRORS = {
    member.value: member
    for member in (
        OAuthErrorCode.AUTHORIZATION_PENDING,
        OAuthErrorCode.SLOW_DOWN,
        OAuthErrorCode.EXPIRED_TOKEN,
        OAuthErrorCode.ACCESS_DENIED,
        OAuthErrorCode.DEVICE_FLOW_DISABLED,
    )
}


@dataclass(frozen=True)
class OAuthFailure:
    """Why a call did not produce its result, as a value the caller branches on."""

    code: OAuthErrorCode
    error: str = ""
    """The `error` GitHub sent, or what it said for a REST call; empty when it sent none."""
    description: str = ""
    interval: int | None = None
    """Seconds to wait before the next poll. Set for AUTHORIZATION_PENDING and SLOW_DOWN only."""


def failure_from_body(body: dict, interval: int) -> OAuthFailure | None:
    """Turn an `error` body into a failure, or return None when the body has no `error`.

    Args:
        body: A decoded token-endpoint response.
        interval: The poll interval in force, used when the body does not name a new one.
    """
    error = body.get("error")
    if not isinstance(error, str):
        return None
    code = KNOWN_ERRORS.get(error, OAuthErrorCode.REJECTED)
    description = str(body.get("error_description") or "")
    next_interval = None
    if code is OAuthErrorCode.AUTHORIZATION_PENDING:
        next_interval = interval
    elif code is OAuthErrorCode.SLOW_DOWN:
        named = body.get("interval")
        has_named = isinstance(named, int) and not isinstance(named, bool)
        next_interval = named if has_named else interval + SLOW_DOWN_STEP_SECONDS
    return OAuthFailure(code, error, description, next_interval)


def is_github_page(uri: str) -> bool:
    """Report whether a URI is an https page on github.com itself, with no credentials or custom port in it.

    The user is told to type a login code at this address, so an answer that names any other host is
    refused rather than shown.
    """
    parts = urlsplit(uri)
    try:
        port = parts.port
    except ValueError:
        return False
    return parts.scheme == "https" and parts.hostname == GITHUB_HOST and port in (None, 443) and parts.username is None


class GithubOAuthClient:
    """Talks to GitHub's device-flow endpoints with an app's public `client_id`.

    No `client_secret` is involved anywhere: the device flow and its token refresh do not take one.
    """

    def __init__(
        self,
        client_id: str,
        *,
        oauth_url: str = GITHUB_OAUTH_URL,
        api_url: str = GITHUB_API,
        session: requests.Session | None = None,
        clock: Callable[[], float] = time.time,
        timeout: float = 15.0,
    ):
        """Create a client.

        Args:
            client_id: The OAuth app's client ID.
            oauth_url: Base URL of the OAuth endpoints.
            api_url: Base URL of the REST API, used to look up the login behind a token.
            session: Session to send requests with; a new one when omitted.
            clock: Source of epoch seconds, to turn `expires_in` into `expires_at`.
            timeout: Seconds before a request is given up on.
        """
        self.client_id = client_id
        self.oauth_url = oauth_url.rstrip("/")
        self.api_url = api_url.rstrip("/")
        self.session = session or requests.Session()
        self.clock = clock
        self.timeout = timeout

    def request_device_code(self) -> DeviceChallenge | OAuthFailure:
        """Start a login. No scope is requested, so the token can read public data only.

        Returns:
            The challenge to show the user, or why GitHub refused, e.g. DEVICE_FLOW_DISABLED.
        """
        body = self.post_form("/login/device/code", {"client_id": self.client_id})
        if isinstance(body, OAuthFailure):
            return body
        failure = failure_from_body(body, interval=0)
        if failure is not None:
            return failure
        try:
            challenge = DeviceChallenge(
                user_code=str(body["user_code"]),
                verification_uri=str(body["verification_uri"]),
                expires_at=int(self.clock() + float(body["expires_in"])),
                interval=int(body["interval"]),
                device_code=str(body["device_code"]),
            )
        except (KeyError, TypeError, ValueError):
            return OAuthFailure(OAuthErrorCode.INVALID_RESPONSE, description="device code response is incomplete")
        if not is_github_page(challenge.verification_uri):
            # The address itself is left out: it is whatever the answer claimed, not something to echo.
            return OAuthFailure(
                OAuthErrorCode.INVALID_RESPONSE, description="device code response names a page outside github.com"
            )
        return challenge

    def poll_once(self, challenge: DeviceChallenge, interval: int) -> GithubCredentials | OAuthFailure:
        """Ask GitHub once whether the user has approved the login.

        Args:
            challenge: The challenge being polled.
            interval: The seconds between polls currently in force.

        Returns:
            The credentials once approved. Otherwise a failure: AUTHORIZATION_PENDING and SLOW_DOWN
            carry the interval to use next, the other codes end the login.
        """
        body = self.post_form(
            "/login/oauth/access_token",
            {"client_id": self.client_id, "device_code": challenge.device_code, "grant_type": DEVICE_GRANT_TYPE},
        )
        return self.credentials_or_failure(body, interval)

    def refresh(self, refresh_token: str) -> GithubCredentials | OAuthFailure:
        """Exchange a refresh token for new credentials.

        GitHub rotates both tokens and accepts each refresh token once, so a failure here may mean
        another process already refreshed.

        Args:
            refresh_token: The refresh token to spend.

        Returns:
            The new credentials, or why GitHub refused.
        """
        body = self.post_form(
            "/login/oauth/access_token",
            {"client_id": self.client_id, "grant_type": "refresh_token", "refresh_token": refresh_token},
        )
        return self.credentials_or_failure(body, interval=0)

    def fetch_login(self, access_token: str) -> str | OAuthFailure:
        """Look up the GitHub login a token belongs to.

        Args:
            access_token: The token to ask `GET /user` about.

        Returns:
            The login, or a failure; UNAUTHORIZED means the token is revoked or invalid.
        """
        try:
            response = self.session.get(
                f"{self.api_url}/user",
                headers={
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": get_user_agent(),
                    "Authorization": f"Bearer {access_token}",
                },
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            logger.debug("GitHub login lookup failed: %s", type(exc).__name__)
            return OAuthFailure(OAuthErrorCode.NETWORK_ERROR, description=str(exc))
        if response.status_code == 401:
            return OAuthFailure(OAuthErrorCode.UNAUTHORIZED, description="GitHub rejected the token")
        try:
            login = response.json().get("login")
        except (ValueError, AttributeError):
            login = None
        if isinstance(login, str):
            return login
        return OAuthFailure(OAuthErrorCode.INVALID_RESPONSE, description=f"HTTP {response.status_code} without a login")

    def post_form(self, path: str, form: dict[str, str]) -> dict | OAuthFailure:
        """POST a form to an OAuth endpoint and decode the JSON answer.

        GitHub reports errors in the body and often with HTTP 200, so the status is ignored.
        """
        try:
            response = self.session.post(
                f"{self.oauth_url}{path}",
                data=form,
                # Without this the endpoints answer form-encoded.
                headers={"Accept": "application/json", "User-Agent": get_user_agent()},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            logger.debug("GitHub OAuth request to %s failed: %s", path, type(exc).__name__)
            return OAuthFailure(OAuthErrorCode.NETWORK_ERROR, description=str(exc))
        try:
            body = response.json()
        except ValueError:
            body = None
        if not isinstance(body, dict):
            return OAuthFailure(
                OAuthErrorCode.INVALID_RESPONSE, description=f"HTTP {response.status_code} without a JSON object"
            )
        return body

    def credentials_or_failure(self, body: dict | OAuthFailure, interval: int) -> GithubCredentials | OAuthFailure:
        """Read a token-endpoint answer as credentials, or as the failure it describes."""
        if isinstance(body, OAuthFailure):
            return body
        failure = failure_from_body(body, interval)
        if failure is not None:
            return failure
        access_token = body.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            return OAuthFailure(OAuthErrorCode.INVALID_RESPONSE, description="response holds no access_token")
        expires_in = body.get("expires_in")
        expires_at = None
        if isinstance(expires_in, (int, float)) and not isinstance(expires_in, bool):
            expires_at = int(self.clock() + expires_in)
        refresh_token = body.get("refresh_token")
        return GithubCredentials(
            access_token=access_token,
            refresh_token=refresh_token if isinstance(refresh_token, str) and refresh_token else None,
            expires_at=expires_at,
            scope=str(body.get("scope") or ""),
            token_type=str(body.get("token_type") or "bearer"),
        )
