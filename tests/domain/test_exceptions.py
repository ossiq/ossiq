"""Tests for domain/exceptions.py — the shared ApplicationError rendering."""

import pytest

from ossiq.domain.exceptions import (
    ApplicationError,
    CredentialStoreUnavailable,
    GithubAuthDenied,
    GithubAuthRequired,
    GithubAuthTimeout,
    GithubRateLimitError,
    UnknownProjectPackageManager,
)
from ossiq.domain.github_auth import DeviceChallenge


class TestApplicationErrorRender:
    """One formatter for both front doors: mcp/server.py used to carry its own copy, marked
    'Mirrors cli.py's error_boundary()'."""

    def test_title_and_message(self):
        assert ApplicationError("something broke").render() == "Error: something broke"

    def test_hint_goes_on_its_own_line(self):
        rendered = ApplicationError("something broke", hint="try --traceback").render()

        assert rendered == "Error: something broke\ntry --traceback"

    def test_subclass_title_and_class_level_hint_are_used(self):
        rendered = UnknownProjectPackageManager("Unable to identify Package Manager for .").render()

        assert rendered.startswith("Unknown Package Manager: Unable to identify Package Manager for .")
        assert "ossiq supports" in rendered

    def test_empty_message_still_names_the_title(self):
        assert ApplicationError().render() == "Error: "


class TestGithubLoginErrors:
    def challenge(self) -> DeviceChallenge:
        return DeviceChallenge(
            user_code="WDJB-4729",
            verification_uri="https://github.com/login/device",
            expires_at=1_000_000,
            interval=5,
            device_code="DEVICE_SECRET",
        )

    def test_required_tells_the_user_where_to_go_and_what_to_type(self):
        rendered = GithubAuthRequired(self.challenge()).render()

        assert "https://github.com/login/device" in rendered
        assert "WDJB-4729" in rendered

    def test_required_carries_the_challenge_for_the_front_doors(self):
        challenge = self.challenge()

        assert GithubAuthRequired(challenge).challenge is challenge

    def test_required_never_exposes_the_device_code(self):
        error = GithubAuthRequired(self.challenge())

        assert "DEVICE_SECRET" not in f"{error!r} {error} {error.render()} {error.args}"

    @pytest.mark.parametrize(
        ("error", "title"),
        [
            (GithubAuthDenied("cancelled"), "GitHub Login Denied"),
            (GithubAuthTimeout("expired"), "GitHub Login Expired"),
            (CredentialStoreUnavailable("locked"), "Credential Store Unavailable"),
        ],
    )
    def test_each_error_renders_its_own_title_message_and_a_hint(self, error, title):
        lines = error.render().splitlines()

        assert lines[0].startswith(f"{title}: ")
        assert len(lines) == 2

    def test_rate_limit_hint_leads_with_the_token_and_offers_the_login_only_with_a_keyring(self):
        rendered = GithubRateLimitError(remaining="0", total="60", reset_time="noon").render()

        assert "containers" in rendered
        assert "where a system keyring is available" in rendered
        assert rendered.index("OSSIQ_GITHUB_TOKEN") < rendered.index("ossiq auth login")
