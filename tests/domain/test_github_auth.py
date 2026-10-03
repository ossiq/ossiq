"""Tests for domain/github_auth.py — the device-flow value types."""

import dataclasses

import pytest

from ossiq.domain.github_auth import REFRESH_MARGIN_SECONDS, DeviceChallenge, GithubCredentials

EXPIRES_AT = 1_000_000


class TestNeedsRefresh:
    def test_not_due_while_more_than_the_margin_remains(self):
        credentials = GithubCredentials(access_token="gho_a", expires_at=EXPIRES_AT)

        assert credentials.needs_refresh(EXPIRES_AT - REFRESH_MARGIN_SECONDS - 1) is False

    def test_boundary_is_exactly_the_margin_before_expiry(self):
        credentials = GithubCredentials(access_token="gho_a", expires_at=EXPIRES_AT)

        assert credentials.needs_refresh(EXPIRES_AT - REFRESH_MARGIN_SECONDS) is False
        assert credentials.needs_refresh(EXPIRES_AT - REFRESH_MARGIN_SECONDS + 1) is True

    def test_due_once_expired(self):
        credentials = GithubCredentials(access_token="gho_a", expires_at=EXPIRES_AT)

        assert credentials.needs_refresh(EXPIRES_AT + 3600) is True

    def test_never_due_without_an_expiry(self):
        credentials = GithubCredentials(access_token="ghp_pat", expires_at=None)

        assert credentials.needs_refresh(10**12) is False

    def test_margin_is_five_minutes(self):
        assert REFRESH_MARGIN_SECONDS == 300


class TestSecretsStayOutOfRepr:
    def test_credentials_hide_both_tokens(self):
        credentials = GithubCredentials(access_token="gho_SECRET_ACCESS", refresh_token="ghr_SECRET_REFRESH")

        text = f"{credentials!r} {credentials}"

        assert "SECRET" not in text

    def test_challenge_hides_the_device_code_but_shows_what_the_user_needs(self):
        challenge = DeviceChallenge(
            user_code="WDJB-4729",
            verification_uri="https://github.com/login/device",
            expires_at=EXPIRES_AT,
            interval=5,
            device_code="DEVICE_SECRET",
        )

        text = f"{challenge!r} {challenge}"

        assert "DEVICE_SECRET" not in text
        assert "WDJB-4729" in text
        assert "https://github.com/login/device" in text


def test_values_are_immutable():
    credentials = GithubCredentials(access_token="gho_a")

    with pytest.raises(dataclasses.FrozenInstanceError):
        credentials.access_token = "other"  # ty: ignore[invalid-assignment]


class TestSecondsLeft:
    def make(self) -> DeviceChallenge:
        return DeviceChallenge(
            user_code="WDJB-4729",
            verification_uri="https://github.com/login/device",
            expires_at=EXPIRES_AT,
            interval=5,
            device_code="dc",
        )

    def test_counts_down_to_expiry(self):
        assert self.make().seconds_left(EXPIRES_AT - 900) == 900

    def test_rounds_a_partial_second_up(self):
        assert self.make().seconds_left(EXPIRES_AT - 10.2) == 11

    def test_is_never_negative(self):
        assert self.make().seconds_left(EXPIRES_AT + 50) == 0
