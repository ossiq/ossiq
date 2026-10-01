"""Tests for ui/auth.py — what the user sees while logging in to GitHub."""

from unittest.mock import patch

import pytest

from ossiq.domain.github_auth import AuthStatus, DeviceChallenge, TokenSource
from ossiq.service.github_auth import AuthSkipReason
from ossiq.ui.auth import (
    REVOKE_URL,
    describe_backend,
    format_expiry,
    show_auth_skipped,
    show_auth_status,
    show_login_challenge,
    show_login_success,
    show_logout,
)

NOW = 1_000_000.0


def challenge(expires_in: int = 900) -> DeviceChallenge:
    return DeviceChallenge(
        user_code="WDJB-4729",
        verification_uri="https://github.com/login/device",
        expires_at=int(NOW) + expires_in,
        interval=5,
        device_code="DEVICE_SECRET",
    )


class TestLoginChallenge:
    def test_shows_where_to_go_and_what_to_type(self, capsys):
        show_login_challenge(challenge(), now=NOW, waiting=True, err=False)

        out = capsys.readouterr().out
        assert "https://github.com/login/device" in out
        assert "WDJB-4729" in out
        assert "15 minutes" in out

    def test_never_shows_the_device_code(self, capsys):
        show_login_challenge(challenge(), now=NOW, waiting=True, err=True)
        show_login_challenge(challenge(), now=NOW, waiting=False, err=False)

        captured = capsys.readouterr()
        assert "DEVICE_SECRET" not in captured.out + captured.err

    def test_a_scan_prints_on_stderr_so_piped_output_stays_clean(self, capsys):
        show_login_challenge(challenge(), now=NOW, waiting=False, err=True)

        captured = capsys.readouterr()
        assert captured.out == ""
        assert "WDJB-4729" in captured.err

    def test_the_auth_command_prints_on_stdout(self, capsys):
        show_login_challenge(challenge(), now=NOW, waiting=False, err=False)

        captured = capsys.readouterr()
        assert captured.err == ""
        assert "WDJB-4729" in captured.out

    def test_while_waiting_it_says_how_to_pick_the_login_up_again(self, capsys):
        show_login_challenge(challenge(), now=NOW, waiting=True, err=False)

        out = capsys.readouterr().out
        assert "Waiting for approval" in out
        assert "--resume" in out

    def test_when_not_waiting_it_says_to_run_the_command_again(self, capsys):
        show_login_challenge(challenge(), now=NOW, waiting=False, err=False)

        out = capsys.readouterr().out
        assert "run the command again" in out
        assert "Waiting for approval" not in out

    def test_a_nearly_expired_code_says_so(self, capsys):
        show_login_challenge(challenge(expires_in=30), now=NOW, waiting=False, err=False)

        assert "less than a minute" in capsys.readouterr().out

    def test_a_long_url_is_not_wrapped_or_restyled(self, capsys):
        long_uri = "https://github.com/login/device/" + "x" * 150
        show_login_challenge(
            DeviceChallenge("WDJB-4729", long_uri, int(NOW) + 900, 5, "dc"), now=NOW, waiting=False, err=False
        )

        assert long_uri in capsys.readouterr().out


class TestLoginSuccess:
    def test_names_the_account_and_where_the_token_lives(self, capsys):
        show_login_success("octocat", "keyring.backends.macOS.Keyring", err=False)

        out = capsys.readouterr().out
        assert "as @octocat" in out
        assert "macOS Keychain" in out

    def test_copes_with_an_unknown_login(self, capsys):
        show_login_success(None, None, err=False)

        assert "Logged in to GitHub." in capsys.readouterr().out


class TestSkipped:
    @pytest.mark.parametrize("reason", [AuthSkipReason.DISABLED, AuthSkipReason.CI])
    def test_the_users_own_choice_is_not_nagged_about(self, reason):
        with patch("ossiq.ui.auth.show_warning") as warn:
            show_auth_skipped(reason, "")

        warn.assert_not_called()

    @pytest.mark.parametrize(
        ("reason", "expected"),
        [
            (AuthSkipReason.STORE_UNAVAILABLE, "OSSIQ_GITHUB_TOKEN"),
            (AuthSkipReason.LOGIN_DENIED, "ossiq auth login"),
            (AuthSkipReason.LOGIN_EXPIRED, "new code"),
            (AuthSkipReason.LOGIN_UNAVAILABLE, "Could not start"),
        ],
    )
    def test_every_other_reason_is_warned_about_with_a_way_forward(self, reason, expected):
        with patch("ossiq.ui.auth.show_warning") as warn:
            show_auth_skipped(reason, "the keyring is locked")

        assert expected in warn.call_args.args[0]

    def test_the_detail_is_included(self):
        with patch("ossiq.ui.auth.show_warning") as warn:
            show_auth_skipped(AuthSkipReason.STORE_UNAVAILABLE, "The system keyring is locked.")

        assert "The system keyring is locked." in warn.call_args.args[0]


class TestStatus:
    def test_a_keyring_login_shows_everything_known(self, capsys):
        status = AuthStatus(
            source=TokenSource.KEYRING,
            login="octocat",
            scope="",
            expires_at=int(NOW) + 3600,
            backend="keyring.backends.macOS.Keyring",
        )

        show_auth_status(status, now=NOW)

        out = capsys.readouterr().out
        assert "GitHub login (system keyring)" in out
        assert "@octocat" in out
        assert "none (public data only)" in out
        assert "1970-01-12" in out
        assert "macOS Keychain" in out

    def test_no_token_points_at_the_login(self, capsys):
        show_auth_status(AuthStatus(source=None, backend="keyring.backends.macOS.Keyring"), now=NOW)

        out = capsys.readouterr().out
        assert "Not logged in" in out
        assert "ossiq auth login" in out
        assert "macOS Keychain" in out

    def test_no_token_and_no_keyring_points_at_the_token_not_the_login(self, capsys):
        """A container cannot hold a login, so telling it to log in sends the user nowhere."""
        show_auth_status(AuthStatus(source=None, backend="keyring.backends.fail.Keyring"), now=NOW)

        out = capsys.readouterr().out
        assert "OSSIQ_GITHUB_TOKEN" in out
        assert "ossiq auth login" not in out
        assert "none available" in out

    def test_an_unconfirmed_login_is_not_passed_off_as_known(self, capsys):
        show_auth_status(AuthStatus(source=TokenSource.ENV_OSSIQ, login=None), now=NOW)

        out = capsys.readouterr().out
        assert "OSSIQ_GITHUB_TOKEN environment variable" in out
        assert "unknown" in out

    def test_a_non_keyring_token_shows_no_scope_or_expiry(self, capsys):
        show_auth_status(AuthStatus(source=TokenSource.CLI_FLAG, login="octocat"), now=NOW)

        out = capsys.readouterr().out
        assert "Scope" not in out
        assert "Expires" not in out

    def test_a_token_left_in_the_legacy_file_is_flagged(self, capsys):
        show_auth_status(AuthStatus(source=TokenSource.KEYRING, login="octocat", legacy_config_in_use=True), now=NOW)

        assert "plaintext in ~/.ossiq/config" in capsys.readouterr().out


class TestLogout:
    def test_says_the_login_is_removed_and_how_to_revoke_it_on_github(self, capsys):
        show_logout(removed=True, remaining=None)

        out = capsys.readouterr().out
        assert "removed from this machine" in out
        assert REVOKE_URL in out

    def test_names_a_token_that_still_applies(self, capsys):
        show_logout(removed=True, remaining=TokenSource.CONFIG_FILE)

        assert "config file" in capsys.readouterr().out

    def test_when_the_keyring_is_unusable_nothing_is_claimed_removed(self, capsys):
        show_logout(removed=False, remaining=None, reason="No system keyring is available on this machine.")

        out = capsys.readouterr().out
        assert "Nothing to remove" in out
        assert "No system keyring" in out
        assert REVOKE_URL not in out


class TestHelpers:
    def test_known_backends_get_human_names(self):
        assert describe_backend("keyring.backends.Windows.WinVaultKeyring") == "Windows Credential Manager"
        assert describe_backend("keyring.backends.SecretService.Keyring").startswith("Secret Service")

    def test_unknown_backends_keep_their_class_name(self):
        assert describe_backend("acme.Vault") == "acme.Vault"

    def test_no_backend_is_unavailable(self):
        assert describe_backend(None) == "unavailable"

    def test_expiry_formats_and_flags_the_past(self):
        assert format_expiry(None, NOW) == "never"
        assert format_expiry(int(NOW) + 60, NOW).endswith("UTC")
        assert format_expiry(int(NOW) - 60, NOW).endswith("(expired)")
