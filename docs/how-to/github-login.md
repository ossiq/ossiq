---
title: Log in to GitHub
description: Log in to GitHub with a one-time code so OSS IQ can make 5,000 GitHub API requests an hour instead of 60. The token stays in your operating system's secret store.
---

# Log in to GitHub

Run `ossiq auth login` once, and scans can make 5,000 GitHub API requests an hour instead of 60.
OSS IQ reads repository activity from GitHub, and a full scan needs hundreds of requests.

The login keeps its token in your operating system's secret store:

| System | Secret store |
|---|---|
| macOS | Keychain |
| Windows | Credential Manager |
| Linux desktop | Secret Service (GNOME Keyring) or KWallet |

The token never goes to a config file, an MCP configuration, the HTTP cache or a log. The login
requests no OAuth scopes, so the token can read public data only. It expires after 8 hours, and
OSS IQ refreshes it for you.

## Log in from a terminal

1. Start the login:

   ```bash
   ossiq auth login
   ```

2. Open the URL it prints, and enter the code:

   ```text
   GitHub login needed to raise the API limit from 60 to 5,000 requests/hour.
     1. Open:  https://github.com/login/device
     2. Enter the code:  ABCD-1234

     The code expires in 15 minutes.
   Waiting for approval... (Ctrl-C to stop; `ossiq auth login --resume` picks it up again)
   ```

3. On GitHub, approve **OSS IQ**. The command then finishes by itself:

   ```text
   ✓ Logged in as @octocat. The token is stored in the system keyring (macOS Keychain).
   ```

You can also skip step 1. A scan that finds no token shows the same code before it starts.

## Log in from a script or an agent's shell

Without a terminal, `ossiq auth login` prints the code and exits with status 75 instead of
waiting. Status 75 means "waiting for approval", not failure.

1. Print the code without waiting:

   ```bash
   ossiq auth login --no-wait
   ```

2. Approve the code on GitHub.
3. Finish the login:

   ```bash
   ossiq auth login --resume
   ```

   Status 0 means you are logged in. Status 75 means GitHub has not seen the approval yet; run
   `--resume` again.

The next scan also finishes a pending login, so step 3 is optional. To start over with a new
code, run `ossiq auth login` again.

## Log in through an MCP client

A coding agent that calls an OSS IQ MCP tool gets the code in the tool result:

```text
GitHub login needed to raise OSS IQ's API limit from 60 to 5,000 requests/hour.
  1. Open:  https://github.com/login/device
  2. Enter the code:  ABCD-1234
The code expires in 15 minutes.
```

The agent shows you the URL and the code. After you approve, the agent calls the tool again, and
the scan runs with your login. The result tells the agent not to ask you for a token.

The result also carries `_meta.auth_status: PENDING_USER_ACTION`, with `verification_uri` and
`user_code`, for clients that render the login themselves. The MCP server asks once per session.
If you cancel or let the code expire, scans in that session run without a token.

## Check which token is in use

```bash
ossiq auth status
```

```text
GitHub token
  Source:   GitHub login (system keyring)
  Login:    @octocat
  Scope:    none (public data only)
  Expires:  2026-10-05 18:40 UTC
  Storage:  macOS Keychain
```

`Source` names the token that scans use. A token from the environment outranks the login; see
[Reference → token precedence](../reference.md#token-precedence).

## Use a token in CI and containers

CI runners and containers have no secret store to hold a login. Set `OSSIQ_GITHUB_TOKEN`
instead.

In GitHub Actions, pass the workflow's built-in token. It allows 1,000 requests an hour per
repository:

```yaml
- name: Run OSS IQ
  env:
    OSSIQ_GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: ossiq export --output=ossiq-report.json .
```

In Docker, pass the variable through:

```bash
export OSSIQ_GITHUB_TOKEN=$(gh auth token)
docker run --rm -e OSSIQ_GITHUB_TOKEN \
  -v "$(pwd)":/project:ro \
  ossiq/ossiq-cli status /project
```

OSS IQ reads `OSSIQ_GITHUB_TOKEN` and never writes it anywhere. A scan never starts a login when
the `CI` variable is set, so a pipeline can't stall on a prompt.

## Turn off the login prompt

To run scans without a token and without the prompt, set `OSSIQ_GITHUB_AUTH=off`:

```bash
export OSSIQ_GITHUB_AUTH=off
```

To make it permanent, add `OSSIQ_GITHUB_AUTH=off` to `~/.config/ossiq/config`. Scans then run at
60 requests an hour, ignore any stored login, and warn when the quota looks too thin.
`ossiq auth login` still works when you run it yourself.

## Log out and revoke access

1. Remove the login from this machine:

   ```bash
   ossiq auth logout
   ```

2. To revoke the authorization as well, open
   [GitHub → Settings → Applications](https://github.com/settings/applications) and remove
   **OSS IQ**. `ossiq auth logout` can't do this for you: GitHub's revocation API needs the app's
   client secret, which a command-line tool can't keep secret.

## Troubleshoot the login

### macOS asks for Keychain access after an upgrade

Click **Always Allow**. macOS ties a Keychain item to the program that created it. Each new
`ossiq` binary, and each new Python interpreter for a PyPI install, is a new program to macOS.
So the first run after an upgrade asks once.

### "Waiting for the system keyring..."

A secret-store dialog is waiting for an answer, possibly behind another window. Approve it.
OSS IQ gives up after 3 minutes; a scan then runs without a token.

### `Storage: none available` or "Credential Store Unavailable"

This machine has no secret store that OSS IQ can use. This is normal in containers, on CI
runners and in SSH sessions without a desktop. Set `OSSIQ_GITHUB_TOKEN` instead; see
[Use a token in CI and containers](#use-a-token-in-ci-and-containers).

### "GitHub Login Expired"

The code expired before you approved it. Codes last 15 minutes. Run `ossiq auth login` for a new
code.

### "GitHub Login Denied" or "The GitHub login was cancelled"

Someone clicked **Cancel** on the GitHub page. Run `ossiq auth login` to try again.

### "GitHub Login Unavailable"

GitHub didn't issue a code. Check your connection, then run `ossiq auth login` again. If the
message says `device_flow_disabled`, the problem is on the OSS IQ side:
[open an issue](https://github.com/ossiq/ossiq/issues).
