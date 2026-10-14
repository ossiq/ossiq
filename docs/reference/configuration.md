---
title: Configuration
description: "Where OSS IQ reads its settings: global flags, OSSIQ_* environment variables and the config file, plus GitHub token precedence, storage and the hosts a scan calls."
---

# Configuration

OSS IQ reads settings from command-line flags, environment variables and a config file. Part of
the [reference](../reference.md).

| You have | Go to |
|---|---|
| A flag such as `--cooldown-period`, or an `OSSIQ_*` variable | [Settings](#settings) |
| A config file to write or find | [Config file](#config-file) |
| A question about which GitHub token a scan uses | [Token precedence](#token-precedence) |
| A scan that asks for a login, or should not | [When a scan logs in](#when-a-scan-logs-in) |
| A firewall or proxy to configure | [Data sources](#data-sources) |

For each setting, the first source that sets it wins:

1. Command-line flags
2. Environment variables
3. The config file
4. Built-in defaults

## Configuration directory

OSS IQ keeps its files in `~/.config/ossiq/`, or in `$XDG_CONFIG_HOME/ossiq/` when
`XDG_CONFIG_HOME` is set:

| File | Contents |
|---|---|
| `config` | Optional settings, one `OSSIQ_*=value` per line |
| `cache.sqlite3` | HTTP cache for registry and GitHub responses. Move it with `--cache-destination`; skip it for one run with `--no-cache` |

The GitHub login is not in this directory; it lives in the [system secret store](#storage).

## Config file

The config file uses dotenv format: `KEY=value` lines and `#` comments. Any `OSSIQ_*` variable
from the [Settings](#settings) table can go in it:

```bash
# ~/.config/ossiq/config
OSSIQ_COOLDOWN_PERIOD=14
OSSIQ_CACHE_TTL=48
```

To read a different file, pass it before the command: `ossiq --config ./ossiq.conf status`. That
file then replaces the default one.

OSS IQ also reads `~/.ossiq/config`, where the file lived before. When both files set a key, the
one in the configuration directory wins.

## Settings

Every setting has a global flag, an environment variable, or both. Global flags go before the
command, for example `ossiq --cutoff-date 2025-01-01 --cooldown-period 14 status`.

| Variable | Flag | Default | Effect |
|---|---|---|---|
| `OSSIQ_GITHUB_TOKEN` | `--github-token`, `-T` | — | GitHub token, for CI and containers. See [GitHub token](#github-token) |
| `GITHUB_TOKEN` | — | — | Used when `OSSIQ_GITHUB_TOKEN` is unset |
| `OSSIQ_GITHUB_AUTH` | — | `auto` | `off` stops scans from offering a GitHub login |
| `OSSIQ_GITHUB_CLIENT_ID` | — | OSS IQ's app | Client ID of the GitHub OAuth app used for login. Set it only to log in through your own OAuth app, with device flow enabled |
| `OSSIQ_CACHE_DESTINATION` | `--cache-destination` | `~/.config/ossiq/cache.sqlite3` | HTTP cache file |
| `OSSIQ_CACHE_TTL` | `--cache-ttl` | `24` | Hours to keep cached responses |
| `OSSIQ_STABILITY_CACHE_TTL` | `--stability-cache-ttl` | `168` | Hours to keep GitHub stability data (commits, activity, README) |
| `OSSIQ_CUTOFF_DATE` | `--cutoff-date`, `-C` | today | Hide versions published after this date (23:59:59 UTC), to reproduce a past state |
| `OSSIQ_COOLDOWN_PERIOD` | `--cooldown-period` | `7` | Days a new version must age before the solver recommends it. `0` turns the cooldown off |
| `OSSIQ_STABILITY` | `--stability` / `--no-stability` | on | Measure upstream repository stability |
| `OSSIQ_STABILITY_RESPONSIVENESS` | `--stability-responsiveness` / `--no-stability-responsiveness` | on with a token | The GraphQL engagement-flow channel |
| `OSSIQ_PROBE_RUNTIME` | `--probe-runtime` / `--no-probe-runtime` | on | Detect the installed Python, Node.js and npm versions |
| — | `--engine ENGINE=VERSION` | — | State the runtime the project runs on, for example `--engine node=20.11.0` (repeatable). Replaces the probe for that engine |
| — | `--config PATH` | `~/.config/ossiq/config` | Read this config file in place of the default one |
| — | `--no-cache` | off | Skip the HTTP cache for this run |
| — | `--traceback` | off | Print a full traceback on error, in place of the error message |
| `OSSIQ_VERBOSE` | `--verbose`, `-v` | off | Detailed progress output |
| `OSSIQ_DEBUG` | `--debug`, `-d` | off | Debug logging |

## GitHub token

A scan with a GitHub token can make 5,000 GitHub API requests an hour; without one, 60. To log
in, see [`auth`](commands.md#auth) and [Log in to GitHub](../how-to/github-login.md).

### Token precedence

Scans use the first token found, in this order:

1. The global `--github-token` (`-T`) flag. Avoid it: a token on the command line shows up in
   shell history and process listings.
2. The `OSSIQ_GITHUB_TOKEN` environment variable.
3. The `GITHUB_TOKEN` environment variable.
4. The stored GitHub login.
5. `OSSIQ_GITHUB_TOKEN` in the [config file](#config-file). The file is plaintext, so prefer the
   login.

A token from the flag or the environment never touches the secret store. `ossiq auth status` shows
which source won.

### When a scan logs in

A scan that finds no token starts the login itself and shows the code on stderr. With a terminal
it waits for approval; without one it exits with status 75. Only scanning commands log in:
`status`, `html`, `export`, `info`, `add`, `update-context`, `plan` and `apply`.

A scan skips the login, and runs at 60 requests an hour, when:

- `OSSIQ_GITHUB_AUTH` is `off`, in the environment or the config file;
- the `CI` environment variable is set to anything but `0` or `false`;
- the machine has no usable secret store.

In the first two cases the scan ignores the stored login as well. The MCP server offers the login
once per session; after a cancelled or expired code, its scans run without a token.

### Storage

The login lives in the operating system's secret store, through the
[keyring](https://pypi.org/project/keyring/) library:

| Item | Value |
|---|---|
| Secret store | macOS Keychain, Windows Credential Manager, or Secret Service or KWallet on Linux |
| Service name | `dev.ossiq.github` |
| Entries | `oauth_tokens` (the login) and `device_pending` (a login waiting for approval) |
| Timeout | A call with no answer after 3 minutes, such as an unanswered dialog, marks the store unavailable for the rest of the run |

The pending entry holds GitHub's device code, which stays secret until the login is approved.

### Tokens

- **Scope:** none. The token can read public data only.
- **Lifetime:** the access token lasts 8 hours, and OSS IQ refreshes it before it expires. The
  refresh token lasts about 6 months. GitHub replaces both on every refresh.
- **Validation:** OSS IQ checks a stored token with one `GET /user` request, at most once every
  10 minutes per process. A revoked token is discarded, and the next scan offers a new login.
- **Never written or printed:** no token, and no device code, appears in config files, `mcp.json`,
  the HTTP cache, logs, `--verbose` output, exports or HTML reports.

## Data sources

A scan reads public data from these hosts. Allow them through a firewall or proxy:

| Source | Host | Used for |
|---|---|---|
| [npm registry](https://www.npmjs.com/) | `registry.npmjs.org`, `api.npmjs.org` | Package metadata, version history and download counts for JavaScript packages |
| [PyPI](https://pypi.org/) | `pypi.org`, `pypistats.org` | Package metadata, version history and download counts for Python packages |
| [OSV](https://osv.dev/) | `api.osv.dev` | Known vulnerabilities (CVEs and security advisories) |
| [EPSS](https://www.first.org/epss/) | `api.first.org` | The probability that a CVE is exploited in the next 30 days |
| [GitHub](https://github.com/) | `api.github.com` | Repository activity, releases and maintenance signals |

When a source is unreachable, the scan still finishes and reports what is missing. See
[Partial data](../recommendations/partial-data.md).
