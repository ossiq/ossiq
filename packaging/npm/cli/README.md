# @ossiq/cli

Make better dependency decisions — before and after installation.

[OSS IQ](https://github.com/ossiq/ossiq) analyses your `package.json`, `pyproject.toml`
or `requirements.txt` and answers: should I add it, update it, or refactor it out?

## Usage

No install required:

```bash
npx @ossiq/cli status
```

Or install it:

```bash
npm install -g @ossiq/cli
ossiq status
```

This package ships a self-contained binary — **no Python installation is required**.
The correct binary for your platform is selected automatically through npm's
optional dependencies.

## Log in to GitHub

Log in once to raise GitHub's API limit from 60 requests an hour to 5,000:

```bash
ossiq auth login
```

Open the URL it prints and enter the code. The token goes to your operating system's
secret store (macOS Keychain, Windows Credential Manager or Secret Service on Linux),
never to a file. In CI and containers, set `OSSIQ_GITHUB_TOKEN` instead.

## Coding agents

Give Claude Code, OpenAI Codex or GitHub Copilot the same check before they add or update a
dependency:

```bash
npx @ossiq/cli install skills
```

The installed skill and MCP server run OSS IQ through `npx --yes @ossiq/cli`, so they need
Node.js but no Python.

## Supported platforms

| OS | Architecture |
| --- | --- |
| macOS | arm64, x64 |
| Linux (glibc) | arm64, x64 |
| Windows | x64 |

On Windows on Arm and on musl-based Linux such as Alpine, install from PyPI:

```bash
uv tool install ossiq      # or: pipx install ossiq
```

## Documentation

<https://ossiq.dev>

## License

AGPL-3.0-only
