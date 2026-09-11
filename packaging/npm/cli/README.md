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

## Supported platforms

| OS | Architecture |
| --- | --- |
| macOS | arm64, x64 |
| Linux (glibc) | arm64, x64 |
| Windows | x64 |

musl-based Linux (Alpine) and Windows on ARM are not covered by the prebuilt
binaries. On those platforms install from PyPI instead:

```bash
uv tool install ossiq      # or: pipx install ossiq
```

## Documentation

<https://ossiq.dev>

## License

AGPL-3.0-only
