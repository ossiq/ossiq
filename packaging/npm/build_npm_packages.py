#!/usr/bin/env python3
"""Generate the npm packages for the OSS IQ CLI from built standalone binaries.

Produces one platform package per target (each carrying a PyInstaller onedir
tree) plus the `@ossiq/cli` launcher that depends on them optionally. This is the
distribution model used by esbuild: npm resolves exactly one platform package for
the host, and the launcher execs the binary inside it.

Usage:
    python packaging/npm/build_npm_packages.py \
        --artifacts artifacts/ \
        --output build/npm

`--artifacts` holds the tarballs produced by .github/workflows/binaries.yml,
named `ossiq-<target>.tar.gz`.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tarfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

LAUNCHER_PACKAGE = "@ossiq/cli"

# npm's `os` and `cpu` fields, keyed by the target names used for the binaries.
TARGETS: dict[str, dict[str, str]] = {
    "darwin-arm64": {"os": "darwin", "cpu": "arm64"},
    "darwin-x64": {"os": "darwin", "cpu": "x64"},
    "linux-arm64": {"os": "linux", "cpu": "arm64"},
    "linux-x64": {"os": "linux", "cpu": "x64"},
    "win32-x64": {"os": "win32", "cpu": "x64"},
}

COMMON_FIELDS = {
    "license": "AGPL-3.0-only",
    "homepage": "https://ossiq.dev",
    "repository": {
        "type": "git",
        "url": "git+https://github.com/ossiq/ossiq.git",
    },
    "bugs": {"url": "https://github.com/ossiq/ossiq/issues"},
}

_VERSION_PATTERN = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)


def read_version(pyproject: Path) -> str:
    """Read the single source of truth for the version from pyproject.toml."""
    match = _VERSION_PATTERN.search(pyproject.read_text(encoding="utf-8"))
    if not match:
        raise SystemExit(f"Could not find a version in {pyproject}")
    return match.group(1)


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def extract_binary(tarball: Path, destination: Path) -> None:
    """Unpack a `ossiq-<target>.tar.gz` into destination, preserving mode bits."""
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as archive:
        # The tarballs are built by our own workflow from a fixed directory, but
        # refuse anything that would escape the destination anyway.
        for member in archive.getmembers():
            member_path = (destination / member.name).resolve()
            if not member_path.is_relative_to(destination.resolve()):
                raise SystemExit(f"Refusing to extract {member.name} outside {destination}")
        archive.extractall(destination, filter="tar")


def pack_filename(package_name: str, version: str) -> str:
    """Return the tarball name `npm pack` produces for a package.

    npm strips the leading `@` from a scoped name and replaces the `/` with a `-`, so
    `@ossiq/cli-darwin-arm64` packs to `ossiq-cli-darwin-arm64-<version>.tgz`.

    Args:
        package_name: The npm package name, scoped or not.
        version: The package version.

    Returns:
        The .tgz filename npm will write.
    """
    return f"{package_name.lstrip('@').replace('/', '-')}-{version}.tgz"


def build_platform_package(target: str, version: str, tarball: Path, output_root: Path) -> str:
    """Write one platform package; returns its npm package name."""
    package_name = f"{LAUNCHER_PACKAGE}-{target}"
    package_dir = output_root / f"cli-{target}"

    if package_dir.exists():
        shutil.rmtree(package_dir)

    extract_binary(tarball, package_dir / "bin")

    executable = package_dir / "bin" / "ossiq" / ("ossiq.exe" if target.startswith("win32") else "ossiq")
    if not executable.exists():
        raise SystemExit(f"{tarball} did not contain the expected executable at bin/ossiq/{executable.name}")
    executable.chmod(0o755)

    write_json(
        package_dir / "package.json",
        {
            "name": package_name,
            "version": version,
            "description": f"Standalone ossiq binary for {target}.",
            **COMMON_FIELDS,
            "os": [TARGETS[target]["os"]],
            "cpu": [TARGETS[target]["cpu"]],
            "files": ["bin"],
            "preferUnplugged": True,
        },
    )
    return package_name


def build_launcher_package(version: str, platform_packages: list[str], output_root: Path) -> Path:
    """Write the @ossiq/cli launcher that optionally depends on every platform package."""
    package_dir = output_root / "cli"

    if package_dir.exists():
        shutil.rmtree(package_dir)

    source = PROJECT_ROOT / "packaging" / "npm" / "cli"
    shutil.copytree(source, package_dir)

    (package_dir / "bin" / "ossiq.js").chmod(0o755)

    write_json(
        package_dir / "package.json",
        {
            "name": LAUNCHER_PACKAGE,
            "version": version,
            "description": "Make better dependency decisions - before and after installation.",
            **COMMON_FIELDS,
            "keywords": ["dependencies", "security", "cve", "supply-chain", "npm", "pypi"],
            "bin": {"ossiq": "bin/ossiq.js"},
            "files": ["bin", "README.md"],
            "engines": {"node": ">=18"},
            # Optional so that an unsupported platform still installs; the
            # launcher then prints the PyPI fallback instructions.
            "optionalDependencies": {name: version for name in sorted(platform_packages)},
        },
    )
    return package_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifacts",
        type=Path,
        required=True,
        help="Directory containing ossiq-<target>.tar.gz binaries",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "build" / "npm",
        help="Directory to write the generated npm packages into",
    )
    parser.add_argument(
        "--version",
        default=None,
        help="Override the version (defaults to the one in pyproject.toml)",
    )
    args = parser.parse_args(argv)

    version = args.version or read_version(PROJECT_ROOT / "pyproject.toml")
    args.output.mkdir(parents=True, exist_ok=True)

    platform_packages: list[str] = []
    platform_dirs: list[str] = []
    missing: list[str] = []

    for target in TARGETS:
        tarball = args.artifacts / f"ossiq-{target}.tar.gz"
        if not tarball.exists():
            missing.append(target)
            continue
        platform_packages.append(build_platform_package(target, version, tarball, args.output))
        platform_dirs.append(f"cli-{target}")
        print(f"built {LAUNCHER_PACKAGE}-{target}")

    if missing:
        # Publishing a launcher whose optionalDependencies do not all exist would
        # leave those platforms permanently broken, so this is fatal.
        raise SystemExit(f"Missing binaries for: {', '.join(missing)} (looked in {args.artifacts})")

    launcher = build_launcher_package(version, platform_packages, args.output)
    print(f"built {LAUNCHER_PACKAGE} at {launcher}")

    # CI drives `npm pack` and the ordered `npm publish` from this rather than from a
    # glob: `npm pack` names tarballs after package.json, so @ossiq/cli packs to
    # ossiq-cli-<version>.tgz and a `ossiq-cli-*.tgz` glob would also match the
    # launcher — publishing it before the platform packages its optionalDependencies
    # pin, which is the exact breakage the ordering exists to prevent. Tarball names
    # are recorded here rather than reconstructed by the caller.
    write_json(
        args.output / "manifest.json",
        {
            "version": version,
            "platform_packages": [
                {"directory": directory, "package": name, "tarball": pack_filename(name, version)}
                for directory, name in zip(platform_dirs, platform_packages, strict=True)
            ],
            "launcher": {
                "directory": "cli",
                "package": LAUNCHER_PACKAGE,
                "tarball": pack_filename(LAUNCHER_PACKAGE, version),
            },
        },
    )

    print(f"\nVersion: {version}")
    print("Publish platform packages BEFORE the launcher.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
