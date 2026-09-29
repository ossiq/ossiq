"""Tests for packaging/npm/build_npm_packages.py.

The script is loaded by path: `packaging/` is not an importable package, and the name
would collide with the `packaging` distribution anyway.
"""

import importlib.util
import io
import sys
import tarfile
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "packaging" / "npm" / "build_npm_packages.py"

# The script only runs on the Linux packing job; creating symlinks on Windows needs
# privileges the test runners are not guaranteed to have.
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX symlinks")


def load_script() -> ModuleType:
    """Import build_npm_packages.py from its file path.

    Returns:
        The loaded module.
    """
    spec = importlib.util.spec_from_file_location("build_npm_packages", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_npm_packages = load_script()


def make_macos_like_tree(root: Path) -> None:
    """Lay out the four links PyInstaller's macOS onedir bundle ships with.

    Args:
        root: Directory that plays the role of the extracted `bin/`.
    """
    internal = root / "ossiq" / "_internal"
    version_dir = internal / "Python.framework" / "Versions" / "3.13"
    (version_dir / "Resources").mkdir(parents=True)
    (version_dir / "Python").write_bytes(b"libpython")
    (version_dir / "Resources" / "Info.plist").write_text("plist")
    (root / "ossiq" / "ossiq").write_text("#!/bin/sh\n")

    (internal / "Python.framework" / "Versions" / "Current").symlink_to("3.13")
    (internal / "Python.framework" / "Python").symlink_to("Versions/Current/Python")
    (internal / "Python.framework" / "Resources").symlink_to("Versions/Current/Resources")
    (internal / "Python").symlink_to("Python.framework/Versions/3.13/Python")


def symlinks_under(root: Path) -> list[Path]:
    """List every symlink under root.

    Args:
        root: Directory to scan.

    Returns:
        The symlinks found, which `npm pack` would drop.
    """
    return [path for path in root.rglob("*") if path.is_symlink()]


def test_materialize_symlinks_replaces_file_and_directory_links(tmp_path: Path) -> None:
    """npm pack dropped `_internal/Python`, so 0.1.12's macOS binaries could not start."""
    make_macos_like_tree(tmp_path)

    build_npm_packages.materialize_symlinks(tmp_path)

    internal = tmp_path / "ossiq" / "_internal"
    assert symlinks_under(tmp_path) == []
    assert (internal / "Python").read_bytes() == b"libpython"
    assert (internal / "Python.framework" / "Python").read_bytes() == b"libpython"
    assert (internal / "Python.framework" / "Resources" / "Info.plist").read_text() == "plist"
    assert (internal / "Python.framework" / "Versions" / "Current" / "Python").read_bytes() == b"libpython"


def test_materialize_symlinks_refuses_a_link_outside_the_tree(tmp_path: Path) -> None:
    """Dereferencing would copy host files into a published package."""
    outside = tmp_path / "secret.txt"
    outside.write_text("do not publish")
    root = tmp_path / "bin"
    root.mkdir()
    (root / "leak").symlink_to(outside)

    with pytest.raises(SystemExit, match="points outside"):
        build_npm_packages.materialize_symlinks(root)

    assert (root / "leak").is_symlink(), "nothing may be rewritten once a link is refused"


def test_materialize_symlinks_refuses_a_dangling_link(tmp_path: Path) -> None:
    """A dangling link has nothing to copy, and silently dropping it is the original bug."""
    (tmp_path / "missing").symlink_to("nowhere")

    with pytest.raises(SystemExit, match="Cannot resolve"):
        build_npm_packages.materialize_symlinks(tmp_path)


def test_platform_package_carries_no_symlinks(tmp_path: Path) -> None:
    """End to end from a release-shaped tarball to the directory `npm pack` reads."""
    staging = tmp_path / "staging"
    make_macos_like_tree(staging)
    tarball = tmp_path / "ossiq-darwin-arm64.tar.gz"
    with tarfile.open(tarball, "w:gz") as archive:
        archive.add(staging / "ossiq", arcname="ossiq")

    output = tmp_path / "out"
    name = build_npm_packages.build_platform_package("darwin-arm64", "9.9.9", tarball, output)

    package_bin = output / "cli-darwin-arm64" / "bin"
    assert name == "@ossiq/cli-darwin-arm64"
    assert symlinks_under(package_bin) == []
    assert (package_bin / "ossiq" / "_internal" / "Python").is_file()


def test_extract_binary_refuses_path_traversal(tmp_path: Path) -> None:
    """The existing guard still holds with materialization added after it."""
    tarball = tmp_path / "evil.tar.gz"
    with tarfile.open(tarball, "w:gz") as archive:
        member = tarfile.TarInfo("../escape.txt")
        payload = b"x"
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))

    with pytest.raises(SystemExit, match="outside"):
        build_npm_packages.extract_binary(tarball, tmp_path / "bin")
