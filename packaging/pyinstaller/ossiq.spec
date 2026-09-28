# PyInstaller spec for the standalone `ossiq` binary.
#
# Built in onedir mode deliberately: agents spawn `ossiq mcp` repeatedly, and a
# onefile build pays a self-extraction cost on every launch.
#
# Build with:  pyinstaller packaging/pyinstaller/ossiq.spec --noconfirm
#
# ruff: noqa: F821  (Analysis/EXE/COLLECT are injected by PyInstaller)

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

PROJECT_ROOT = Path(SPECPATH).parent.parent
ENTRYPOINT = PROJECT_ROOT / "packaging" / "pyinstaller" / "entrypoint.py"

# The package reads these through importlib.resources, so PyInstaller's import
# analysis cannot see them. Covers ossiq/data/SKILL.md, the HTML templates
# (including the ~640 KB spa_app.html) and the JSON export schemas.
datas = collect_data_files("ossiq")

# Native extension modules whose submodules are imported dynamically.
hiddenimports = [
    # python-sat ships three compiled top-level modules alongside its package.
    "pysolvers",
    "pycard",
    "pyformula",
    *collect_submodules("pysat"),
    # common-expression-language (Rust/PyO3).
    "cel",
]

excludes = [
    "tkinter",
    "test",
    "unittest",
    "pydoc_data",
    # Docs stack is a dev-only extra but can be present in the build venv.
    "sphinx",
    "IPython",
    "matplotlib",
]

a = Analysis(
    [str(ENTRYPOINT)],
    pathex=[str(PROJECT_ROOT / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ossiq",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="ossiq",
)
