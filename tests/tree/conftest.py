"""Fixtures shared by the builder and walker tests."""

import pytest

from tests.tree.helpers import lock_dep, lock_edge, lock_pkg, make_lockfile


@pytest.fixture
def extras_lockfile():
    """The project enables uvicorn[standard]; uvicorn's lock entry lists what that extra installs."""
    return make_lockfile(
        lock_pkg("my-app", "1.0.0", deps=[lock_edge("uvicorn", "0.54.0", "standard"), lock_dep("gunicorn", "26.2.0")]),
        lock_pkg(
            "uvicorn",
            "0.54.0",
            deps=[lock_dep("click", "8.5.0")],
            optional_deps={"standard": [lock_dep("httptools", "0.8.0")], "unused": [lock_dep("pytest", "9.0.3")]},
        ),
        lock_pkg("gunicorn", "26.2.0"),
        lock_pkg("click", "8.5.0"),
        lock_pkg("httptools", "0.8.0"),
        lock_pkg("pytest", "9.0.3"),
    )
