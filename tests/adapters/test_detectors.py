import os

import pytest

from ossiq.adapters.detectors import detect_package_manager, detect_source_code_provider
from ossiq.domain.common import RepositoryProvider, UnsupportedProjectType, UnsupportedRepositoryProvider
from ossiq.domain.ecosystem import NPM, PDM, PIP, PIPENV, POETRY, UV, YARN


@pytest.fixture
def mock_os_path_exists(monkeypatch):
    """Fixture to mock os.path.exists."""
    mock_files = set()

    def exists_side_effect(path):
        filename = os.path.basename(path)
        return filename in mock_files

    monkeypatch.setattr(os.path, "exists", exists_side_effect)

    class MockExistsHelper:
        def set_files(self, files):
            mock_files.clear()
            mock_files.update(files)

    return MockExistsHelper()


def test_detect_package_manager_uv(mock_os_path_exists):
    mock_os_path_exists.set_files(["pyproject.toml", "uv.lock"])
    manager = detect_package_manager("/test/project")
    assert manager == UV


def test_detect_package_manager_poetry(mock_os_path_exists):
    mock_os_path_exists.set_files(["pyproject.toml", "poetry.lock"])
    manager = detect_package_manager("/test/project")
    assert manager == POETRY


def test_detect_package_manager_pdm(mock_os_path_exists):
    mock_os_path_exists.set_files(["pyproject.toml", "pdm.lock"])
    manager = detect_package_manager("/test/project")
    assert manager == PDM


def test_detect_package_manager_pipenv(mock_os_path_exists):
    mock_os_path_exists.set_files(["Pipfile", "Pipfile.lock"])
    manager = detect_package_manager("/test/project")
    assert manager == PIPENV


def test_detect_package_manager_npm(mock_os_path_exists):
    mock_os_path_exists.set_files(["package.json", "package-lock.json"])
    manager = detect_package_manager("/test/project")
    assert manager == NPM


def test_detect_package_manager_yarn(mock_os_path_exists):
    mock_os_path_exists.set_files(["package.json", "yarn.lock"])
    manager = detect_package_manager("/test/project")
    assert manager == YARN


def test_detect_package_manager_pip_requirements(mock_os_path_exists):
    mock_os_path_exists.set_files(["requirements.txt"])
    manager = detect_package_manager("/test/project")
    assert manager == PIP


def test_detect_package_manager_ambiguous_pyproject_toml(mock_os_path_exists):
    mock_os_path_exists.set_files(["pyproject.toml"])
    with pytest.raises(UnsupportedProjectType) as excinfo:
        detect_package_manager("/test/project")
    assert "Detected 'pyproject.toml' but no lockfile." in str(excinfo.value)


def test_detect_package_manager_no_files_found(mock_os_path_exists):
    mock_os_path_exists.set_files([])
    with pytest.raises(UnsupportedProjectType) as excinfo:
        detect_package_manager("/test/project")
    assert "Could not determine project type in '/test/project'." in str(excinfo.value)


def test_detect_source_code_provider_github():
    provider = detect_source_code_provider("https://github.com/owner/repo")
    assert provider == RepositoryProvider.PROVIDER_GITHUB


def test_detect_source_code_provider_github_with_git_prefix():
    provider = detect_source_code_provider("git@github.com:owner/repo.git")
    assert provider == RepositoryProvider.PROVIDER_GITHUB


def test_detect_source_code_provider_unsupported():
    with pytest.raises(UnsupportedRepositoryProvider) as excinfo:
        detect_source_code_provider("https://gitlab.com/owner/repo")
    assert "Unknown repository provider for the URL: https://gitlab.com/owner/repo" in str(excinfo.value)
