# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**OSS IQ** is a CLI tool that analyzes open-source dependency risk by cross-referencing version lag, CVEs, and maintainer activity to produce actionable intelligence about project dependencies.

- **Ecosystems supported**: NPM (JavaScript) and Python (uv, Poetry, pip)
- **License**: AGPL-3.0-only
- **Python requirement**: >= 3.11

## Development Commands

This project uses `uv` for dependency management and `just` for task automation.

### Setup
```bash
# Install dependencies
uv sync

# Required environment variable for GitHub API
export OSSIQ_GITHUB_TOKEN=$(gh auth token)
```

### Quality Assurance
```bash
# Run full QA suite (format, lint, type check, tests)
uv run just qa

# Individual QA steps
uv run ruff format .                      # Format code
uv run ruff check . --fix                 # Lint with auto-fix
uv run ty check .                         # Type checking
uv run pytest .                           # Run tests
```

### Testing
```bash
# Run all tests
uv run just test

# Run specific test
uv run just test tests/adapters/test_api_npm.py::TestClass::test_method

# Run tests with debugger on failure
uv run just pdb tests/path/to/test.py

# Coverage report (generates HTML in htmlcov/)
uv run just coverage
```

### Running the CLI
```bash
# Analyze a project
uv run hatch run ossiq-cli scan /path/to/project

# Or directly via module
uv run python -m ossiq.cli scan /path/to/project
```

## Architecture

### High-Level Pattern: Hexagonal Architecture

The codebase follows **Hexagonal/Ports & Adapters** architecture with clear separation between domain logic and external integrations.

```
src/ossiq/
├── domain/          # Core business logic (pure Python, no I/O)
├── adapters/        # External integrations (package managers, registries, APIs)
├── service/         # Application services (orchestrate domain + adapters)
├── unit_of_work/    # UoW pattern for transaction boundaries
├── commands/        # CLI command implementations
└── ui/              # Output formatting (console, HTML, JSON, SBOM)
```

### Key Architectural Patterns

#### 1. **Adapter Pattern for Package Managers**
Location: `src/ossiq/adapters/package_managers/`

All package manager adapters inherit from `AbstractPackageManagerApi`:
- **Static method**: `has_package_manager(project_path)` - detects if manager is present
- **Instance method**: `project_info()` - returns `Project` with dependencies

**Adding a new package manager**:
1. Define ecosystem in `src/ossiq/domain/ecosystem.py` (Manifest, Lockfile, PackageManagerType)
2. Create adapter in `src/ossiq/adapters/package_managers/api_<name>.py`
3. Register in `PACKAGE_MANAGERS` tuple in `src/ossiq/adapters/package_managers/api.py`

**Reference implementations**:
- `api_uv.py` - TOML-based with CEL version detection (use as template for Python package managers)
- `api_npm.py` - JSON-based with optional lockfile support

#### 2. **Unit of Work Pattern**
Location: `src/ossiq/unit_of_work/uow_project.py`

The UoW pattern manages:
- Auto-detection of package manager (probes via `has_package_manager()`)
- Lazy initialization of adapters (GitHub API, package registries, CVE database)
- Resource lifecycle management (context manager)

Usage:
```python
with ProjectUnitOfWork(settings, project_path) as uow:
    project = uow.packages_manager.project_info()
    versions = uow.packages_registry.package_versions(package_name)
```

#### 3. **Lockfile Version Handling with CEL**
Location: `src/ossiq/adapters/package_managers/utils.py`

Uses **Common Expression Language (CEL)** for dynamic parser selection:

```python
supported_versions = {"version == 1 && revision >= 3": "parse_lockfile_v1_r3"}
# CEL evaluates conditions at runtime to select appropriate parser method
```

This allows graceful handling of multiple lockfile format versions.

### Domain Model Structure

#### Core Entities (`src/ossiq/domain/`)
- **`Project`**: Container for project metadata and dependencies
- **`Dependency`**: Represents a package with:
  - `version_installed`: Resolved version from lockfile
  - `version_defined`: Version specifier from manifest (optional)
  - `categories`: Dependency groups (dev, optional, peer, etc.)
- **`PackageVersion`**: Package registry version metadata
- **`RepositoryVersion`**: Source code repository release information

#### Ecosystem Configuration (`domain/ecosystem.py`)
Defines metadata for each package manager:
```python
NPM = PackageManagerType(
    name="npm",
    ecosystem=ProjectPackagesRegistry.NPM,
    primary_manifest=NPM_PACKAGE_JSON,
    lockfile=NPM_LOCKFILE,
)
```

### Adapter Implementation Notes

#### Package Manager Adapters
- **Detection order** matters: Listed in `PACKAGE_MANAGERS` tuple, first match wins
- **Lockfile parsing**: Use CEL for version-specific parsers (see `api_uv.py`)
- **Error handling**: Wrap file I/O and parsing errors in `PackageManagerLockfileParsingError`
- **Dependency separation**: Return tuple of `(dependencies, optional_dependencies)`
- **Project package exclusion**: Always filter out the project itself from dependencies

#### Package Registry Adapters (`src/ossiq/adapters/`)
- `api_pypi.py`: PyPI integration for Python packages
- `api_npm.py`: NPM registry integration for JavaScript packages
- All implement version comparison and difference calculation

#### Source Code Provider Adapters
- `api_github.py`: GitHub API integration for repository analysis
- Requires `OSSIQ_GITHUB_TOKEN` for rate limit handling

### Testing Patterns

Tests follow consistent patterns across adapters and are written following pytest best practices.

#### Test File Structure

Tests are organized by functionality (see `tests/adapters/package_managers/test_api_uv.py`):
```python
# Fixtures for test projects
@pytest.fixture
def package_manager_project_basic(temp_project_dir):
    # Create realistic project structure with manifest + lockfile

# Test classes organized by method
class TestStaticMethods:
    # Test project_files(), has_package_manager()

class TestParsing:
    # Test lockfile parsing logic

class TestProjectInfo:
    # Integration tests for project_info()
```

#### Pytest Best Practices

All tests in this project must follow these practices:

**1. AAA Pattern (Arrange-Act-Assert)**
Structure every test into three distinct blocks for clarity:
```python
def test_package_version_parsing(self, sample_lockfile):
    """Test lockfile parser extracts correct package version."""
    # Arrange
    parser = LockfileParser()

    # Act
    version = parser.parse_version(sample_lockfile, "react")

    # Assert
    assert version == "18.2.0"
```

**2. Use Parametrization**
Use `@pytest.mark.parametrize` to run the same test logic against multiple data sets:
```python
@pytest.mark.parametrize(
    "version_string,expected",
    [
        ("^1.2.3", "1.2.3"),
        ("~2.0.0", "2.0.0"),
        (">=3.1.0", "3.1.0"),
    ],
)
def test_version_normalization(self, version_string, expected):
    """Test version normalization handles various prefixes."""
    # Act
    result = normalize_version(version_string)

    # Assert
    assert result == expected
```

**3. Implement Fixtures**
Use pytest fixtures for reusable setup and teardown logic:
```python
@pytest.fixture
def temp_lockfile(tmp_path):
    """Create temporary lockfile for testing."""
    lockfile = tmp_path / "uv.lock"
    lockfile.write_text("version = 1\n")
    yield lockfile
    # Cleanup happens automatically via tmp_path
```

**4. Single Responsibility**
Each test validates exactly one behavior. Avoid combining multiple unrelated assertions:
```python
# Good - single responsibility
def test_parser_extracts_package_name(self):
    """Test parser extracts package name correctly."""
    assert parser.get_name() == "react"

def test_parser_extracts_package_version(self):
    """Test parser extracts package version correctly."""
    assert parser.get_version() == "18.2.0"

# Bad - multiple responsibilities
def test_parser_extracts_data(self):
    """Test parser extracts data."""
    assert parser.get_name() == "react"
    assert parser.get_version() == "18.2.0"
    assert parser.get_description() == "React library"
```

**5. Mock External Boundaries**
Use `unittest.mock` or `pytest-mock` to isolate units from external dependencies:
```python
from unittest.mock import patch

def test_github_api_rate_limit_handling(self):
    """Test GitHub API handles rate limits correctly."""
    # Arrange
    with patch('requests.get') as mock_get:
        mock_get.return_value.status_code = 429
        api = GitHubApi(token="test")

        # Act & Assert
        with pytest.raises(RateLimitError):
            api.get_releases("owner/repo")
```

**6. Descriptive Test Names**
Test names should clearly describe what is being tested and expected outcome:
- Use `test_<action>_<expected_result>` pattern
- Be specific about the scenario
- Examples:
  - `test_parser_raises_error_on_invalid_lockfile_version`
  - `test_exported_json_conforms_to_schema`
  - `test_unicode_characters_handled_correctly`

**7. Test Documentation**
Include docstrings with AAA pattern explanation for complex tests:
```python
def test_complex_scenario(self):
    """Test complex scenario with multiple steps.

    AAA Pattern:
    - Arrange: Set up multiple dependencies
    - Act: Execute multi-step operation
    - Assert: Verify final state and side effects
    """
```

**Coverage requirement**: Target 80%+ for new code (use `uv run just coverage`)

### Type Checking

- Uses `ty` (pyright-based) for static type analysis
- Type hints required for all public APIs
- Note: Some adapters have intentional `# type: ignore[arg-type]` for TOML int vs str mismatches

### Code Style

- Line length: 120 characters
- Formatter: `ruff format` (Black-compatible)
- Linter: `ruff check` with pycodestyle, Pyflakes, isort, bugbear, pyupgrade
- Import sorting: Automated via `ruff check --select I --fix`

## Important Environment Variables

- `OSSIQ_GITHUB_TOKEN` - **Required** for GitHub API (hundreds of requests per analysis)
- `OSSIQ_PRESENTATION` - Output format (console/html/json/sbom)
- `OSSIQ_OUTPUT` - Output destination path
- `OSSIQ_VERBOSE` - Enable verbose logging

## Project-Specific Notes

### Dependency Categories
The system tracks dependency categories (similar to npm's devDependencies):
- **Python**: `dev`, `test`, `docs`, etc. (from optional-dependencies)
- **NPM**: `development`, `optional`, `peer`

Categories are stored in `Dependency.categories` as a list.

### Version Normalization
All version strings are normalized (strip `^`, `~`, `>=` modifiers) via `normalize_version()` in `domain/version.py`.

### Package Manager Detection Precedence
Adapters are probed in order defined in `PACKAGE_MANAGERS` tuple. If a project has multiple lockfiles (e.g., both `uv.lock` and `pylock.toml`), the first match wins.
