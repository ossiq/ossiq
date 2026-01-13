# Serve documentation locally
docs-serve:
    mkdocs serve --watch-theme

# Build documentation
docs-build:
    mkdocs build

list:
    @just --list

# Run all the formatting, linting, and testing commands
qa:
    uv run --extra dev ruff format .
    uv run --extra dev ruff check . --fix
    uv run --extra dev ruff check --select I --fix .
    uv run --extra dev ty check .
    uv run --extra dev pytest .

qa-integration:
    mkdir reports || echo 'Reports is there already'
    uv run hatch run ossiq-cli scan testdata/npm/project1
    uv run hatch run ossiq-cli scan testdata/npm/project2
    uv run hatch run ossiq-cli scan testdata/pypi/uv
    uv run hatch run ossiq-cli scan testdata/pypi/pylock
    uv run hatch run ossiq-cli scan testdata/pypi/pip-classic
    uv run hatch run ossiq-cli scan testdata/mixed
    uv run hatch run ossiq-cli scan testdata/mixed --registry-type=npm
    uv run hatch run ossiq-cli scan testdata/mixed --registry-type=pypi
    uv run hatch run ossiq-cli scan --presentation=html --output=./reports/scan_npm.html --registry-type=npm testdata/mixed
    uv run hatch run ossiq-cli scan --presentation=html --output=./reports/scan_pypi.html --registry-type=pypi testdata/mixed
    uv run hatch run ossiq-cli export --output-format=json --output=./reports/scan_export_pypi.json --registry-type=pypi testdata/mixed
    uv run hatch run ossiq-cli export --output-format=csv --output=./reports/scan_export_pypi.json --registry-type=pypi testdata/pypi/uv

lint:
    uv run ruff check .
    uv run ruff check --exit-zero --statistics .

# Run all the tests for all the supported Python versions
testall:
    uv run --python=3.10 --extra dev pytest
    uv run --python=3.11 --extra dev pytest
    uv run --python=3.12 --extra dev pytest
    uv run --python=3.13 --extra dev pytest

# Run all the tests, but allow for arguments to be passed
test *ARGS:
    @echo "Running with arg: {{ARGS}}"
    uv run --extra dev pytest {{ARGS}}

# Run all the tests, but on failure, drop into the debugger
pdb *ARGS:
    @echo "Running with arg: {{ARGS}}"
    uv run --python=3.13  --extra dev pytest --pdb --maxfail=10 --pdbcls=IPython.terminal.debugger:TerminalPdb {{ARGS}}

# Run coverage, and build to HTML
coverage:
    uv run --python=3.13 --extra dev coverage run -m pytest .
    uv run --python=3.13 --extra dev coverage report -m
    uv run --python=3.13 --extra dev coverage html

# Build the project, useful for checking that packaging is correct
build:
    rm -rf build
    rm -rf dist
    uv build

VERSION := `grep -m1 '^version' pyproject.toml | sed -E 's/version = "(.*)"/\1/'`

# Print the current version of the project
version:
    @echo "Current version is {{VERSION}}"

# Check what version PSR would bump to (dry-run)
version-next:
    uv run --extra dev semantic-release version --print

# View unpublished changes since last release
version-changelog:
    uv run --extra dev semantic-release changelog --unreleased

# Tag the current version in git and put to github
tag:
    echo "Tagging version v{{VERSION}}"
    git tag -a v{{VERSION}} -m "Creating version v{{VERSION}}"
    git push origin v{{VERSION}}

# remove all build, test, coverage and Python artifacts
clean: 
	uv run just clean-build
	uv run just clean-pyc
	uv run just clean-test

# remove build artifacts
clean-build:
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +

# remove Python file artifacts
clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

# remove test and coverage artifacts
clean-test:
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache