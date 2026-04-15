# Serve documentation locally with live reload
docs-serve:
    uv run just docs-clean
    uv run --extra docs sphinx-autobuild docs docs/_build/html --open-browser --watch docs

# Build documentation
docs-build:
    uv run --extra docs sphinx-build -b html docs docs/_build/html

# Check documentation for broken links
docs-check:
    uv run --extra docs sphinx-build -b linkcheck docs docs/_build/linkcheck

docs-clean:
    [ -d "docs/_build" ] && rm -rf docs/_build;    

list:
    @just --list

# Run all the formatting, linting, and testing commands
qa:
    uv run --group dev ruff format .
    uv run --group dev ruff check . --fix
    uv run --group dev ruff check --select I --fix .
    uv run --group dev ty check .
    uv run --group dev pytest .

qa-integration:
    mkdir reports || echo 'Reports is there already'
    uv run hatch run ossiq-cli scan testdata/npm/project1
    uv run hatch run ossiq-cli scan testdata/npm/project1
    uv run hatch run ossiq-cli scan testdata/npm/project2
    uv run hatch run ossiq-cli package testdata/npm/project3 ms
    uv run hatch run ossiq-cli package testdata/npm/project3 chalk
    uv run hatch run ossiq-cli package testdata/npm/project3 lodash
    uv run hatch run ossiq-cli scan testdata/pypi/uv
    uv run hatch run ossiq-cli scan testdata/pypi/pylock
    uv run hatch run ossiq-cli scan testdata/pypi/pip-classic
    uv run hatch run ossiq-cli scan testdata/mixed
    uv run hatch run ossiq-cli scan testdata/mixed --registry-type=npm
    uv run hatch run ossiq-cli scan testdata/mixed --registry-type=pypi
    uv run hatch run ossiq-cli scan --presentation=html --output=./reports/scan_npm.html --registry-type=npm testdata/mixed
    uv run hatch run ossiq-cli scan --presentation=html --output=./reports/scan_pypi.html --registry-type=pypi testdata/mixed
    uv run hatch run ossiq-cli scan testdata/npm/project3
    uv run hatch run ossiq-cli export --output-format=json --output=./reports/scan_export_pypi0.json --registry-type=pypi testdata/mixed
    uv run hatch run ossiq-cli export --output-format=csv --output=./reports/scan_export_pypi1.json --registry-type=pypi testdata/pypi/uv
    uv run hatch run ossiq-cli export --output-format=csv --schema-version=1.0 --output=./reports/scan_export_pypi_10.json --registry-type=pypi testdata/pypi/uv
    uv run hatch run ossiq-cli export --output-format=csv --schema-version=1.1 --output=./reports/scan_export_pypi_11.json --registry-type=pypi testdata/pypi/uv
    uv run hatch run ossiq-cli export --output-format=csv --schema-version=1.2 --output=./reports/scan_export_pypi_12.json --registry-type=pypi testdata/pypi/uv
    uv run hatch run ossiq-cli export --output-format=json --schema-version=1.0 --output=./reports/scan_export_pypi_10.json --registry-type=pypi testdata/mixed
    uv run hatch run ossiq-cli export --output-format=json --schema-version=1.1 --output=./reports/scan_export_npm_11.json --registry-type=npm testdata/mixed
    uv run hatch run ossiq-cli export --output-format=json --schema-version=1.2 --output=./reports/scan_export_npm_12.json --registry-type=npm testdata/mixed
    uv run hatch run ossiq-cli package testdata/pypi/version-constraint scipy
    uv run hatch run ossiq-cli package testdata/pypi/version-constraint numpy
    uv run hatch run ossiq-cli export --output-format=json --output=./reports/scan_export_pypi_version_constriant.json testdata/pypi/version-constraint
    uv run hatch run ossiq-cli export --output-format=json --output=./reports/scan_export_pypi_version_uv.json testdata/pypi/uv
    uv run hatch run ossiq-cli export --output-format=json --output=./reports/scan_export_pypi_version_pylock.json testdata/pypi/pylock
    cat ./reports/scan_export_pypi_version_uv.json | jq | grep '"constraint_type": "ADDITIVE"'

lint:
    uv run ruff check .
    uv run ruff check --exit-zero --statistics .

# Run all the tests for all the supported Python versions
testall:
    uv run --python=3.10 --group dev pytest
    uv run --python=3.11 --group dev pytest
    uv run --python=3.12 --group dev pytest
    uv run --python=3.13 --group dev pytest

# Run all the tests, but allow for arguments to be passed
test *ARGS:
    @echo "Running with arg: {{ARGS}}"
    uv run --group dev pytest {{ARGS}}

# Run all the tests, but on failure, drop into the debugger
pdb *ARGS:
    @echo "Running with arg: {{ARGS}}"
    uv run --python=3.13  --group dev pytest --pdb --maxfail=10 --pdbcls=IPython.terminal.debugger:TerminalPdb {{ARGS}}

# Run coverage, and build to HTML
coverage:
    uv run --python=3.13 --group dev coverage run -m pytest .
    uv run --python=3.13 --group dev coverage report -m
    uv run --python=3.13 --group dev coverage html

# Build Vue.js SPA frontend and produce the SPA template for HTML reports
frontend-build:
    uv run python frontend_build.py

# Build the project, useful for checking that packaging is correct
build:
    rm -rf build
    rm -rf dist
    uv build

VERSION := `grep -m1 '^version' pyproject.toml | sed -E 's/version = "(.*)"/\1/'`

# Print the current version of the project
version:
    @echo "Current version is {{VERSION}}"

# Create a new release (dry-run by default)
release *ARGS:
    uv run python release.py {{ARGS}} --dry-run

# Preview what a patch release would look like
release-preview:
    uv run python release.py --patch --dry-run

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