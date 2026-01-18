## How to cut new release

This document outlines the process for cutting a new release of the `ossiq-cli` project.
It covers both the standard release procedure and steps for reverting a release if issues arise.

**Important Warning**: Do not reuse the same release version twice. While local operations might appear successful, you will be unable to push a tag with an identical version to the remote repository, even if the previous remote tag has been deleted. Each release must have a unique version number.

### Standard Release Procedure

Follow these steps to create and publish a new release:

1.  **Ensure `production` branch is up-to-date**:
    ```bash    
    git checkout production
    git merge -ff-only main
    ```

2.  **Run the release script (dry-run first)**:
    Use the `release.py` script to manage version bumping and tagging.
    It's highly recommended to perform a dry-run first to preview the changes without actually applying them.
    You can specify the version bump type (`--major`, `--minor`, `--patch`) or explicitly set the version with `--override-version`.
    
    *   **Make sure github token is exported to the environment:
        ```bash
        export OSSIQ_GITHUB_TOKEN=$(gh auth token)
        ```
        
    *   **Dry-run (recommended)**:
        ```bash
        uv run release.py --dry-run --override-version 0.1.3 # or --major/--minor/--patch
        ```
    *   **Execute the release**:
        ```bash
        uv run release.py --override-version 0.1.3 # or --major/--minor/--patch
        ```

3.  **Synchronize `main` with `production`**:
    After a successful release, ensure your `main` branch reflects the changes from `production`.
    ```bash
    git push origin production
    git checkout main
    git merge production
    git push origin main
    ```

### How to Revert a Release (If Something Goes Wrong)

If an issue is discovered immediately after a release, you can revert the changes using these steps.
**Note**: This should be done with caution, as it rewrites history.

1.  **Revert the version bump commit**:
    This command will undo the last commit, which typically contains the version bump.
    ```bash
    git reset --hard HEAD~1
    ```

2.  **Delete the local tag**:
    Remove the tag associated with the problematic release from your local repository.
    ```bash
    git tag -d vX.Y.Z # Replace vX.Y.Z with the actual version tag, e.g., v0.1.3
    ```

3.  **Delete the remote tag (if already pushed)**:
    If the tag was already pushed to the remote, you must delete it there as well.
    ```bash
    git push origin :refs/tags/vX.Y.Z # Replace vX.Y.Z with the actual version tag
    ```

---

## Docker Image

The Docker image is automatically built and pushed to Docker Hub when a GitHub release is published.
The workflow is defined in `.github/workflows/docker.yml`.

### Building and Testing Locally

Before releasing, test the Docker build locally:

```bash
# Build the image
docker build -t ossiq/ossiq-cli:test .

# Test help commands
docker run --rm ossiq/ossiq-cli:test --help
docker run --rm ossiq/ossiq-cli:test scan --help

# Test token validation (should fail gracefully with helpful message)
docker run --rm ossiq/ossiq-cli:test scan /project

# Test actual scan with a project
docker run -t --rm \
  -e OSSIQ_GITHUB_TOKEN=$(gh auth token) \
  -v ./testdata/npm/project1:/project:ro \
  ossiq/ossiq-cli:test scan /project

# Test HTML report generation
docker run --rm \
  -e OSSIQ_GITHUB_TOKEN=$(gh auth token) \
  -v ./testdata/npm/project1:/project:ro \
  -v $(pwd)/reports:/output \
  ossiq/ossiq-cli:test scan -p html -o /output/report.html /project
```

### Multi-Architecture Build Test

The CI builds for both `linux/amd64` and `linux/arm64`. To test multi-arch locally:

```bash
# Create a builder (one-time setup)
docker buildx create --name multiarch --use

# Build for multiple platforms (without pushing)
docker buildx build --platform linux/amd64,linux/arm64 -t ossiq/ossiq-cli:test .
```

### Updating Python Version

The Dockerfile uses a specific Python version. Update it when:
- A new Python version becomes stable and is tested with OSS IQ
- The minimum Python version in `pyproject.toml` changes
- Security updates require a newer version

**Files to update:**
1. `Dockerfile` - Update both stages:
   ```dockerfile
   FROM python:3.14-slim-bookworm AS builder
   ...
   ENV UV_PYTHON=python3.14
   ...
   FROM python:3.14-slim-bookworm AS runtime
   ```

2. `pyproject.toml` - Ensure classifiers include the version:
   ```toml
   "Programming Language :: Python :: 3.14",
   ```

3. `.github/workflows/test.yml` - Add the version to the test matrix

### Updating uv Version

The Dockerfile pins a specific uv version for reproducibility. Update it when:
- A new uv version has features or fixes you need
- Security updates are released
- Breaking changes require testing

**File to update:** `Dockerfile`
```dockerfile
COPY --from=ghcr.io/astral-sh/uv:0.9.26 /uv /uvx /bin/
```

Check for new versions at: https://github.com/astral-sh/uv/releases

### Specifying OSS IQ Version in Docker

The Docker image version is determined by the Git tag used in the GitHub release.
The `docker/metadata-action` automatically extracts version tags:

| Git Tag | Docker Tags Created |
|---------|---------------------|
| `v0.1.3` | `0.1.3`, `0.1`, `latest` |
| `v1.0.0` | `1.0.0`, `1.0`, `1`, `latest` |
| `v2.0.0-beta.1` | `2.0.0-beta.1` |

The version in the Docker image comes from the installed Python package, which is set in `pyproject.toml`.

### Docker Hub Setup (One-Time)

1. Create Docker Hub repository at https://hub.docker.com
   - Organization/Username: `ossiq`
   - Repository: `ossiq-cli`
   - Short description: "Dependency risk analysis by linking version lag, CVEs, and maintainer activity"

2. Add GitHub repository secrets:
   - `DOCKER_USERNAME` - Docker Hub username
   - `DOCKER_PASSWORD` - Docker Hub access token (create at https://hub.docker.com/settings/security)

3. Update Docker Hub README:
   - Copy content from `DOCKER_README.md` to the Docker Hub repository description
