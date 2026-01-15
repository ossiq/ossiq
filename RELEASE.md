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
