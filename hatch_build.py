import re
import shutil
import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

REPORT_DATA_PLACEHOLDER = "__OSSIQ_REPORT_DATA__"
# The SPA template is a committed, reviewed source artifact that packaging only
# ever reads. Regenerating it is a developer action (`just frontend-build`), so a
# wheel built from the repo and one built from the sdist carry identical bytes.
SPA_TEMPLATE_RELATIVE = Path("src") / "ossiq" / "ui" / "html_templates" / "spa_app.html"

SCRIPT_TAG_PATTERN = re.compile(
    r'(<script\s+type="json/oss-iq-report">)(.*?)(</script>)',
    re.DOTALL,
)


def replace_report_data_with_placeholder(
    html: str,
    placeholder: str = REPORT_DATA_PLACEHOLDER,
) -> str:
    """Replace the JSON content of the oss-iq-report script tag with a placeholder.

    Args:
        html: The full HTML string from the built SPA.
        placeholder: The sentinel string to inject.

    Returns:
        The HTML with the script tag content replaced.

    Raises:
        ValueError: If the script tag is not found in the HTML.
    """
    result, count = SCRIPT_TAG_PATTERN.subn(rf"\g<1>{placeholder}\g<3>", html)
    if count == 0:
        raise ValueError(
            'No <script type="json/oss-iq-report"> tag found in the built HTML. '
            "Ensure frontend/index.html contains the data script tag."
        )
    return result


def render_spa_template(project_root: Path) -> str:
    """Build the frontend and return the SPA template as text.

    Runs `npm ci` rather than `npm install`, so the build cannot resolve outside
    frontend/package-lock.json. Writes nothing: the caller decides where the
    result goes, which keeps this usable as a comparison as well as a write.

    Args:
        project_root: The root directory of the ossiq project.

    Returns:
        The built HTML with the report data replaced by the placeholder.

    Raises:
        RuntimeError: If npm is not available.
        FileNotFoundError: If the frontend build does not produce output.
    """
    frontend_dir = project_root / "frontend"

    npm = shutil.which("npm")
    if not npm:
        raise RuntimeError("npm is required to build frontend assets.")

    subprocess.check_call([npm, "ci"], cwd=str(frontend_dir))
    subprocess.check_call([npm, "run", "build"], cwd=str(frontend_dir))

    built_html = frontend_dir / "dist" / "index.html"
    if not built_html.exists():
        raise FileNotFoundError(f"Frontend build did not produce {built_html}")

    return replace_report_data_with_placeholder(built_html.read_text(encoding="utf-8"))


def build_frontend(project_root: Path) -> Path:
    """Regenerate the committed SPA template from the frontend sources.

    A developer action, not a packaging step: this mutates the source tree, so the
    regenerated template must be committed alongside the frontend change.

    Args:
        project_root: The root directory of the ossiq project.

    Returns:
        Path to the generated spa_app.html template.
    """
    target_html = project_root / SPA_TEMPLATE_RELATIVE
    template_html = render_spa_template(project_root)

    target_html.parent.mkdir(parents=True, exist_ok=True)
    target_html.write_text(template_html, encoding="utf-8")

    print(f"SPA template written to {target_html} ({target_html.stat().st_size:,} bytes)")
    return target_html


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        """Verify the committed SPA template is present before packaging.

        Deliberately never invokes npm: packaging does no network I/O and does not
        write to the source tree. Regenerating the template is `just frontend-build`.
        OSSIQ_SKIP_FRONTEND_BUILD is accepted and ignored, so the workflows and
        Dockerfiles that still set it keep working.

        Raises:
            RuntimeError: If the committed template is missing or empty.
        """
        prebuilt = Path(self.root) / SPA_TEMPLATE_RELATIVE
        if not prebuilt.is_file() or not prebuilt.stat().st_size:
            raise RuntimeError(
                f"missing or empty SPA template at {prebuilt}; run `just frontend-build` and commit the result."
            )
