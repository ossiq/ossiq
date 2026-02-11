"""
Build the Vue.js SPA frontend and prepare it as an HTML report template.

This script:
1. Runs `npm install` and `npm run build` in the frontend/ directory
2. Reads the built single-file HTML from frontend/dist/index.html
3. Replaces the dummy JSON data in the <script type="json/oss-iq-report"> tag
   with a placeholder sentinel (__OSSIQ_REPORT_DATA__)
4. Writes the result to src/ossiq/ui/html_templates/spa_app.html

The placeholder is later replaced with real scan data at render time by the
HtmlScanRenderer.

Usage:
    uv run python frontend_build.py
"""

import re
import shutil
import subprocess
from pathlib import Path

REPORT_DATA_PLACEHOLDER = "__OSSIQ_REPORT_DATA__"

_SCRIPT_TAG_PATTERN = re.compile(
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
    result, count = _SCRIPT_TAG_PATTERN.subn(rf"\g<1>{placeholder}\g<3>", html)
    if count == 0:
        raise ValueError(
            'No <script type="json/oss-iq-report"> tag found in the built HTML. '
            "Ensure frontend/index.html contains the data script tag."
        )
    return result


def build_frontend(project_root: Path) -> Path:
    """Build the frontend and produce the SPA template with placeholder.

    Args:
        project_root: The root directory of the ossiq-cli project.

    Returns:
        Path to the generated spa_app.html template.

    Raises:
        RuntimeError: If npm is not available.
        FileNotFoundError: If the frontend build does not produce output.
    """
    frontend_dir = project_root / "frontend"
    target_html = project_root / "src" / "ossiq" / "ui" / "html_templates" / "spa_app.html"

    npm = shutil.which("npm")
    if not npm:
        raise RuntimeError("npm is required to build frontend assets.")

    subprocess.check_call([npm, "install"], cwd=str(frontend_dir))
    subprocess.check_call([npm, "run", "build"], cwd=str(frontend_dir))

    built_html = frontend_dir / "dist" / "index.html"
    if not built_html.exists():
        raise FileNotFoundError(f"Frontend build did not produce {built_html}")

    html_content = built_html.read_text(encoding="utf-8")
    template_html = replace_report_data_with_placeholder(html_content)

    target_html.parent.mkdir(parents=True, exist_ok=True)
    target_html.write_text(template_html, encoding="utf-8")

    print(f"SPA template written to {target_html} ({target_html.stat().st_size:,} bytes)")
    return target_html


if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    build_frontend(root)
