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

from pathlib import Path

import hatch_build

if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    hatch_build.build_frontend(root)
