import hashlib
from pathlib import Path

from sphinx.application import Sphinx
from sphinx_immaterial.mermaid_diagrams import MermaidDirective

project = "OSS IQ"
author = "Maksym Klymyshyn"
copyright = "2026, OSS IQ DEV SL"
html_baseurl = "https://ossiq.dev/"

extensions = [
    "myst_parser",
    "sphinx.ext.mathjax",
    "sphinx_immaterial",
    "sphinxext.opengraph",
]

templates_path = ["_templates"]
html_static_path = ["_static"]
html_extra_path = ["_static/llms.txt", "_static/robots.txt", "_static/images/favicon/favicon.ico"]

# Custom landing page replaces index.html
html_additional_pages = {
    "index": "landing.html",
    "journal/index": "journal/index.html",
    "journal/the-hidden-cost-of-ai-generated-code": "journal/the-hidden-cost-of-ai-generated-code.html",
    "journal/the-poisoned-well-ai-supply-chain-attacks": "journal/the-poisoned-well-ai-supply-chain-attacks.html",
}
# landing.html loads its script by hand, so it misses the ?v= checksum Sphinx gives html_js_files;
# without one a browser can pair fresh HTML with a cached old landing.js.
html_context = {
    "landing_js_version": hashlib.sha256(
        (Path(__file__).parent / "_static/landing/landing.js").read_bytes()
    ).hexdigest()[:8],
}
html_css_files = ["ossiq.css"]
html_js_files = [("search_compat.js", {"defer": "defer"})]

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "html_admonition",
    "html_image",
    "replacements",
    "smartquotes",
    "strikethrough",
    "tasklist",
    "attrs_inline",
    "attrs_block",
    "dollarmath",
]
# MathJax v3 with SVG output (tex-svg.js). Chosen over sphinx.ext.imgmath because imgmath
# shells out to a local latex + dvisvgm install, which CI and contributor machines lack.
mathjax_path = "https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-svg.js"

myst_heading_anchors = 3
# Lets plain ```mermaid fences (the syntax GitHub/VS Code previewers recognize)
# also trigger the `mermaid` directive registered in setup() below, instead of requiring
# ```{md-mermaid}.
myst_fence_as_directive = ["mermaid"]

pygments_style = "sphinx"

html_theme = "sphinx_immaterial"
html_title = "OSS IQ"
html_logo = "img/oss-iq-logo-light.svg"
html_favicon = "_static/images/favicon/favicon.svg"

html_theme_options = {
    "site_url": "https://ossiq.dev/",
    "repo_url": "https://github.com/ossiq/ossiq",
    "repo_name": "ossiq/ossiq",
    "edit_uri": "blob/main/docs/",
    # Keeps every sidebar group expanded, so the Explanation sidebar mirrors the tables on its
    # index page from any page, not only from the page inside the open group.
    "globaltoc_collapse": False,
    "palette": [
        {
            "scheme": "default",
            "primary": "white",
            "toggle": {
                "icon": "material/brightness-7",
                "name": "Switch to dark mode",
            },
        },
        {
            "scheme": "slate",
            "primary": "black",
            "accent": "black",
            "toggle": {
                "icon": "material/brightness-4",
                "name": "Switch to light mode",
            },
        },
    ],
    "features": [
        "navigation.tabs",
        "navigation.sections",
        "toc.integrate",
        "navigation.top",
        "search.suggest",
        "search.highlight",
        "content.tabs.link",
    ],
}

# sphinxext-opengraph — applies to all regular doc pages
ogp_site_url = "https://ossiq.dev/"
ogp_image = "https://ossiq.dev/_static/images/og-landing.jpg"
ogp_description_length = 200
ogp_type = "website"
ogp_enable_meta_description = True
ogp_custom_meta_tags = [
    '<meta name="twitter:card" content="summary_large_image">',
]


def setup(app: Sphinx) -> None:
    """Route plain `mermaid` fences to the theme's own diagram renderer.

    sphinx_immaterial already finds every `pre.mermaid` on a page and draws it. A second
    renderer (sphinxcontrib-mermaid) re-read each diagram after the theme replaced it, found no
    text, and left a "Syntax error" SVG behind, which its fullscreen button then showed.
    """
    app.add_directive("mermaid", MermaidDirective)
