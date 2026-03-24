project = "OSS IQ"
author = "Maksym Klymyshyn"
copyright = "2026, Maksym Klymyshyn"
html_baseurl = "https://ossiq.dev/"

extensions = [
    "myst_parser",
    "sphinx_immaterial",
    "sphinxext.opengraph",
]

templates_path = ["_templates"]
html_static_path = ["_static"]
html_extra_path = ["img", "samples", "_static/llms.txt", "_static/robots.txt"]

# Custom landing page replaces index.html
html_additional_pages = {"index": "landing.html"}
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
]
myst_heading_anchors = 2

pygments_style = "sphinx"

html_theme = "sphinx_immaterial"
html_title = "OSS IQ"
html_logo = "img/oss-iq-logo-light.svg"

html_theme_options = {
    "site_url": "https://ossiq.dev/",
    "repo_url": "https://github.com/ossiq/ossiq",
    "repo_name": "ossiq/ossiq",
    "edit_uri": "blob/main/docs/",
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
ogp_image = "https://ossiq.dev/img/ossiq-report-html-light.png"
ogp_description_length = 200
ogp_type = "website"
ogp_enable_meta_description = True
ogp_custom_meta_tags = [
    '<meta name="twitter:card" content="summary_large_image">',
]
