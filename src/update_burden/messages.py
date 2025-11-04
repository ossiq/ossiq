HELP_TEXT = """
Utility to determine difference between versions of the same package.
Support languages:
 - TypeScript
 - JavaScript
"""

HELP_LAG_THRESHOULD = """
Time delta after which a package is considered to be lagging.
Supported units: y/m/w/d/h, default: d (days).
Exit with non-zero status code if lag exceeds this threshold.
"""

HELP_PRODUCTION_ONLY = """
Exclude development packages if specified. Default: false
"""
