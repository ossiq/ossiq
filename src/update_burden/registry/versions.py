"""
Module to operate with package versions
"""
import semver
import re


def normalize_version(spec: str) -> str:
    if not spec:
        return spec
    m = re.search(r"\d+\.\d+\.\d+(?:[-+][^\s,]*)?", spec)
    if m:
        return m.group(0)
    return spec


def compare_versions(v1: str, v2: str) -> int:
    """
    Compare two versions leveraging semver
    """
    try:
        return semver.compare(v1, v2)
    except Exception:
        return (v1 > v2) - (v1 < v2)
