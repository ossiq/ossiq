# OSS IQ — Design Notes

Architectural decisions, known gaps, and deferred work.

---

## Gaps

Gaps identified during architectural review and deferred for separate implementation.

### GAP-5: No `is_yanked` / `is_deprecated` distinction in `PackageVersion`

**Context:** `PackageVersion.is_published = False` covers the case where a version has
been fully unpublished (removed from the registry). However, registries also expose
softer deprecation states:

- **PyPI**: Individual releases can be *yanked* (still downloadable but flagged unsafe).
  The current adapter sets `is_published=False` for yanked versions, conflating yanked
  with unpublished.
- **NPM**: Packages can be `deprecated` with a free-text reason, distinct from
  being unpublished.

These are meaningfully different signals: a yanked/deprecated package still exists and
may be transitively pulled in, but carries an explicit maintainer warning.

**Future work:** Add `is_yanked: bool = False` and `deprecation_notice: str | None = None`
fields to `PackageVersion`. Update `api_pypi.py` to set `is_published=True, is_yanked=True`
for yanked releases, and update `api_npm.py` to capture the `deprecated` field from NPM
registry responses.

---
