import difflib

from rich.text import Text

def diff_dicts(old, new):
    removed = set(old.keys()) - set(new.keys())
    added = set(new.keys()) - set(old.keys())
    common = set(old.keys()) & set(new.keys())

    changed = {}
    for k in common:
        if old[k]["signature"] != new[k]["signature"] or old[k]["params"] != new[k]["params"]:
            changed[k] = {"old": old[k], "new": new[k]}
    return removed, added, changed

def diff_exports(exports_old, exports_new):
    return {
        cat: diff_dicts(exports_old[cat], exports_new[cat])
        for cat in ["functions", "classes", "methods", "constructors"]
    }

# ---- Inline diff rendering ----
def render_inline_diff(old_text, new_text):
    diff = difflib.ndiff(old_text.splitlines(), new_text.splitlines())
    rendered = Text()
    for line in diff:
        if line.startswith("-"):
            rendered.append(line + "\n", style="red")
        elif line.startswith("+"):
            rendered.append(line + "\n", style="green")
        elif line.startswith("?"):
            continue  # skip guide lines
        else:
            rendered.append(line + "\n", style="white")
    return rendered
