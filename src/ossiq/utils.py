import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .code.diffs import diff_exports, render_inline_diff
from .code.ast_parser import parse_files_with_tree_sitter, JS_LANGUAGE
from .code.api_index import PackageApiIndex


console = Console()


def print_report(diffs):
    console.print(
        Panel(Text("API Diff Report", style="bold cyan"), expand=False))

    for category, (removed, added, changed) in diffs.items():
        if not (removed or added or changed):
            continue

        console.rule(f"[bold yellow]{category.capitalize()}")

        if removed:
            console.print("[bold red]Removed[/bold red]")
            for f in removed:
                console.print(f"  - {f}", style="red")

        if added:
            console.print("\n[bold green]Added[/bold green]")
            for f in added:
                console.print(f"  + {f}", style="green")

        if changed:
            console.print("\n[bold blue]Changed[/bold blue]")
            for f, diff in changed.items():
                console.print(Panel(f, style="bold magenta"))

                sig_diff = render_inline_diff(
                    diff["old"]["signature"], diff["new"]["signature"])
                console.print("[bold]Signature Diff:[/bold]")
                console.print(sig_diff)

                params_old = json.dumps(diff["old"]["params"], indent=2)
                params_new = json.dumps(diff["new"]["params"], indent=2)
                param_diff = render_inline_diff(params_old, params_new)
                console.print("[bold]Params Diff:[/bold]")
                console.print(param_diff)

                if diff["old"]["doc"] or diff["new"]["doc"]:
                    doc_diff = render_inline_diff(
                        diff["old"]["doc"], diff["new"]["doc"])
                    console.print("[bold]Doc Diff:[/bold]")
                    console.print(doc_diff)


def run_analysis(repo_v1, repo_v2):
    index_v1 = PackageApiIndex()
    exports_v1 = parse_files_with_tree_sitter(index_v1, repo_v1, JS_LANGUAGE)
    print(index_v1)
    return
    Path("cache_v1.json").write_text(json.dumps(exports_v1, indent=2))
    exports_v2 = parse_files_with_tree_sitter(repo_v2, JS_LANGUAGE)
    Path("cache_v2.json").write_text(json.dumps(exports_v2, indent=2))

    # 4. Diff + Report
    diffs = diff_exports(exports_v1, exports_v2)
    print_report(diffs)
