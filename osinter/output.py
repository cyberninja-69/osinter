from __future__ import annotations

import json
from collections import defaultdict
from typing import Iterable, List

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .base import Finding


def _confidence_bar(confidence: float, *, width: int = 10) -> str:
    c = max(0.0, min(1.0, float(confidence)))
    filled = int(round(c * width))
    return "█" * filled + "░" * (width - filled)


def render_findings(findings: Iterable[Finding], *, console: Console | None = None) -> None:
    console = console or Console()

    findings_list: List[Finding] = list(findings)
    if not findings_list:
        console.print("[yellow]No findings.[/yellow]")
        return

    grouped = defaultdict(list)
    for f in findings_list:
        grouped[f.source].append(f)

    for source in sorted(grouped.keys()):
        console.print()
        console.print(Text(source.upper(), style="bold cyan"))

        for finding in grouped[source]:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Data", style="dim", width=18)
            table.add_column("Value")
            table.add_column("Conf", justify="right", width=14)

            if isinstance(finding.data, dict) and finding.data:
                for k, v in finding.data.items():
                    if isinstance(v, (dict, list)):
                        v_str = json.dumps(v, ensure_ascii=False)
                    else:
                        v_str = str(v)
                    table.add_row(str(k), v_str, _confidence_bar(finding.confidence))
            else:
                table.add_row("-", "-", _confidence_bar(finding.confidence))

            console.print(table)

    console.print()
    console.print(
        f"[green]Summary:[/green] {len(findings_list)} findings "
        f"from {len(grouped)} modules"
    )
