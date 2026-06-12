from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table

try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv()
except Exception:
    pass

from .executor import OSINTExecutor
from .modules_network import DNSModule, IPGeolocationModule, WHOISModule
from .modules_social import EmailFinderModule, HaveIBeenPwnedModule, SocialMediaModule
from .output import render_findings


DEFAULT_MODULES = [
    IPGeolocationModule(),
    DNSModule(),
    WHOISModule(),
    SocialMediaModule(),
    HaveIBeenPwnedModule(),
    EmailFinderModule(),
]


def _read_targets_file(path: Path) -> List[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def cmd_modules(_: argparse.Namespace) -> int:
    console = Console()
    table = Table(title="osinter modules", show_header=True, header_style="bold magenta")
    table.add_column("Name", style="cyan")
    table.add_column("Targets", style="green")
    table.add_column("Description")

    executor = OSINTExecutor(DEFAULT_MODULES)
    for m in executor.list_modules():
        table.add_row(m.name, ", ".join(m.target_types), m.description)

    console.print(table)
    return 0


async def _scan_async(args: argparse.Namespace) -> int:
    console = Console()
    executor = OSINTExecutor(DEFAULT_MODULES, semaphore=args.threads, verbose=args.verbose)

    targets: List[str] = []
    if args.file:
        targets = _read_targets_file(Path(args.file))
    elif args.target:
        targets = [args.target]
    else:
        raise SystemExit("Provide a target or -f/--file.")

    if len(targets) == 1:
        findings = await executor.scan(targets[0], target_type=args.type)
    else:
        findings = await executor.scan_many(targets, target_type=args.type)

    render_findings(findings, console=console)

    if args.export_json:
        OSINTExecutor.export_json(findings, Path(args.export_json))
        console.print(f"[green]Exported JSON:[/green] {args.export_json}")

    if args.export_csv:
        OSINTExecutor.export_csv(findings, Path(args.export_csv))
        console.print(f"[green]Exported CSV:[/green] {args.export_csv}")

    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    return asyncio.run(_scan_async(args))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="osinter", description="osinter — Complete OSINT Framework")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan single or batch targets")
    p_scan.add_argument("target", nargs="?", help="Target to scan (ip/domain/email/username)")
    p_scan.add_argument("-f", "--file", help="File containing targets (one per line)")
    p_scan.add_argument("-t", "--type", choices=["ip", "domain", "email", "username"], help="Force target type")
    p_scan.add_argument("--export-json", dest="export_json", help="Export findings to JSON file")
    p_scan.add_argument("--export-csv", dest="export_csv", help="Export findings to CSV file")
    p_scan.add_argument("--threads", type=int, default=5, help="Concurrency/semaphore size")
    p_scan.add_argument("-v", "--verbose", action="store_true", help="Verbose error output")
    p_scan.set_defaults(func=cmd_scan)

    p_mods = sub.add_parser("modules", help="List available modules")
    p_mods.set_defaults(func=cmd_modules)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

