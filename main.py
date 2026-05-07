#!/usr/bin/env python3
"""
ctfrecon — CTF Recon Automation Tool
Usage: python main.py --target <IP|CIDR|domain> [options]
"""
from __future__ import annotations

import argparse
import asyncio
import importlib.util
import inspect
import ipaddress
import os
import sys
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from plugins.base import PortScan, ServiceScan
from reporter import Reporter
from scanner import Scanner

console = Console()

BANNER = """
 ██████╗████████╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║        ██║   █████╗  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║        ██║   ██╔══╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚██████╗   ██║   ██║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
CTF Recon Automation Tool  |  github.com/th3ch0s3n1/ctfrecon
"""


def load_plugins(plugins_dir: Path) -> tuple[list[PortScan], list[ServiceScan]]:
    """Dynamically discover and load all plugin classes from the plugins/ directory."""
    port_scan_plugins: list[PortScan] = []
    service_scan_plugins: list[ServiceScan] = []

    for py_file in sorted(plugins_dir.glob("*.py")):
        if py_file.name.startswith("_") or py_file.name == "base.py":
            continue

        spec = importlib.util.spec_from_file_location(
            f"ctfrecon.plugins.{py_file.stem}", py_file
        )
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as e:
            console.print(f"[yellow]Warning: failed to load plugin {py_file.name}: {e}[/yellow]")
            continue

        for _, cls in inspect.getmembers(module, predicate=inspect.isclass):
            if cls.__module__ != module.__name__:
                continue  # skip imported base classes
            if issubclass(cls, PortScan) and cls is not PortScan:
                instance = cls()
                instance.configure() if hasattr(instance, "configure") else None
                port_scan_plugins.append(instance)
            elif issubclass(cls, ServiceScan) and cls is not ServiceScan:
                instance = cls()
                instance.configure()
                service_scan_plugins.append(instance)

    return port_scan_plugins, service_scan_plugins


def expand_targets(raw: list[str]) -> list[str]:
    """Expand CIDR ranges into individual IPs, pass hostnames/single IPs as-is."""
    expanded: list[str] = []
    for t in raw:
        try:
            network = ipaddress.ip_network(t, strict=False)
            if network.num_addresses == 1:
                expanded.append(str(network.network_address))
            else:
                expanded.extend(str(ip) for ip in network.hosts())
        except ValueError:
            expanded.append(t)  # hostname or single IP string
    return expanded


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctfrecon",
        description="CTF Recon Automation Tool — chains nmap → service-specific tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python main.py --target 10.10.10.5
  python main.py --target 10.10.10.0/24 --mode fast --quiet
  python main.py --target example.com --mode full --brute
  python main.py --target 10.10.10.5 --resume --verbose
        """,
    )
    parser.add_argument(
        "--target", "-t",
        nargs="+",
        required=True,
        metavar="HOST",
        help="Target IP, CIDR range, or hostname (multiple allowed)",
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["fast", "full", "all"],
        default="fast",
        help="fast: top-1000 ports | full: all 65535 ports | all: both (default: fast)",
    )
    parser.add_argument(
        "--brute", "-b",
        action="store_true",
        help="Enable brute-force plugins (hydra, etc.)",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("results"),
        metavar="DIR",
        help="Output directory (default: ./results)",
    )
    parser.add_argument(
        "--resume", "-r",
        action="store_true",
        help="Resume an interrupted scan (reads state.json)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show commands as they run",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress all output except findings",
    )
    parser.add_argument(
        "--max-scans",
        type=int,
        default=10,
        metavar="N",
        help="Max concurrent service scans (default: 10)",
    )
    return parser


async def async_main(args: argparse.Namespace) -> None:
    if not args.quiet:
        console.print(f"[bold cyan]{BANNER}[/bold cyan]")

    targets = expand_targets(args.target)

    if not targets:
        console.print("[red]No valid targets provided.[/red]")
        sys.exit(1)

    if not args.quiet:
        console.print(
            Panel(
                f"[bold]Targets:[/bold] {', '.join(targets)}\n"
                f"[bold]Mode:[/bold]    {args.mode}\n"
                f"[bold]Output:[/bold]  {args.output}\n"
                f"[bold]Brute:[/bold]   {'yes' if args.brute else 'no'}\n"
                f"[bold]Resume:[/bold]  {'yes' if args.resume else 'no'}",
                title="ctfrecon",
                border_style="cyan",
            )
        )

    plugins_dir = Path(__file__).parent / "plugins"
    port_plugins, service_plugins = load_plugins(plugins_dir)

    if not args.quiet:
        console.print(
            f"[dim]Loaded {len(port_plugins)} port-scan plugin(s), "
            f"{len(service_plugins)} service-scan plugin(s)[/dim]"
        )

    scanner = Scanner(
        targets=targets,
        output_dir=args.output,
        mode=args.mode,
        brute=args.brute,
        verbose=args.verbose,
        quiet=args.quiet,
        resume=args.resume,
        max_port_scans=2,
        max_service_scans=args.max_scans,
    )
    scanner.port_scan_plugins = port_plugins
    scanner.service_scan_plugins = service_plugins

    await scanner.run_all()

    # Generate reports
    reporter = Reporter(scanner)
    for target in scanner.targets:
        reporter.generate(target)

    if not args.quiet:
        console.print("\n[bold green]Done![/bold green] Reports saved to:")
        for target in scanner.targets:
            out = args.output / target.address.replace("/", "_")
            console.print(f"  [cyan]{out}/report.md[/cyan]")
            console.print(f"  [cyan]{out}/report.html[/cyan]")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose and args.quiet:
        parser.error("--verbose and --quiet are mutually exclusive")

    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted. State saved — run with --resume to continue.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
