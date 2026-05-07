from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from models import ScanState, Service, Target

if TYPE_CHECKING:
    from plugins.base import PortScan, ServiceScan

console = Console()

# ──────────────────────────────────────────────
# Stream reader that captures stdout/stderr
# ──────────────────────────────────────────────

class CommandStreamReader:
    def __init__(self, stream: asyncio.StreamReader, tag: str, outfile: Optional[Path] = None):
        self.stream = stream
        self.tag = tag
        self.outfile = outfile
        self.lines: list[str] = []
        self.ended = False
        self._fh = None

    async def _read(self) -> None:
        if self.outfile:
            self.outfile.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(self.outfile, "w", encoding="utf-8", errors="replace")
        try:
            while True:
                raw = await self.stream.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip()
                self.lines.append(line)
                if self._fh:
                    self._fh.write(line + "\n")
                    self._fh.flush()
        finally:
            if self._fh:
                self._fh.close()
            self.ended = True

    async def readline(self) -> Optional[str]:
        """Yield lines one at a time; returns None when stream is done."""
        while True:
            if self.lines:
                return self.lines.pop(0)
            if self.ended:
                return None
            await asyncio.sleep(0.05)

    def get_all(self) -> list[str]:
        return list(self.lines)


# ──────────────────────────────────────────────
# Core Scanner
# ──────────────────────────────────────────────

class Scanner:
    def __init__(
        self,
        targets: list[str],
        output_dir: Path,
        mode: str = "fast",
        brute: bool = False,
        verbose: bool = False,
        quiet: bool = False,
        resume: bool = False,
        max_port_scans: int = 2,
        max_service_scans: int = 10,
    ):
        self.targets: list[Target] = []
        self.output_dir = output_dir
        self.mode = mode
        self.brute = brute
        self.verbose = verbose
        self.quiet = quiet
        self.resume = resume

        self.port_scan_semaphore = asyncio.Semaphore(max_port_scans)
        self.service_scan_semaphore = asyncio.Semaphore(max_service_scans)

        self.port_scan_plugins: list[PortScan] = []
        self.service_scan_plugins: list[ServiceScan] = []

        self.states: dict[str, ScanState] = {}
        self.findings: dict[str, list[str]] = {}

        for addr in targets:
            t = Target(address=addr)
            t.scandir = str(output_dir / addr.replace("/", "_"))
            self.targets.append(t)

    # ── State persistence ──────────────────────

    def _state_path(self, target: Target) -> Path:
        return Path(target.scandir) / "state.json"

    def load_state(self, target: Target) -> ScanState:
        path = self._state_path(target)
        if self.resume and path.exists():
            with open(path) as f:
                data = json.load(f)
            state = ScanState.from_dict(data)
            # Restore previously discovered services
            for sd in state.services:
                svc = Service(**sd)
                target.add_service(svc)
            self.log(f"[cyan]Resuming scan for {target.address} "
                     f"({len(state.completed_plugins)} plugins already done)[/cyan]")
        else:
            state = ScanState(
                target=target.address,
                started_at=datetime.now(timezone.utc).isoformat(),
            )
        self.states[target.address] = state
        return state

    def save_state(self, target: Target) -> None:
        state = self.states[target.address]
        state.updated_at = datetime.now(timezone.utc).isoformat()
        # Sync services to state
        state.services = [
            {"protocol": s.protocol, "port": s.port, "name": s.name,
             "product": s.product, "version": s.version, "secure": s.secure}
            for s in target.services
        ]
        path = self._state_path(target)
        Path(target.scandir).mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(state.to_dict(), f, indent=2)

    # ── Logging ────────────────────────────────

    def log(self, msg: str, verbose_only: bool = False) -> None:
        if self.quiet:
            return
        if verbose_only and not self.verbose:
            return
        console.print(msg)

    def add_finding(self, target: Target, finding: str) -> None:
        self.findings.setdefault(target.address, []).append(finding)
        state = self.states.get(target.address)
        if state:
            state.findings.append(finding)
        self.log(f"[bold green][FINDING][/bold green] {finding}")

    # ── Process execution ──────────────────────

    async def execute(
        self,
        cmd: str,
        target: Target,
        tag: str,
        outfile: Optional[Path] = None,
        errfile: Optional[Path] = None,
    ) -> tuple[asyncio.subprocess.Process, CommandStreamReader, CommandStreamReader]:
        self.log(f"[dim]  [{tag}] {cmd}[/dim]", verbose_only=True)

        process = await asyncio.create_subprocess_shell(
            cmd,
            stdin=open(os.devnull),   # prevent stdin blocking
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        cout = CommandStreamReader(process.stdout, tag, outfile)
        cerr = CommandStreamReader(process.stderr, tag, errfile)
        asyncio.create_task(cout._read())
        asyncio.create_task(cerr._read())
        return process, cout, cerr

    # ── Service detection from nmap text ──────

    async def extract_services(self, stream: CommandStreamReader) -> list[Service]:
        services: list[Service] = []
        port_re = re.compile(
            r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+open\s+(?P<name>[\w\-/]+)"
            r"(?:\s+(?P<rest>.*))?$"
        )
        while True:
            line = await stream.readline()
            if line is None:
                break
            m = port_re.match(line.strip())
            if not m:
                continue
            name = m.group("name")
            secure = name.startswith("ssl/") or name.startswith("tls/")
            if secure:
                name = name.split("/", 1)[1]

            product = version = ""
            rest = (m.group("rest") or "").strip()
            # nmap -sV output: "Apache httpd 2.4.49 ((Debian))"
            if rest:
                parts = rest.split(" ")
                product = parts[0] if parts else ""
                version = parts[1] if len(parts) > 1 else ""
                # strip trailing junk like ((...))
                version = re.sub(r"\(.*\)", "", version).strip()

            svc = Service(
                protocol=m.group("proto"),
                port=int(m.group("port")),
                name=name,
                product=product,
                version=version,
                secure=secure,
            )
            services.append(svc)
            self.log(f"  [green]Found:[/green] {svc}")
        return services

    # ── Main orchestration ─────────────────────

    async def run_target(self, target: Target, progress: Progress, task_id) -> None:
        state = self.load_state(target)
        Path(target.scandir).mkdir(parents=True, exist_ok=True)

        # ── Phase 1: Port scans ───────────────
        port_tasks = []
        for plugin in sorted(self.port_scan_plugins, key=lambda p: p.priority):
            if state.is_done(plugin.slug):
                self.log(f"[dim]Skipping {plugin.name} (already done)[/dim]")
                continue
            if not plugin.check():
                self.log(f"[yellow]Skipping {plugin.name} (binary not found)[/yellow]")
                continue
            # Skip full scan unless mode is 'full' or 'all'
            if getattr(plugin, "full_scan", False) and self.mode == "fast":
                continue

            port_tasks.append(self._run_port_scan(plugin, target, state))

        new_services: list[Service] = []
        results = await asyncio.gather(*port_tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                self.log(f"[red]Port scan error: {r}[/red]")
            elif r:
                new_services.extend(r)

        for svc in new_services:
            target.add_service(svc)
        self.save_state(target)

        # ── Phase 2: Service scans ────────────
        service_tasks = []
        triggered: set[str] = set()  # for run_once_per_target

        for svc in target.services:
            for plugin in sorted(self.service_scan_plugins, key=lambda p: p.priority):
                key = f"{plugin.slug}:{svc.port}"
                once_key = plugin.slug

                if state.is_done(key):
                    continue
                if plugin.run_once_per_target and once_key in triggered:
                    continue
                if not plugin.matches(svc):
                    continue
                if not plugin.check():
                    self.log(f"[yellow]Skipping {plugin.name} (binary not found)[/yellow]")
                    continue
                # Hydra only runs if --brute is set
                if getattr(plugin, "requires_brute", False) and not self.brute:
                    continue

                triggered.add(once_key)
                service_tasks.append(self._run_service_scan(plugin, svc, target, state, key))

        await asyncio.gather(*service_tasks, return_exceptions=True)
        self.save_state(target)

        progress.advance(task_id)
        self.log(f"[bold green]Completed:[/bold green] {target.address}")

    async def _run_port_scan(
        self,
        plugin: "PortScan",
        target: Target,
        state: ScanState,
    ) -> list[Service]:
        async with self.port_scan_semaphore:
            self.log(f"[cyan]Running:[/cyan] {plugin.name} on {target.address}")
            try:
                services = await plugin.run(target, self)
                state.mark_done(plugin.slug)
                self.save_state(target)
                return services
            except Exception as e:
                self.log(f"[red]Error in {plugin.name}: {e}[/red]")
                return []

    async def _run_service_scan(
        self,
        plugin: "ServiceScan",
        service: Service,
        target: Target,
        state: ScanState,
        key: str,
    ) -> None:
        async with self.service_scan_semaphore:
            self.log(f"[cyan]Running:[/cyan] {plugin.name} on {service}")
            try:
                await plugin.run(service, target, self)
                state.mark_done(key)
                self.save_state(target)
            except Exception as e:
                self.log(f"[red]Error in {plugin.name}: {e}[/red]")

    async def run_all(self) -> None:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task_id = progress.add_task("Scanning targets...", total=len(self.targets))
            await asyncio.gather(
                *[self.run_target(t, progress, task_id) for t in self.targets]
            )
