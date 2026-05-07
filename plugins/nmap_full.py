from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from plugins.base import PortScan

if TYPE_CHECKING:
    from models import Service, Target
    from scanner import Scanner


class NmapFullScan(PortScan):
    """Full 65535-port TCP scan — runs only in 'full' or 'all' mode."""

    name = "Nmap Full TCP Scan"
    slug = "nmap-full"
    tags = ["full"]
    priority = 20
    full_scan = True   # scanner checks this to skip in 'fast' mode

    def check(self) -> bool:
        return self.binary_exists("nmap")

    async def run(self, target: "Target", scanner: "Scanner") -> list["Service"]:
        scandir = Path(target.scandir)
        xml_dir = scandir / "xml"
        xml_dir.mkdir(parents=True, exist_ok=True)

        # Phase 1: discover all open ports quickly
        discover_cmd = (
            f"nmap -p- --min-rate 5000 -T4 --open "
            f'-oN "{scandir}/nmap_full_tcp_ports.txt" '
            f"{target.address}"
        )
        process1, stdout1, _ = await scanner.execute(
            discover_cmd,
            target,
            tag="nmap-full-ports",
        )
        # Collect open ports from this scan
        import re
        open_ports: list[str] = []
        while True:
            line = await stdout1.readline()
            if line is None:
                break
            m = re.match(r"^(\d+)/tcp\s+open", line.strip())
            if m:
                open_ports.append(m.group(1))
        await process1.wait()

        if not open_ports:
            scanner.log(
                f"[yellow]nmap-full: no additional open ports found on {target.address}[/yellow]"
            )
            return []

        ports_arg = ",".join(open_ports)
        scanner.log(
            f"[dim]nmap-full: probing {len(open_ports)} port(s) with -sV on {target.address}[/dim]",
            verbose_only=True,
        )

        # Phase 2: version detection on discovered ports
        version_cmd = (
            f"nmap -sV -sC --version-all -p {ports_arg} "
            f'-oN "{scandir}/nmap_full_tcp.txt" '
            f'-oX "{xml_dir}/nmap_full_tcp.xml" '
            f"{target.address}"
        )
        process2, stdout2, _ = await scanner.execute(
            version_cmd,
            target,
            tag="nmap-full-version",
            outfile=scandir / "nmap_full_tcp.txt",
        )
        services = await scanner.extract_services(stdout2)
        await process2.wait()

        return services
