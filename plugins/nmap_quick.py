from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from plugins.base import PortScan

if TYPE_CHECKING:
    from models import Service, Target
    from scanner import Scanner


class NmapQuickScan(PortScan):
    """Top-1000 TCP ports with service/version detection. Results stream in live."""

    name = "Nmap Quick Scan"
    slug = "nmap-quick"
    tags = ["default", "fast"]
    priority = 10
    full_scan = False

    def check(self) -> bool:
        return self.binary_exists("nmap")

    async def run(self, target: "Target", scanner: "Scanner") -> list["Service"]:
        scandir = Path(target.scandir)
        xml_dir = scandir / "xml"
        xml_dir.mkdir(parents=True, exist_ok=True)

        cmd = (
            f"nmap -sV -sC --version-all -A --osscan-guess "
            f"-T4 "
            f'-oN "{scandir}/nmap_quick_tcp.txt" '
            f'-oX "{xml_dir}/nmap_quick_tcp.xml" '
            f"{target.address}"
        )

        process, stdout, stderr = await scanner.execute(
            cmd,
            target,
            tag="nmap-quick",
            outfile=scandir / "nmap_quick_tcp.txt",
        )

        services = await scanner.extract_services(stdout)
        await process.wait()

        if process.returncode != 0 and not services:
            scanner.log(
                f"[yellow]nmap-quick exited {process.returncode} for {target.address}[/yellow]"
            )

        return services
