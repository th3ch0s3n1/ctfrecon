from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from plugins.base import ServiceScan

if TYPE_CHECKING:
    from models import Service, Target
    from scanner import Scanner


class SearchsploitScan(ServiceScan):
    """Look up CVEs/exploits for detected service versions via searchsploit."""

    name = "Searchsploit"
    slug = "searchsploit"
    tags = ["default", "cve"]
    priority = 90   # run last, after we have version info

    def configure(self) -> None:
        # Matches any service — we filter on version availability in run()
        self.match_port(
            21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 443, 445,
            512, 513, 514, 1099, 1524, 2049, 3306, 3389, 5432, 5900,
            6000, 6667, 8080, 8443, 8888,
        )

    def check(self) -> bool:
        return self.binary_exists("searchsploit")

    async def run(self, service: "Service", target: "Target", scanner: "Scanner") -> None:
        if not service.product:
            scanner.log(
                f"[dim]searchsploit: no product info for port {service.port}, skipping[/dim]",
                verbose_only=True,
            )
            return

        query = service.product
        if service.version:
            query = f"{service.product} {service.version}"

        scandir = Path(target.scandir)
        outfile = scandir / f"searchsploit_{service.port}.txt"

        cmd = f'searchsploit "{query}" 2>&1 | tee "{outfile}"'

        process, stdout, _ = await scanner.execute(
            cmd, target, tag=f"searchsploit:{service.port}", outfile=outfile
        )

        hit_re = re.compile(r"^\s*\|?\s*(.+?)\s+\|\s+(EDB-ID:\d+|\d+)\s*$")
        while True:
            line = await stdout.readline()
            if line is None:
                break
            line = line.strip()
            # Skip header/separator lines
            if not line or line.startswith("-") or line.startswith("="):
                continue
            if "No Results" in line:
                scanner.log(
                    f"[dim]searchsploit: no results for '{query}'[/dim]",
                    verbose_only=True,
                )
                break
            # Capture exploit entries
            if "|" in line and "EDB-ID" not in line and "Title" not in line:
                scanner.add_finding(
                    target, f"[searchsploit:{service.port}] {query} -> {line}"
                )

        await process.wait()
