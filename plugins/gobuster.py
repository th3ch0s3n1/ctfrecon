from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from plugins.base import ServiceScan

if TYPE_CHECKING:
    from models import Service, Target
    from scanner import Scanner


class GobusterScan(ServiceScan):
    """Directory brute-force against HTTP/HTTPS services."""

    name = "Gobuster Dir"
    slug = "gobuster"
    tags = ["default", "web"]
    priority = 30

    def configure(self) -> None:
        self.match_service_name(r"^http")
        self.match_service_name(r"^nacn_http$", negative_match=True)

    def check(self) -> bool:
        return self.binary_exists("gobuster")

    async def run(self, service: "Service", target: "Target", scanner: "Scanner") -> None:
        from wordlists import resolve_wordlist

        wordlist = resolve_wordlist("web_dirs")
        if wordlist is None:
            scanner.log("[yellow]gobuster: no suitable wordlist found, skipping[/yellow]")
            return

        scandir = Path(target.scandir)
        scheme = service.http_scheme
        url = f"{scheme}://{target.address}:{service.port}"
        outfile = scandir / f"gobuster_{service.port}_{scheme}.txt"

        cmd = (
            f"gobuster dir -u {url} -w {wordlist} "
            f"-t 30 -q --no-error "
            f'-o "{outfile}"'
        )

        process, stdout, stderr = await scanner.execute(
            cmd, target, tag=f"gobuster:{service.port}", outfile=outfile
        )

        # Stream findings in real time
        while True:
            line = await stdout.readline()
            if line is None:
                break
            line = line.strip()
            if line and not line.startswith("Error") and not line.startswith("Progress"):
                scanner.add_finding(target, f"[gobuster:{service.port}] {line}")

        await process.wait()
