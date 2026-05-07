from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from plugins.base import ServiceScan

if TYPE_CHECKING:
    from models import Service, Target
    from scanner import Scanner


class NiktoScan(ServiceScan):
    """Web server vulnerability scanner."""

    name = "Nikto"
    slug = "nikto"
    tags = ["default", "web"]
    priority = 31

    def configure(self) -> None:
        self.match_service_name(r"^http")
        self.match_service_name(r"^nacn_http$", negative_match=True)

    def check(self) -> bool:
        return self.binary_exists("nikto")

    async def run(self, service: "Service", target: "Target", scanner: "Scanner") -> None:
        scandir = Path(target.scandir)
        scheme = service.http_scheme
        outfile = scandir / f"nikto_{service.port}_{scheme}.txt"

        cmd = (
            f"nikto -ask=no -nointeractive "
            f"-host {scheme}://{target.address}:{service.port} "
            f"-Tuning x4567890ac "
            f'-output "{outfile}"'
        )

        process, stdout, stderr = await scanner.execute(
            cmd, target, tag=f"nikto:{service.port}", outfile=outfile
        )

        # Capture findings — nikto prefixes interesting lines with "+"
        while True:
            line = await stdout.readline()
            if line is None:
                break
            line = line.strip()
            if line.startswith("+") and "OSVDB" not in line or "CVE" in line:
                scanner.add_finding(target, f"[nikto:{service.port}] {line}")

        await process.wait()
