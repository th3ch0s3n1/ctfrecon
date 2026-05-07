from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from plugins.base import ServiceScan

if TYPE_CHECKING:
    from models import Service, Target
    from scanner import Scanner


class WhatwebScan(ServiceScan):
    """Technology fingerprinting for HTTP/HTTPS services."""

    name = "WhatWeb"
    slug = "whatweb"
    tags = ["default", "web"]
    priority = 25  # run before gobuster/nikto

    def configure(self) -> None:
        self.match_service_name(r"^http")
        self.match_service_name(r"^nacn_http$", negative_match=True)

    def check(self) -> bool:
        return self.binary_exists("whatweb")

    async def run(self, service: "Service", target: "Target", scanner: "Scanner") -> None:
        scandir = Path(target.scandir)
        scheme = service.http_scheme
        url = f"{scheme}://{target.address}:{service.port}"
        outfile = scandir / f"whatweb_{service.port}_{scheme}.txt"

        cmd = (
            f'whatweb --color=never --log-brief="{outfile}" '
            f"-a 3 {url}"
        )

        process, stdout, stderr = await scanner.execute(
            cmd, target, tag=f"whatweb:{service.port}", outfile=outfile
        )

        while True:
            line = await stdout.readline()
            if line is None:
                break
            line = line.strip()
            if line:
                scanner.add_finding(target, f"[whatweb:{service.port}] {line}")

        await process.wait()
