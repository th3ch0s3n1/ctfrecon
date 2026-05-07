from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from plugins.base import ServiceScan

if TYPE_CHECKING:
    from models import Service, Target
    from scanner import Scanner


class HydraScan(ServiceScan):
    """Brute-force login for SSH and FTP. Only runs with --brute flag."""

    name = "Hydra Brute Force"
    slug = "hydra"
    tags = ["brute"]
    priority = 80
    requires_brute = True    # scanner checks this flag

    # Default wordlists — resolved at runtime via wordlists.py
    _USER_LIST = None
    _PASS_LIST = None

    def configure(self) -> None:
        self.match_service_name(r"^ssh|^ftp")
        self.match_port(21, 22)

    def check(self) -> bool:
        return self.binary_exists("hydra")

    async def run(self, service: "Service", target: "Target", scanner: "Scanner") -> None:
        from wordlists import resolve_wordlist

        user_list = resolve_wordlist("users")
        pass_list = resolve_wordlist("passwords")

        if not user_list or not pass_list:
            scanner.log("[yellow]hydra: wordlists not found, skipping[/yellow]")
            return

        scandir = Path(target.scandir)
        proto = service.name.lower().split("/")[0]   # 'ssh' or 'ftp'
        outfile = scandir / f"hydra_{proto}_{service.port}.txt"

        cmd = (
            f"hydra -L {user_list} -P {pass_list} "
            f"-t 4 -f "
            f"{target.address} {proto} "
            f'-o "{outfile}"'
        )

        process, stdout, _ = await scanner.execute(
            cmd, target, tag=f"hydra:{proto}:{service.port}", outfile=outfile
        )

        while True:
            line = await stdout.readline()
            if line is None:
                break
            line = line.strip()
            if "login:" in line and "password:" in line:
                scanner.add_finding(
                    target, f"[hydra:{proto}:{service.port}] CREDENTIAL FOUND: {line}"
                )

        await process.wait()
