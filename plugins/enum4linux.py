from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from plugins.base import ServiceScan

if TYPE_CHECKING:
    from models import Service, Target
    from scanner import Scanner


class Enum4linuxScan(ServiceScan):
    """SMB/Samba enumeration via enum4linux-ng."""

    name = "Enum4linux"
    slug = "enum4linux"
    tags = ["default", "smb"]
    priority = 30
    run_once_per_target = True

    def configure(self) -> None:
        self.match_service_name(r"microsoft-ds|netbios|smb")
        self.match_port(139, 445)

    def check(self) -> bool:
        # Prefer enum4linux-ng, fall back to enum4linux
        return self.binary_exists("enum4linux-ng") or self.binary_exists("enum4linux")

    async def run(self, service: "Service", target: "Target", scanner: "Scanner") -> None:
        import shutil

        scandir = Path(target.scandir)
        outfile = scandir / "enum4linux.txt"

        binary = "enum4linux-ng" if shutil.which("enum4linux-ng") else "enum4linux"

        if binary == "enum4linux-ng":
            cmd = (
                f'enum4linux-ng -A -oA "{scandir}/enum4linux" '
                f"{target.address} 2>&1"
            )
        else:
            cmd = f'enum4linux -a {target.address} 2>&1 | tee "{outfile}"'

        process, stdout, _ = await scanner.execute(
            cmd, target, tag="enum4linux", outfile=outfile
        )

        keywords = ("Domain", "Password", "Share", "User", "Group", "Policy", "Account")
        while True:
            line = await stdout.readline()
            if line is None:
                break
            line = line.strip()
            if any(kw.lower() in line.lower() for kw in keywords):
                scanner.add_finding(target, f"[enum4linux] {line}")

        await process.wait()
