from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from plugins.base import ServiceScan

if TYPE_CHECKING:
    from models import Service, Target
    from scanner import Scanner


class SmbclientScan(ServiceScan):
    """List SMB shares anonymously with smbclient."""

    name = "SMBClient Share List"
    slug = "smbclient"
    tags = ["default", "smb"]
    priority = 29
    run_once_per_target = True

    def configure(self) -> None:
        self.match_service_name(r"microsoft-ds|netbios|smb")
        self.match_port(139, 445)

    def check(self) -> bool:
        return self.binary_exists("smbclient")

    async def run(self, service: "Service", target: "Target", scanner: "Scanner") -> None:
        scandir = Path(target.scandir)
        outfile = scandir / "smbclient_shares.txt"

        # List shares anonymously
        cmd = (
            f'smbclient -L //{target.address} -N 2>&1 | tee "{outfile}"'
        )

        process, stdout, _ = await scanner.execute(
            cmd, target, tag="smbclient", outfile=outfile
        )

        shares: list[str] = []
        while True:
            line = await stdout.readline()
            if line is None:
                break
            line = line.strip()
            if "Disk" in line or "IPC" in line or "Printer" in line:
                scanner.add_finding(target, f"[smbclient] Share: {line}")
                shares.append(line)

        await process.wait()

        # Try to list readable shares
        for share_line in shares:
            parts = share_line.split()
            if not parts:
                continue
            share_name = parts[0].strip()
            if share_name.startswith("//") or not share_name:
                continue

            list_cmd = (
                f'smbclient //{target.address}/{share_name} -N '
                f'-c "ls" 2>&1 | head -40'
            )
            ls_out = scandir / f"smbclient_{share_name}_ls.txt"
            proc2, out2, _ = await scanner.execute(
                list_cmd, target, tag=f"smbclient:{share_name}", outfile=ls_out
            )
            while True:
                l = await out2.readline()
                if l is None:
                    break
                if l.strip() and "NT_STATUS" not in l and "Anonymous" not in l:
                    scanner.add_finding(target, f"[smbclient:{share_name}] {l.strip()}")
            await proc2.wait()
