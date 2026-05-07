# ctfrecon

A Python-based CTF recon automation tool that chains **nmap** with service-specific tools in a smart decision tree. Designed for HackTheBox, TryHackMe, and CTF targets.

---

## How it works

1. Runs **nmap** against the target (top-1000 or all 65535 ports)
2. Parses discovered services in real time (live stream — no waiting for nmap to finish)
3. Automatically triggers the right follow-up tools based on what's found:

| Discovered service | Tools triggered |
|--------------------|-----------------|
| Port 80 / 443 / 8080 | gobuster, nikto, whatweb |
| Port 445 / 139 (SMB) | enum4linux, smbclient |
| Port 21 / 22 | hydra *(only with `--brute`)* |
| Any open port | searchsploit CVE lookup |

4. Saves a **Markdown + HTML report** and a `state.json` for resuming interrupted scans

---

## Requirements

- Kali Linux (tools assumed installed: `nmap`, `gobuster`, `nikto`, `whatweb`, `enum4linux`/`enum4linux-ng`, `smbclient`, `searchsploit`, `hydra`)
- Python 3.10+

## Installation

```bash
git clone https://github.com/th3ch0s3n1/ctfrecon
cd ctfrecon
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

```bash
# Fast scan (top-1000 ports) — default
python main.py --target 10.10.10.5

# Full scan (all 65535 ports)
python main.py --target 10.10.10.5 --mode full

# Full scan + brute force (hydra)
python main.py --target 10.10.10.5 --mode full --brute

# Subnet sweep
python main.py --target 10.10.10.0/24 --mode fast --quiet

# Resume an interrupted scan
python main.py --target 10.10.10.5 --resume

# Verbose output (shows commands as they run)
python main.py --target 10.10.10.5 --verbose
```

### All options

| Flag | Description |
|------|-------------|
| `--target / -t` | IP, CIDR range, or hostname (multiple allowed) |
| `--mode / -m` | `fast` (top-1000) · `full` (all ports) · `all` (both) — default: `fast` |
| `--brute / -b` | Enable brute-force plugins (hydra) |
| `--output / -o` | Output directory — default: `./results` |
| `--resume / -r` | Resume from `state.json` — skips completed plugins |
| `--verbose / -v` | Show every command as it runs |
| `--quiet / -q` | Suppress all output except findings |
| `--max-scans` | Max concurrent service scans — default: `10` |

---

## Output

Results are saved to `results/<target>/`:

```
results/10.10.10.5/
├── state.json                  ← resume state
├── report.md                   ← Markdown report
├── report.html                 ← HTML report (dark theme)
├── nmap_quick_tcp.txt
├── nmap_full_tcp.txt           ← (full mode only)
├── gobuster_80_http.txt
├── nikto_80_http.txt
├── whatweb_80_http.txt
├── enum4linux.txt
├── smbclient_shares.txt
├── searchsploit_80.txt
├── hydra_ssh_22.txt            ← (--brute only)
└── xml/
    ├── nmap_quick_tcp.xml
    └── nmap_full_tcp.xml
```

---

## Adding a plugin

Drop a `.py` file into `plugins/` — it's auto-discovered at startup.

```python
# plugins/my_tool.py
from plugins.base import ServiceScan

class MyTool(ServiceScan):
    name = "My Tool"
    slug = "my-tool"
    priority = 40

    def configure(self):
        self.match_service_name(r"^http")   # trigger on HTTP services
        # self.match_port(8080, 8443)       # or match by port

    def check(self):
        return self.binary_exists("mytool")

    async def run(self, service, target, scanner):
        process, stdout, _ = await scanner.execute(
            f"mytool {target.address}:{service.port}",
            target, tag="my-tool"
        )
        while True:
            line = await stdout.readline()
            if line is None:
                break
            if "interesting" in line.lower():
                scanner.add_finding(target, f"[my-tool] {line}")
        await process.wait()
```

---

## Disclaimer

This tool is intended for **authorized testing only** — CTF platforms (HackTheBox, TryHackMe), your own lab VMs, or systems you have explicit written permission to test. Never run against targets you don't own or have authorization for.
