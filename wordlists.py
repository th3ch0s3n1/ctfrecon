"""
Resolve wordlist paths for Kali Linux.
Tries common installed locations and falls back gracefully.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

# Ordered preference lists for each category
_WORDLIST_CANDIDATES: dict[str, list[str]] = {
    "web_dirs": [
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ],
    "web_files": [
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",
        "/usr/share/wordlists/dirb/common.txt",
    ],
    "users": [
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/wordlists/metasploit/unix_users.txt",
        "/usr/share/seclists/Usernames/Names/names.txt",
    ],
    "passwords": [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
        "/usr/share/wordlists/metasploit/unix_passwords.txt",
    ],
    "subdomains": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
    ],
}

_cache: dict[str, Optional[str]] = {}


def resolve_wordlist(category: str) -> Optional[str]:
    """Return the path of the first existing wordlist for the given category."""
    if category in _cache:
        return _cache[category]

    candidates = _WORDLIST_CANDIDATES.get(category, [])
    for path in candidates:
        p = Path(path)
        if p.exists():
            _cache[category] = str(p)
            return str(p)

    # Try to unzip rockyou if compressed version found
    if category == "passwords":
        gz = Path("/usr/share/wordlists/rockyou.txt.gz")
        txt = Path("/usr/share/wordlists/rockyou.txt")
        if gz.exists() and not txt.exists():
            import subprocess
            try:
                subprocess.run(["gunzip", str(gz)], check=True, capture_output=True)
                if txt.exists():
                    _cache[category] = str(txt)
                    return str(txt)
            except Exception:
                pass

    _cache[category] = None
    return None
