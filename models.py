from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Service:
    protocol: str       # 'tcp' | 'udp'
    port: int
    name: str           # e.g. 'http', 'ssh', 'microsoft-ds'
    product: str = ""   # e.g. 'Apache httpd'
    version: str = ""   # e.g. '2.4.29'
    secure: bool = False  # True for ssl/tls variants

    @property
    def http_scheme(self) -> str:
        return "https" if self.secure else "http"

    def __str__(self) -> str:
        parts = [f"{self.port}/{self.protocol}", self.name]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(parts)


@dataclass
class Target:
    address: str
    scandir: str = ""
    services: list[Service] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def add_service(self, service: Service) -> None:
        # Avoid duplicates
        key = (service.protocol, service.port)
        existing = {(s.protocol, s.port) for s in self.services}
        if key not in existing:
            self.services.append(service)

    def get_services_by_port(self, port: int) -> list[Service]:
        return [s for s in self.services if s.port == port]

    def get_services_by_name(self, name: str) -> list[Service]:
        import re
        return [s for s in self.services if re.search(name, s.name, re.IGNORECASE)]

    def __str__(self) -> str:
        return self.address


@dataclass
class ScanState:
    target: str
    completed_plugins: list[str] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)   # serialised Service dicts
    findings: list[str] = field(default_factory=list)
    started_at: Optional[str] = None
    updated_at: Optional[str] = None

    def is_done(self, plugin_name: str) -> bool:
        return plugin_name in self.completed_plugins

    def mark_done(self, plugin_name: str) -> None:
        if plugin_name not in self.completed_plugins:
            self.completed_plugins.append(plugin_name)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "completed_plugins": self.completed_plugins,
            "services": self.services,
            "findings": self.findings,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScanState":
        return cls(
            target=data.get("target", ""),
            completed_plugins=data.get("completed_plugins", []),
            services=data.get("services", []),
            findings=data.get("findings", []),
            started_at=data.get("started_at"),
            updated_at=data.get("updated_at"),
        )
