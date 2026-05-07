from __future__ import annotations
import re
import shutil
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from models import Target, Service


class Plugin(ABC):
    """Base class for all plugins."""

    name: str = ""
    slug: str = ""
    tags: list[str] = []
    priority: int = 50   # lower = runs first

    def check(self) -> bool:
        """Return False to disable this plugin (e.g. binary not found)."""
        return True

    def binary_exists(self, binary: str) -> bool:
        return shutil.which(binary) is not None


class PortScan(Plugin):
    """Runs against a Target and returns a list of discovered Services."""

    protocol: str = "tcp"  # 'tcp' | 'udp' | 'both'

    @abstractmethod
    async def run(self, target: "Target", scanner: "object") -> list["Service"]:
        ...


class ServiceScan(Plugin):
    """Runs against a Service when matching conditions are met."""

    _name_patterns: list[tuple[str, bool]] = []  # (pattern, negative)
    _port_list: list[int] = []
    run_once_per_target: bool = False

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Each subclass gets its own lists
        cls._name_patterns = []
        cls._port_list = []

    def match_service_name(self, pattern: str, negative_match: bool = False) -> None:
        self._name_patterns.append((pattern, negative_match))

    def match_port(self, *ports: int) -> None:
        self._port_list.extend(ports)

    def matches(self, service: "Service") -> bool:
        """Return True if this plugin should run against the given service."""
        port_match = not self._port_list or service.port in self._port_list

        if self._name_patterns:
            name_ok = True
            for pattern, negative in self._name_patterns:
                hit = bool(re.search(pattern, service.name, re.IGNORECASE))
                if negative and hit:
                    return False
                if not negative and not hit:
                    name_ok = False
            if not name_ok and not self._port_list:
                return False
            if self._port_list and not port_match:
                return False
        else:
            if not port_match:
                return False

        return True

    def configure(self) -> None:
        """Override to call match_service_name() / match_port()."""
        pass

    @abstractmethod
    async def run(self, service: "Service", target: "Target", scanner: "object") -> None:
        ...

    def manual(self, service: "Service", plugin_was_run: bool) -> Optional[str]:
        """Return a manual command suggestion, or None."""
        return None
