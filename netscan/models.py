from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class PortResult:
    port: int
    state: str
    service: str | None = None
    banner: str | None = None
    tls_subject: str | None = None
    tls_issuer: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class HostResult:
    address: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    is_live: bool = False
    ports: list[PortResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["open_port_count"] = len([port for port in self.ports if port.state == "open"])
        return data


@dataclass(frozen=True, slots=True)
class ScanConfig:
    ports: tuple[int, ...]
    timeout: float
    workers: int
    use_discovery: bool
    grab_banners: bool
    reverse_dns: bool
    arp: bool
