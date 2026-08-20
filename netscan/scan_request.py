from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from .interfaces import local_ipv4_networks, overlapping_local_networks
from .models import ScanConfig
from .ports import MAX_DEFAULT_PORTS, parse_ports
from .safety import (
    DEFAULT_MAX_HOSTS,
    expand_target_networks,
    is_personal_network,
    parse_target_networks,
)


@dataclass(frozen=True, slots=True)
class ScanRequest:
    target: str = "local"
    ports: str = "top"
    timeout: float = 0.6
    workers: int = 128
    max_hosts: int = DEFAULT_MAX_HOSTS
    max_ports: int = MAX_DEFAULT_PORTS
    allow_public: bool = False
    discovery: bool = True
    banners: bool = True
    reverse_dns: bool = True
    arp: bool = True


@dataclass(frozen=True, slots=True)
class ScanPlan:
    targets: list[IPv4Address | IPv6Address]
    target_networks: list[IPv4Network | IPv6Network]
    local_networks: list[IPv4Network]
    config: ScanConfig

    @property
    def overlaps_local_network(self) -> bool:
        if not self.local_networks:
            return True
        return bool(overlapping_local_networks(self.target_networks, self.local_networks))


def resolve_scan_request(request: ScanRequest, *, require_local_overlap: bool = False) -> ScanPlan:
    ports = parse_ports(request.ports, max_ports=request.max_ports)
    local_networks = local_ipv4_networks()

    if request.target == "local":
        target_networks = [network for network in local_networks if is_personal_network(network)]
        if not target_networks:
            raise ValueError("No local personal IPv4 networks were found.")
    else:
        target_networks = parse_target_networks(
            request.target, allow_public=request.allow_public
        )

    if (
        require_local_overlap
        and local_networks
        and not request.allow_public
        and not overlapping_local_networks(target_networks, local_networks)
    ):
        target_text = ", ".join(str(network) for network in target_networks)
        local_text = ", ".join(str(network) for network in local_networks)
        raise ValueError(
            f"Target {target_text} does not overlap local IPv4 network(s): {local_text}."
        )

    if request.timeout <= 0:
        raise ValueError("timeout must be greater than zero.")
    if request.workers < 1:
        raise ValueError("workers must be at least 1.")

    return ScanPlan(
        targets=expand_target_networks(target_networks, max_hosts=request.max_hosts),
        target_networks=target_networks,
        local_networks=local_networks,
        config=ScanConfig(
            ports=ports,
            timeout=request.timeout,
            workers=request.workers,
            use_discovery=request.discovery,
            grab_banners=request.banners,
            reverse_dns=request.reverse_dns,
            arp=request.arp,
        ),
    )


def scan_request_from_payload(payload: dict[str, object]) -> ScanRequest:
    return ScanRequest(
        target=str(payload.get("target") or "local"),
        ports=str(payload.get("ports") or "top"),
        timeout=float(payload.get("timeout", 0.6)),
        workers=int(payload.get("workers", 128)),
        max_hosts=int(payload.get("max_hosts", DEFAULT_MAX_HOSTS)),
        max_ports=int(payload.get("max_ports", MAX_DEFAULT_PORTS)),
        allow_public=bool(payload.get("allow_public", False)),
        discovery=bool(payload.get("discovery", True)),
        banners=bool(payload.get("banners", True)),
        reverse_dns=bool(payload.get("reverse_dns", True)),
        arp=bool(payload.get("arp", True)),
    )
