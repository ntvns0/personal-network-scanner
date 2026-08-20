from __future__ import annotations

import ipaddress
from collections.abc import Iterable

PERSONAL_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "127.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

DEFAULT_MAX_HOSTS = 4096


def parse_targets(
    value: str, *, allow_public: bool = False, max_hosts: int = DEFAULT_MAX_HOSTS
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    hosts = expand_target_networks(
        parse_target_networks(value, allow_public=allow_public), max_hosts=max_hosts
    )
    if not hosts:
        raise ValueError("No target hosts were provided.")
    return hosts


def parse_target_networks(
    value: str, *, allow_public: bool = False
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    seen: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    for raw_part in value.split(","):
        part = raw_part.strip()
        if not part:
            continue
        network = _parse_network_or_host(part)
        if not allow_public and not is_personal_network(network):
            raise ValueError(
                f"Target {network} is outside the default personal-network scope. "
                "Only scan networks/devices you own or have explicit permission to assess. "
                "Use --allow-public only for authorized public addresses."
            )
        if network not in seen:
            networks.append(network)
            seen.add(network)
    if not networks:
        raise ValueError("No target networks were provided.")
    return networks


def expand_target_networks(
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network], *, max_hosts: int
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    hosts: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for network in networks:
        for host in network.hosts():
            hosts.add(host)
            if len(hosts) > max_hosts:
                raise ValueError(
                    f"Too many target hosts ({len(hosts)}). Narrow the CIDR or raise --max-hosts."
                )
    return sorted(hosts, key=lambda address: (address.version, int(address)))


def is_personal_network(network: ipaddress._BaseNetwork) -> bool:
    return all(is_personal_address(address) for address in _network_edges(network))


def is_personal_address(address: ipaddress._BaseAddress) -> bool:
    return any(address in network for network in PERSONAL_NETWORKS)


def describe_personal_networks() -> str:
    return ", ".join(str(network) for network in PERSONAL_NETWORKS)


def _parse_network_or_host(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as network_error:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as address_error:
            raise ValueError(f"Invalid target '{value}'.") from address_error
        return ipaddress.ip_network(address.exploded + "/32" if address.version == 4 else address.exploded + "/128")


def _network_edges(
    network: ipaddress._BaseNetwork,
) -> Iterable[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    yield network.network_address
    yield network.broadcast_address
