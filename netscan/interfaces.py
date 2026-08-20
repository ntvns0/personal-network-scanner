from __future__ import annotations

import ipaddress
import subprocess


def local_ipv4_networks() -> list[ipaddress.IPv4Network]:
    """Return non-loopback IPv4 interface networks reported by the OS."""
    try:
        result = subprocess.run(
            ["ip", "-o", "-f", "inet", "addr", "show", "scope", "global"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError:
        return []

    networks: set[ipaddress.IPv4Network] = set()
    for cidr in parse_ip_addr_output(result.stdout):
        network = ipaddress.ip_network(cidr, strict=False)
        if network.version == 4:
            networks.add(network)
    return sorted(networks, key=lambda network: int(network.network_address))


def parse_ip_addr_output(output: str) -> list[str]:
    cidrs: list[str] = []
    for line in output.splitlines():
        parts = line.split()
        if "inet" in parts:
            index = parts.index("inet")
            if index + 1 < len(parts):
                cidrs.append(parts[index + 1])
    return cidrs


def overlapping_local_networks(
    target_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    local_networks: list[ipaddress.IPv4Network] | None = None,
) -> list[ipaddress.IPv4Network]:
    local = local_networks if local_networks is not None else local_ipv4_networks()
    overlaps: list[ipaddress.IPv4Network] = []
    for target in target_networks:
        if target.version != 4:
            continue
        for network in local:
            if target.overlaps(network):
                overlaps.append(network)
    return sorted(set(overlaps), key=lambda network: int(network.network_address))
