from __future__ import annotations

import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Protocol

from .arp import read_neighbor_cache, vendor_from_mac
from .discovery import is_host_live, reverse_dns
from .models import HostResult, PortResult, ScanConfig

TLS_PORTS = {443, 465, 563, 636, 853, 989, 990, 993, 995, 2376, 5986, 8443, 8883}
HTTP_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888, 9000}


class Progress(Protocol):
    def start_phase(self, phase: str, total: int, **details: int | str) -> None: ...
    def advance(self, amount: int = 1, **details: int | str) -> None: ...
    def finish_phase(self, **details: int | str) -> None: ...


def scan_hosts(
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    config: ScanConfig,
    progress: Progress | None = None,
) -> list[HostResult]:
    live_addresses = addresses

    if config.use_discovery:
        live_addresses = discover_hosts(addresses, config, progress)

    arp_cache = read_neighbor_cache() if config.arp else {}
    results: list[HostResult] = []
    total_checks = len(live_addresses) * len(config.ports)
    if progress:
        progress.start_phase("scanning ports", total_checks, hosts=len(live_addresses), open=0)
    open_ports = 0
    with ThreadPoolExecutor(max_workers=config.workers) as executor:
        futures = {
            executor.submit(scan_host, address, config, arp_cache, progress): address
            for address in live_addresses
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            open_ports += len(result.ports)
    if progress:
        progress.finish_phase(hosts=len(live_addresses), open=open_ports, current="done")

    return sorted(results, key=lambda host: _address_sort_key(host.address))


def discover_hosts(
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    config: ScanConfig,
    progress: Progress | None = None,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    live: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    if progress:
        progress.start_phase("discovering hosts", len(addresses), live=0)
    with ThreadPoolExecutor(max_workers=config.workers) as executor:
        futures = {executor.submit(is_host_live, address, config.timeout): address for address in addresses}
        for future in as_completed(futures):
            address = futures[future]
            if future.result():
                live.add(address)
            if progress:
                progress.advance(live=len(live))

    if config.arp:
        target_set = set(addresses)
        for address_text in read_neighbor_cache():
            try:
                address = ipaddress.ip_address(address_text)
            except ValueError:
                continue
            if address in target_set:
                live.add(address)
    if progress:
        progress.finish_phase(live=len(live))
    return sorted(live, key=lambda address: (address.version, int(address)))


def scan_host(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    config: ScanConfig,
    arp_cache: dict[str, str | None] | None = None,
    progress: Progress | None = None,
) -> HostResult:
    host = HostResult(address=str(address), is_live=True)
    if config.reverse_dns:
        host.hostname = reverse_dns(address, config.timeout)

    if arp_cache:
        host.mac = arp_cache.get(str(address))
        host.vendor = vendor_from_mac(host.mac)

    for port in config.ports:
        result = scan_port(address, port, config.timeout, config.grab_banners)
        if result.state == "open":
            host.ports.append(result)
        if progress:
            progress.advance(current=f"{address}:{port}")
    return host


def scan_port(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    port: int,
    timeout: float,
    grab_banner: bool,
) -> PortResult:
    try:
        with socket.create_connection((str(address), port), timeout=timeout) as sock:
            result = PortResult(port=port, state="open", service=service_name(port))
            if grab_banner:
                enrich_banner(result, sock, str(address), timeout)
            return result
    except OSError:
        return PortResult(port=port, state="closed", service=service_name(port))


def enrich_banner(result: PortResult, sock: socket.socket, host: str, timeout: float) -> None:
    sock.settimeout(timeout)
    if result.port in TLS_PORTS:
        _enrich_tls(result, sock, host, timeout)
        return

    try:
        if result.port in HTTP_PORTS:
            request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: personal-network-scanner/0.1\r\n\r\n"
            sock.sendall(request.encode("ascii", errors="ignore"))
        data = sock.recv(256)
    except OSError:
        return

    if data:
        result.banner = _clean_banner(data)


def service_name(port: int) -> str | None:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return None


def _enrich_tls(result: PortResult, sock: socket.socket, host: str, timeout: float) -> None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            tls_sock.settimeout(timeout)
            cert = tls_sock.getpeercert()
            result.banner = f"TLS {tls_sock.version()}"
            if cert:
                result.tls_subject = _format_name(cert.get("subject", ()))
                result.tls_issuer = _format_name(cert.get("issuer", ()))
    except OSError:
        return


def _format_name(name_parts: tuple[tuple[tuple[str, str], ...], ...]) -> str | None:
    values: list[str] = []
    for group in name_parts:
        for key, value in group:
            if key in {"commonName", "organizationName"}:
                values.append(value)
    return ", ".join(values) if values else None


def _clean_banner(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    return " ".join(text.replace("\r", " ").replace("\n", " ").split())[:240]


def _address_sort_key(value: str) -> tuple[int, int]:
    address = ipaddress.ip_address(value)
    return address.version, int(address)
