from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess

from .ports import DISCOVERY_PORTS


def tcp_probe(address: ipaddress._BaseAddress, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((str(address), port), timeout=timeout):
            return True
    except OSError:
        return False


def is_host_live(address: ipaddress._BaseAddress, timeout: float) -> bool:
    if ping(address, timeout):
        return True
    return any(tcp_probe(address, port, timeout) for port in DISCOVERY_PORTS)


def ping(address: ipaddress._BaseAddress, timeout: float) -> bool:
    command = _ping_command(str(address), timeout)
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(timeout + 0.4, 1.0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def reverse_dns(address: ipaddress._BaseAddress, timeout: float) -> str | None:
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(str(address))[0]
    except (OSError, socket.herror):
        return None
    finally:
        socket.setdefaulttimeout(previous_timeout)


def _ping_command(address: str, timeout: float) -> list[str]:
    seconds = str(max(1, int(round(timeout))))
    if platform.system().lower() == "windows":
        return ["ping", "-n", "1", "-w", str(int(float(seconds) * 1000)), address]
    return ["ping", "-c", "1", "-W", seconds, address]
