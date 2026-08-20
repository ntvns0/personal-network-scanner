from __future__ import annotations

from pathlib import Path
import subprocess


def read_arp_cache(path: Path = Path("/proc/net/arp")) -> dict[str, str]:
    """Read Linux ARP cache as address -> MAC. Returns an empty map elsewhere."""
    if not path.exists():
        return {}

    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4:
            address, _hw_type, _flags, mac = parts[:4]
            if mac != "00:00:00:00:00:00":
                entries[address] = mac.lower()
    return entries


def read_neighbor_cache() -> dict[str, str | None]:
    """Read IPv4 neighbors through iproute2, falling back to /proc/net/arp."""
    try:
        result = subprocess.run(
            ["ip", "-4", "neigh", "show"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError:
        return {address: mac for address, mac in read_arp_cache().items()}

    entries: dict[str, str | None] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        address = parts[0]
        mac = None
        if "lladdr" in parts:
            index = parts.index("lladdr")
            if index + 1 < len(parts):
                mac = parts[index + 1].lower()
        state = parts[-1]
        if state not in {"FAILED", "INCOMPLETE"}:
            entries[address] = mac

    if entries:
        return entries
    return {address: mac for address, mac in read_arp_cache().items()}


def vendor_from_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    prefix = mac.upper().replace("-", ":")[:8]
    return _KNOWN_OUIS.get(prefix)


_KNOWN_OUIS = {
    "00:05:02": "Apple",
    "00:0A:27": "Apple",
    "00:0C:29": "VMware",
    "00:16:3E": "Xen",
    "00:17:F2": "Apple",
    "00:1B:63": "Apple",
    "00:1C:42": "Parallels",
    "00:1D:4F": "Apple",
    "00:1E:52": "Apple",
    "00:21:6A": "Intel",
    "00:23:12": "Apple",
    "00:25:00": "Apple",
    "00:26:BB": "Apple",
    "00:50:56": "VMware",
    "00:90:27": "Intel",
    "00:E0:4C": "Realtek",
    "08:00:27": "VirtualBox",
    "10:93:E9": "Apple",
    "14:7D:DA": "Apple",
    "18:65:90": "Apple",
    "1C:1A:C0": "Apple",
    "28:CF:E9": "Apple",
    "3C:07:54": "Apple",
    "3C:22:FB": "Apple",
    "40:B0:34": "Hewlett Packard",
    "44:65:0D": "Amazon",
    "50:32:37": "Apple",
    "58:55:CA": "Apple",
    "5C:F9:38": "Apple",
    "60:33:4B": "Apple",
    "68:5B:35": "Apple",
    "70:56:81": "Apple",
    "74:E2:F5": "Apple",
    "7C:D1:C3": "Apple",
    "84:38:35": "Apple",
    "88:66:A5": "Apple",
    "8C:85:90": "Apple",
    "98:01:A7": "Apple",
    "A4:5E:60": "Apple",
    "B8:27:EB": "Raspberry Pi",
    "BC:92:6B": "Apple",
    "C8:2A:14": "Apple",
    "CC:20:E8": "Apple",
    "D8:30:62": "Apple",
    "DC:A6:32": "Raspberry Pi",
    "E0:5F:45": "Apple",
    "F0:18:98": "Apple",
    "F4:5C:89": "Apple",
    "FC:FC:48": "Apple",
}
