from __future__ import annotations

COMMON_PORTS = (
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    80,
    110,
    111,
    123,
    135,
    137,
    138,
    139,
    143,
    161,
    162,
    389,
    443,
    445,
    465,
    500,
    515,
    548,
    554,
    587,
    631,
    636,
    993,
    995,
    1433,
    1521,
    1723,
    1883,
    2049,
    2375,
    2376,
    3306,
    3389,
    5000,
    5432,
    5900,
    5985,
    5986,
    6379,
    8000,
    8080,
    8443,
    8883,
    9000,
    9100,
)

DISCOVERY_PORTS = (22, 53, 80, 139, 443, 445, 3389, 5000, 8000, 8080, 9100)
MAX_DEFAULT_PORTS = 1024


def parse_ports(value: str, max_ports: int = MAX_DEFAULT_PORTS) -> tuple[int, ...]:
    """Parse a comma-separated port expression into sorted unique port numbers."""
    normalized = value.strip().lower()
    if normalized in {"", "top", "common"}:
        return COMMON_PORTS

    ports: set[int] = set()
    for part in normalized.split(","):
        item = part.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start = _parse_port(start_text)
            end = _parse_port(end_text)
            if start > end:
                raise ValueError(f"Invalid port range '{item}': start is greater than end.")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_port(item))

        if len(ports) > max_ports:
            raise ValueError(
                f"Too many ports requested ({len(ports)}). Keep scans focused or raise the limit."
            )

    if not ports:
        raise ValueError("No ports were provided.")
    return tuple(sorted(ports))


def _parse_port(value: str) -> int:
    try:
        port = int(value, 10)
    except ValueError as exc:
        raise ValueError(f"Invalid port '{value}'.") from exc
    if port < 1 or port > 65535:
        raise ValueError(f"Port {port} is outside the valid range 1-65535.")
    return port
