from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from .models import HostResult, PortResult


@dataclass(frozen=True, slots=True)
class DeviceProfile:
    device_type: str
    confidence: float
    signals: tuple[str, ...]
    risk_score: int
    risk_level: str
    recommendations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_type": self.device_type,
            "confidence": self.confidence,
            "signals": list(self.signals),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "recommendations": list(self.recommendations),
        }


SERVICE_GROUPS = {
    "web": {80, 443, 8000, 8080, 8081, 8443, 8888, 9000},
    "remote_access": {22, 23, 3389, 5900, 5985, 5986},
    "file_sharing": {111, 139, 445, 548, 2049},
    "printer": {515, 631, 9100},
    "database": {1433, 1521, 3306, 5432, 6379},
    "iot_messaging": {1883, 8883},
    "directory": {389, 636},
    "dns": {53},
}

HIGH_ATTENTION_PORTS = {
    23: "Telnet is unencrypted and should usually be disabled.",
    3389: "Remote Desktop is exposed on this network.",
    5900: "VNC is exposed on this network.",
    5985: "WinRM over HTTP is exposed on this network.",
    6379: "Redis should not be reachable unless intentionally managed.",
    3306: "MySQL should only be reachable by trusted clients.",
    5432: "PostgreSQL should only be reachable by trusted clients.",
    1433: "SQL Server should only be reachable by trusted clients.",
}


def profile_host(host: HostResult) -> DeviceProfile:
    ports = {port.port for port in host.ports}
    text = " ".join(
        value
        for value in [
            host.hostname or "",
            host.vendor or "",
            " ".join(port.banner or "" for port in host.ports),
        ]
        if value
    ).lower()

    scores: Counter[str] = Counter()
    signals: list[str] = []

    def add(device_type: str, amount: int, signal: str) -> None:
        scores[device_type] += amount
        signals.append(signal)

    if ports & SERVICE_GROUPS["printer"]:
        add("printer", 5, "printing service")
    if {139, 445, 548, 2049} & ports:
        add("storage", 4, "file sharing service")
    if {53, 67, 68} & ports or any(word in text for word in ("router", "gateway", "openwrt")):
        add("router", 4, "network infrastructure signal")
    if ports & SERVICE_GROUPS["web"]:
        add("web device", 2, "web service")
    if ports & SERVICE_GROUPS["remote_access"]:
        add("computer/server", 3, "remote access service")
    if ports & SERVICE_GROUPS["database"]:
        add("server", 4, "database service")
    if ports & SERVICE_GROUPS["iot_messaging"] or any(
        word in text for word in ("esp", "shelly", "tasmota", "mqtt", "iot")
    ):
        add("iot device", 4, "iot or messaging signal")
    if "raspberry pi" in text:
        add("single-board computer", 5, "Raspberry Pi vendor")
    if any(word in text for word in ("apple", "iphone", "ipad", "macbook", "imac")):
        add("apple device", 3, "Apple hostname/vendor")

    if not scores:
        device_type = "unknown device"
        confidence = 0.15
        signals.append("host responded but exposed services were limited")
    else:
        device_type, score = scores.most_common(1)[0]
        confidence = min(0.95, 0.25 + (score / 10))

    risk_score, recommendations = risk_for_ports(host.ports)
    return DeviceProfile(
        device_type=device_type,
        confidence=round(confidence, 2),
        signals=tuple(dict.fromkeys(signals)),
        risk_score=risk_score,
        risk_level=risk_level(risk_score),
        recommendations=tuple(recommendations),
    )


def risk_for_ports(ports: list[PortResult]) -> tuple[int, list[str]]:
    score = 0
    recommendations: list[str] = []
    open_ports = {port.port for port in ports}
    for port in ports:
        if port.port in HIGH_ATTENTION_PORTS:
            score += 25
            recommendations.append(f"{port.port}: {HIGH_ATTENTION_PORTS[port.port]}")
        elif port.port in SERVICE_GROUPS["remote_access"]:
            score += 14
        elif port.port in SERVICE_GROUPS["database"]:
            score += 18
        elif port.port in SERVICE_GROUPS["file_sharing"]:
            score += 8
        elif port.port in SERVICE_GROUPS["web"]:
            score += 5
        else:
            score += 2

    if 80 in open_ports and 443 not in open_ports:
        score += 8
        recommendations.append("HTTP is available without HTTPS in the scanned port set.")
    if len(open_ports) > 8:
        score += 10
        recommendations.append("This host exposes many services; review which ones are required.")
    if not recommendations and open_ports:
        recommendations.append("No high-attention services found in this scan profile.")
    if not open_ports:
        recommendations.append("No open TCP services found in the requested port set.")
    return min(score, 100), recommendations


def risk_level(score: int) -> str:
    if score >= 65:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def summarize_results(results: list[HostResult]) -> dict[str, Any]:
    profiles = [profile_host(host) for host in results]
    device_counts = Counter(profile.device_type for profile in profiles)
    service_counts: Counter[str] = Counter()
    port_counts: Counter[int] = Counter()
    risk_counts = Counter(profile.risk_level for profile in profiles)

    for host in results:
        for port in host.ports:
            port_counts[port.port] += 1
            for group, ports in SERVICE_GROUPS.items():
                if port.port in ports:
                    service_counts[group] += 1

    return {
        "host_count": len(results),
        "open_port_count": sum(len(host.ports) for host in results),
        "device_counts": dict(device_counts),
        "service_counts": dict(service_counts),
        "risk_counts": dict(risk_counts),
        "top_ports": [
            {"port": port, "count": count} for port, count in port_counts.most_common(10)
        ],
    }


def report_payload(results: list[HostResult]) -> dict[str, Any]:
    return {
        "summary": summarize_results(results),
        "hosts": [
            {
                **host.to_dict(),
                "profile": profile_host(host).to_dict(),
            }
            for host in results
        ],
    }
