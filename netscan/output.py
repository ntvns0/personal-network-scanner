from __future__ import annotations

import csv
import json
from pathlib import Path

from .insights import profile_host
from .models import HostResult


def print_text_report(results: list[HostResult]) -> None:
    if not results:
        print("No live hosts found.")
        return

    for host in results:
        identity = host.address
        if host.hostname:
            identity += f" ({host.hostname})"
        print(identity)
        if host.mac:
            vendor = f" [{host.vendor}]" if host.vendor else ""
            print(f"  MAC: {host.mac}{vendor}")
        profile = profile_host(host)
        print(
            f"  Device: {profile.device_type} "
            f"(confidence {profile.confidence:.0%}, risk {profile.risk_level})"
        )
        if not host.ports:
            print("  No open TCP ports found in the requested set.")
        for port in host.ports:
            service = f"/{port.service}" if port.service else ""
            print(f"  {port.port}{service}: {port.state}")
            if port.banner:
                print(f"    banner: {port.banner}")
            if port.tls_subject:
                print(f"    tls subject: {port.tls_subject}")
            if port.tls_issuer:
                print(f"    tls issuer: {port.tls_issuer}")
        for note in host.notes:
            print(f"  note: {note}")


def write_json_report(path: Path, results: list[HostResult]) -> None:
    payload = [host.to_dict() for host in results]
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv_report(path: Path, results: list[HostResult]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "address",
                "hostname",
                "mac",
                "vendor",
                "device_type",
                "risk_level",
                "risk_score",
                "port",
                "state",
                "service",
                "banner",
                "tls_subject",
                "tls_issuer",
            ],
        )
        writer.writeheader()
        for host in results:
            profile = profile_host(host)
            if not host.ports:
                writer.writerow(
                    {
                        "address": host.address,
                        "hostname": host.hostname,
                        "mac": host.mac,
                        "vendor": host.vendor,
                        "device_type": profile.device_type,
                        "risk_level": profile.risk_level,
                        "risk_score": profile.risk_score,
                        "port": "",
                        "state": "no-open-ports",
                        "service": "",
                        "banner": "",
                        "tls_subject": "",
                        "tls_issuer": "",
                    }
                )
            for port in host.ports:
                writer.writerow(
                    {
                        "address": host.address,
                        "hostname": host.hostname,
                        "mac": host.mac,
                        "vendor": host.vendor,
                        "device_type": profile.device_type,
                        "risk_level": profile.risk_level,
                        "risk_score": profile.risk_score,
                        "port": port.port,
                        "state": port.state,
                        "service": port.service,
                        "banner": port.banner,
                        "tls_subject": port.tls_subject,
                        "tls_issuer": port.tls_issuer,
                    }
                )
