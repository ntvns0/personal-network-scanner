from __future__ import annotations

import argparse
import errno
import sys
from pathlib import Path

from .interfaces import local_ipv4_networks
from .output import print_text_report, write_csv_report, write_json_report
from .ports import MAX_DEFAULT_PORTS
from .progress import ProgressReporter
from .scan_request import ScanRequest, resolve_scan_request
from .safety import (
    DEFAULT_MAX_HOSTS,
    describe_personal_networks,
    is_personal_network,
)
from .scanner import scan_hosts
from .web import add_web_parser, run_web_server


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "suggest-targets":
        return suggest_targets()
    if args.command == "scan":
        return run_scan(args)
    if args.command == "web":
        try:
            run_web_server(args.host, args.port)
            return 0
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                print(
                    f"error: {args.host}:{args.port} is already in use. "
                    f"Stop the existing server or choose another port, for example: "
                    f"python -m netscan web --port {args.port + 1}",
                    file=sys.stderr,
                )
                return 2
            raise

    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="personal-network-scanner",
        description="Scan owned or explicitly authorized personal networks for live hosts and open TCP services.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan a CIDR, IP address, or comma-separated target list.")
    scan.add_argument("target", help="Target CIDR/IP list, for example 192.168.1.0/24 or 10.0.0.5.")
    scan.add_argument(
        "--ports",
        default="top",
        help="Ports to scan: 'top', comma list, or ranges such as 22,80,443,8000-8010.",
    )
    scan.add_argument("--timeout", type=float, default=0.6, help="Socket timeout in seconds.")
    scan.add_argument("--workers", type=int, default=128, help="Maximum concurrent workers.")
    scan.add_argument(
        "--max-hosts",
        type=int,
        default=DEFAULT_MAX_HOSTS,
        help=f"Maximum target hosts accepted. Default: {DEFAULT_MAX_HOSTS}.",
    )
    scan.add_argument(
        "--max-ports",
        type=int,
        default=MAX_DEFAULT_PORTS,
        help=f"Maximum ports accepted. Default: {MAX_DEFAULT_PORTS}.",
    )
    scan.add_argument(
        "--allow-public",
        action="store_true",
        help="Allow non-local targets. Only use for addresses you own or have explicit authorization to scan.",
    )
    scan.add_argument(
        "--no-discovery",
        action="store_true",
        help="Scan every target host instead of first checking whether hosts appear live.",
    )
    scan.add_argument("--skip-banners", action="store_true", help="Skip banner and TLS metadata collection.")
    scan.add_argument("--no-reverse-dns", action="store_true", help="Skip reverse DNS lookup.")
    scan.add_argument("--no-arp", action="store_true", help="Skip ARP cache enrichment.")
    scan.add_argument("--no-progress", action="store_true", help="Disable live progress output.")
    scan.add_argument(
        "--progress-interval",
        type=float,
        default=0.2,
        help="Minimum seconds between progress redraws. Default: 0.2.",
    )
    scan.add_argument("--json", type=Path, help="Write JSON report to this path.")
    scan.add_argument("--csv", type=Path, help="Write CSV report to this path.")

    subparsers.add_parser("suggest-targets", help="Print local IPv4 CIDRs reported by the OS.")
    add_web_parser(subparsers)
    return parser


def run_scan(args: argparse.Namespace) -> int:
    try:
        plan = resolve_scan_request(
            ScanRequest(
                target=args.target,
                ports=args.ports,
                timeout=args.timeout,
                workers=args.workers,
                max_hosts=args.max_hosts,
                max_ports=args.max_ports,
                allow_public=args.allow_public,
                discovery=not args.no_discovery,
                banners=not args.skip_banners,
                reverse_dns=not args.no_reverse_dns,
                arp=not args.no_arp,
            )
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(f"personal ranges: {describe_personal_networks()}", file=sys.stderr)
        return 2

    if args.progress_interval <= 0:
        print("error: --progress-interval must be greater than zero.", file=sys.stderr)
        return 2

    if plan.local_networks and not plan.overlaps_local_network:
        local_text = ", ".join(str(network) for network in plan.local_networks)
        target_text = ", ".join(str(network) for network in plan.target_networks)
        print(
            f"warning: target {target_text} does not overlap local IPv4 network(s): {local_text}",
            file=sys.stderr,
        )
        print("hint: run 'python -m netscan scan <one-of-those-cidrs>'", file=sys.stderr)

    print(
        f"Scanning {len(plan.targets)} host(s), {len(plan.config.ports)} port(s). "
        "Only scan networks/devices you own or are authorized to assess.",
        file=sys.stderr,
    )
    progress = ProgressReporter(enabled=not args.no_progress, interval=args.progress_interval)
    try:
        results = scan_hosts(plan.targets, plan.config, progress)
    finally:
        progress.close()
    print_text_report(results)

    if args.json:
        write_json_report(args.json, results)
    if args.csv:
        write_csv_report(args.csv, results)
    return 0


def suggest_targets() -> int:
    suggestions = local_ipv4_networks()

    if not suggestions:
        print("No global IPv4 interface CIDRs found.")
        return 0

    default_safe = [network for network in suggestions if is_personal_network(network)]
    other = [network for network in suggestions if network not in default_safe]

    for suggestion in default_safe:
        print(suggestion)
    for suggestion in other:
        print(f"{suggestion} (use --allow-public only if authorized)")
    print()
    if default_safe:
        print(f"Example: python -m netscan scan {default_safe[0]}")
        print("Shortcut: python -m netscan scan local")
    else:
        print("No local networks are in the default personal range allowlist.")
    return 0
