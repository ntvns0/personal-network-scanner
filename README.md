# Personal Network Scanner

A standard-library Python CLI for inventorying devices and open TCP services on networks you own or are explicitly authorized to assess.

This tool is intentionally scoped for personal and lab networks. It is not for scanning random public IP ranges, other people's networks, or systems where you do not have clear permission.

## Features

- Private-network safety checks by default.
- CIDR, single-IP, and comma-separated target input.
- TCP-based host discovery and port scanning.
- Optional reverse DNS lookup and ARP cache MAC enrichment.
- Conservative service names from the OS service database.
- Light banner and HTTPS certificate metadata collection.
- Text, JSON, and CSV output.
- Bounded host and port counts to avoid accidental broad scans.

## Quick Start

```bash
cd /path/to/personal_network_scanner
python -m netscan suggest-targets
python -m netscan scan local
```

Scan a smaller port set:

```bash
python -m netscan scan 192.168.0.0/24 --ports 22,80,443,8000-8010
```

Write reports:

```bash
python -m netscan scan local --json report.json --csv report.csv
```

## Safety Model

By default, the scanner only accepts personal/local ranges:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `169.254.0.0/16`
- `127.0.0.0/8`
- `fc00::/7`
- `fe80::/10`
- `::1/128`

Use `--allow-public` only for addresses you own or administer and have explicit authorization to scan.

See [docs/TOOLS_GUIDELINES.md](docs/TOOLS_GUIDELINES.md) before using the scanner.

## CLI

```bash
python -m netscan scan TARGET [options]
python -m netscan suggest-targets
python -m netscan web
```

`TARGET` can be a CIDR, single IP, comma-separated target list, or `local` to scan local personal IPv4 networks reported by the OS.

## Web UI

Run the local web interface:

```bash
python -m netscan web
```

Then open `http://127.0.0.1:8765/`.

The web UI provides scan setup, live progress, device-type estimates, service-group charts, host filtering, risk hints, and JSON report export. It uses the same scanning engine and authorization guardrails as the CLI.

Common options:

- `--ports`: Port list or ranges, such as `top`, `22,80,443`, or `1-1024`.
- `--workers`: Concurrent socket workers. Defaults to `128`.
- `--timeout`: Socket timeout in seconds. Defaults to `0.6`.
- `--no-progress`: Disable the live progress display.
- `--progress-interval`: Minimum seconds between progress updates.
- `--no-discovery`: Scan every target host instead of first finding likely live hosts.
- `--skip-banners`: Skip banner/certificate collection.
- `--no-arp`: Skip ARP cache enrichment.
- `--json PATH`: Write JSON output.
- `--csv PATH`: Write CSV output.

## Development

```bash
cd /path/to/personal_network_scanner
python -m unittest
```

## License

[MIT](LICENSE).
