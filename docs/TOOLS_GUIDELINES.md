# Tool Usage Guidelines

This scanner is for personal networks, lab environments, and devices where you have explicit permission to scan.

## Allowed Use

- Inventory devices on networks you own or administer.
- Check your home router, personal computers, lab machines, and IoT devices.
- Validate that expected services are exposed on your own systems.
- Create reports for maintenance, hardening, or troubleshooting.

## Not Allowed Use

- Do not scan random public IP ranges.
- Do not scan neighbors, workplaces, schools, hotels, coffee shops, or ISP networks without written authorization.
- Do not use the tool to probe systems for exploitation.
- Do not try to bypass firewalls, hide scan activity, evade monitoring, or overwhelm devices.

## Operational Guardrails

- Start with the smallest practical target range.
- Prefer local/private ranges unless you own the public address space.
- Keep concurrency and port ranges reasonable on fragile networks.
- Stop scanning if a device or network becomes unstable.
- Treat discovered hostnames, banners, and MAC addresses as private information.

The default CLI blocks non-personal ranges unless `--allow-public` is supplied. That flag is only for networks and hosts you own or have explicit permission to assess.
