from __future__ import annotations

import unittest

from netscan.interfaces import overlapping_local_networks, parse_ip_addr_output
from netscan.ports import COMMON_PORTS, parse_ports
from netscan.safety import parse_targets


class PortParsingTests(unittest.TestCase):
    def test_top_ports(self) -> None:
        self.assertEqual(parse_ports("top"), COMMON_PORTS)

    def test_list_and_ranges(self) -> None:
        self.assertEqual(parse_ports("22,80,8000-8002"), (22, 80, 8000, 8001, 8002))

    def test_invalid_port(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_max_ports(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("1-5", max_ports=4)


class SafetyTests(unittest.TestCase):
    def test_private_targets_allowed(self) -> None:
        hosts = parse_targets("192.168.1.0/30")
        self.assertEqual([str(host) for host in hosts], ["192.168.1.1", "192.168.1.2"])

    def test_public_targets_blocked_by_default(self) -> None:
        with self.assertRaises(ValueError):
            parse_targets("8.8.8.8")

    def test_public_targets_can_be_explicitly_allowed(self) -> None:
        hosts = parse_targets("8.8.8.8", allow_public=True)
        self.assertEqual([str(host) for host in hosts], ["8.8.8.8"])

    def test_max_hosts(self) -> None:
        with self.assertRaises(ValueError):
            parse_targets("192.168.1.0/24", max_hosts=10)


class InterfaceTests(unittest.TestCase):
    def test_parse_ip_addr_output(self) -> None:
        output = (
            "2: wlan0    inet 192.168.0.173/24 brd 192.168.0.255 scope global dynamic wlan0\n"
            "3: tailscale0    inet 100.119.139.123/32 scope global tailscale0\n"
        )
        self.assertEqual(
            parse_ip_addr_output(output), ["192.168.0.173/24", "100.119.139.123/32"]
        )

    def test_overlapping_local_networks(self) -> None:
        ipaddress = __import__("ipaddress")
        target = [ipaddress.ip_network("192.168.1.0/24")]
        local = [ipaddress.ip_network("192.168.0.0/24")]
        self.assertEqual(overlapping_local_networks(target, local), [])
