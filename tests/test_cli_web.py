from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from netscan.cli import main
from netscan.web import read_static_asset


class CliTests(unittest.TestCase):
    def test_invalid_public_target_returns_error(self) -> None:
        self.assertEqual(main(["scan", "8.8.8.8", "--ports", "80"]), 2)

    def test_suggest_targets_prints_network_cidr_and_local_shortcut(self) -> None:
        ipaddress = __import__("ipaddress")
        networks = [
            ipaddress.ip_network("192.168.0.0/24"),
            ipaddress.ip_network("100.119.139.123/32"),
        ]
        stream = io.StringIO()
        with patch("netscan.cli.local_ipv4_networks", return_value=networks):
            with redirect_stdout(stream):
                self.assertEqual(main(["suggest-targets"]), 0)
        output = stream.getvalue()
        self.assertIn("192.168.0.0/24", output)
        self.assertIn("python -m netscan scan local", output)


class WebTests(unittest.TestCase):
    def test_static_index_contains_dashboard_targets(self) -> None:
        index = read_static_asset("index.html")
        self.assertIsNotNone(index)
        text = index.decode("utf-8") if index else ""
        self.assertIn("scan-form", text)
        self.assertIn("device-chart", text)
        self.assertIn("service-chart", text)
