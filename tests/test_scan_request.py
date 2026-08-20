from __future__ import annotations

import unittest
from unittest.mock import patch

from netscan.scan_request import ScanRequest, resolve_scan_request, scan_request_from_payload


class ScanRequestTests(unittest.TestCase):
    def test_resolve_scan_request_uses_local_networks(self) -> None:
        ipaddress = __import__("ipaddress")
        with patch(
            "netscan.scan_request.local_ipv4_networks",
            return_value=[ipaddress.ip_network("192.168.0.0/30")],
        ):
            plan = resolve_scan_request(
                ScanRequest(target="local", ports="22,80", timeout=0.2, workers=4, discovery=False)
            )
        self.assertEqual([str(target) for target in plan.targets], ["192.168.0.1", "192.168.0.2"])
        self.assertEqual(plan.config.ports, (22, 80))
        self.assertFalse(plan.config.use_discovery)

    def test_payload_conversion(self) -> None:
        request = scan_request_from_payload(
            {"target": "127.0.0.1", "ports": "1", "timeout": 0.1, "workers": 4}
        )
        self.assertEqual(request.target, "127.0.0.1")
        self.assertEqual(request.ports, "1")
        self.assertEqual(request.timeout, 0.1)
        self.assertEqual(request.workers, 4)
