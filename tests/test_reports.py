from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from netscan.insights import profile_host, report_payload
from netscan.models import HostResult, PortResult
from netscan.output import print_text_report, write_csv_report, write_json_report


class OutputTests(unittest.TestCase):
    def test_text_report(self) -> None:
        host = HostResult(address="192.168.1.2", hostname="router.local")
        host.ports.append(PortResult(port=80, state="open", service="http", banner="HTTP/1.0 200 OK"))
        stream = io.StringIO()
        with redirect_stdout(stream):
            print_text_report([host])
        output = stream.getvalue()
        self.assertIn("192.168.1.2 (router.local)", output)
        self.assertIn("80/http: open", output)
        self.assertIn("Device:", output)

    def test_report_files(self) -> None:
        host = HostResult(address="192.168.1.2")
        host.ports.append(PortResult(port=22, state="open", service="ssh"))
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "report.json"
            csv_path = Path(directory) / "report.csv"
            write_json_report(json_path, [host])
            write_csv_report(csv_path, [host])
            self.assertIn('"address": "192.168.1.2"', json_path.read_text(encoding="utf-8"))
            csv_text = csv_path.read_text(encoding="utf-8")
            self.assertIn("192.168.1.2", csv_text)
            self.assertIn("device_type", csv_text)


class InsightTests(unittest.TestCase):
    def test_profile_host_identifies_printer(self) -> None:
        host = HostResult(address="192.168.1.40")
        host.ports.append(PortResult(port=9100, state="open"))
        profile = profile_host(host)
        self.assertEqual(profile.device_type, "printer")
        self.assertEqual(profile.risk_level, "low")

    def test_report_payload_includes_summary_and_profiles(self) -> None:
        host = HostResult(address="192.168.1.20")
        host.ports.append(PortResult(port=22, state="open", service="ssh"))
        payload = report_payload([host])
        self.assertEqual(payload["summary"]["host_count"], 1)
        self.assertEqual(payload["hosts"][0]["profile"]["device_type"], "computer/server")
