from __future__ import annotations

import socket
import tempfile
import threading
import unittest
from pathlib import Path

from netscan.arp import read_arp_cache, vendor_from_mac
from netscan.scanner import scan_port


class ArpTests(unittest.TestCase):
    def test_read_arp_cache(self) -> None:
        content = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.10     0x1         0x2         b8:27:eb:00:11:22     *        eth0\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "arp"
            path.write_text(content, encoding="utf-8")
            self.assertEqual(read_arp_cache(path), {"192.168.1.10": "b8:27:eb:00:11:22"})

    def test_vendor_lookup(self) -> None:
        self.assertEqual(vendor_from_mac("b8:27:eb:00:11:22"), "Raspberry Pi")


class ScannerTests(unittest.TestCase):
    def test_scan_open_loopback_port(self) -> None:
        ready = threading.Event()

        def server(listener: socket.socket) -> None:
            ready.set()
            conn, _addr = listener.accept()
            with conn:
                conn.sendall(b"hello\r\n")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            thread = threading.Thread(target=server, args=(listener,), daemon=True)
            thread.start()
            ready.wait(timeout=1)

            result = scan_port(__import__("ipaddress").ip_address("127.0.0.1"), port, 1.0, True)

        self.assertEqual(result.state, "open")
        self.assertEqual(result.banner, "hello")
