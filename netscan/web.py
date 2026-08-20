from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any
from urllib.parse import urlparse

from .interfaces import local_ipv4_networks
from .safety import describe_personal_networks, is_personal_network
from .web_jobs import ScanStore

STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".png": "image/png",
}


def make_handler(store: ScanStore) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "PersonalNetworkScanner/0.1"

        def do_GET(self) -> None:
            self._route(send_body=True)

        def do_HEAD(self) -> None:
            self._route(send_body=False)

        def _route(self, *, send_body: bool) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._send_static("index.html", send_body=send_body)
                return
            if parsed.path.startswith("/static/"):
                self._send_static(parsed.path.removeprefix("/static/"), send_body=send_body)
                return
            if parsed.path == "/api/suggestions":
                networks = local_ipv4_networks()
                self._send_json(
                    {
                        "networks": [
                            {"cidr": str(network), "allowed": is_personal_network(network)}
                            for network in networks
                        ],
                        "personal_ranges": describe_personal_networks(),
                    },
                    send_body=send_body,
                )
                return
            if parsed.path == "/api/scans":
                self._send_json({"scans": store.list()}, send_body=send_body)
                return
            if parsed.path.startswith("/api/scans/"):
                job_id = parsed.path.rsplit("/", 1)[-1]
                job = store.get(job_id)
                if not job:
                    self._send_json({"error": "scan not found"}, HTTPStatus.NOT_FOUND, send_body=send_body)
                    return
                self._send_json(job.to_dict(), send_body=send_body)
                return
            self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND, send_body=send_body)

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/api/scans":
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return
            try:
                payload = self._read_json()
                job = store.create(payload)
            except ValueError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            self._send_json({"id": job.id, "status": job.status}, HTTPStatus.ACCEPTED)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _read_json(self) -> dict[str, object]:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 64_000:
                raise ValueError("request body is too large.")
            data = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(data.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError("invalid JSON request body.") from exc
            if not isinstance(payload, dict):
                raise ValueError("JSON request body must be an object.")
            return payload

        def _send_json(
            self,
            payload: dict[str, object],
            status: HTTPStatus = HTTPStatus.OK,
            *,
            send_body: bool = True,
        ) -> None:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if send_body:
                self.wfile.write(body)

        def _send_static(self, name: str, *, send_body: bool = True) -> None:
            if "/" in name or "\\" in name or name.startswith("."):
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND, send_body=send_body)
                return
            content = read_static_asset(name)
            if content is None:
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND, send_body=send_body)
                return
            suffix = "." + name.rsplit(".", 1)[-1] if "." in name else ""
            content_type = STATIC_TYPES.get(suffix, "application/octet-stream")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if send_body:
                self.wfile.write(content)

    return Handler


def read_static_asset(name: str) -> bytes | None:
    try:
        return resources.files("netscan.static").joinpath(name).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError):
        return None


def run_web_server(host: str = "127.0.0.1", port: int = 8765) -> None:
    store = ScanStore()
    server = ThreadingHTTPServer((host, port), make_handler(store))
    print(f"Personal Network Scanner web UI: http://{host}:{server.server_port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def add_web_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    web = subparsers.add_parser("web", help="Run the local web UI.")
    web.add_argument("--host", default="127.0.0.1", help="Bind host. Default: 127.0.0.1.")
    web.add_argument("--port", type=int, default=8765, help="Bind port. Default: 8765.")
