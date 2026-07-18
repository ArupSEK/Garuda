from __future__ import annotations

import json
import mimetypes
import argparse
import socket
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from garuda.scanner import ScopeError, scan_target


ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"


class GarudaHandler(SimpleHTTPRequestHandler):
    server_version = "GarudaHTTP/0.1"

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/health":
            self.send_json({"ok": True, "service": "garuda"})
            return
        if path == "/api/scan":
            self.handle_scan_query()
            return
        self.serve_static(path)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/scan":
            self.handle_scan_json()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def handle_scan_query(self) -> None:
        query = parse_qs(urlsplit(self.path).query)
        payload = {
            "target": query.get("target", [""])[0],
            "ports": query.get("ports", [""])[0],
            "authorized": query.get("authorized", ["false"])[0].lower() == "true",
        }
        self.run_scan(payload)

    def handle_scan_json(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON payload."}, HTTPStatus.BAD_REQUEST)
            return
        self.run_scan(payload)

    def run_scan(self, payload: dict) -> None:
        if not payload.get("authorized"):
            self.send_json(
                {"error": "Explicit authorization is required before scanning a target."},
                HTTPStatus.FORBIDDEN,
            )
            return

        try:
            result = scan_target(payload.get("target", ""), payload.get("ports") or None)
        except ScopeError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        except Exception as exc:  # Keep API errors JSON-shaped for the UI.
            self.send_json({"error": f"Scan failed: {exc.__class__.__name__}"}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        self.send_json(result)

    def serve_static(self, path: str) -> None:
        requested = "index.html" if path in {"", "/"} else path.lstrip("/")
        file_path = (STATIC_DIR / requested).resolve()
        if not str(file_path).startswith(str(STATIC_DIR.resolve())) or not file_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        body = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def available_port(preferred_port: int) -> int:
    for port in range(preferred_port, preferred_port + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("No local port available.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Garuda web application.")
    parser.add_argument("--port", type=int, default=8087)
    args = parser.parse_args()
    port = available_port(args.port)
    server = ThreadingHTTPServer(("127.0.0.1", port), GarudaHandler)
    print(f"Garuda running at http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
