from __future__ import annotations

import argparse
import json
import mimetypes
import socket
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from garuda.orchestrator import Orchestrator
from garuda.scope import ScopeError

ROOT = Path(__file__).resolve().parent
STATIC_DIR = (ROOT / "static").resolve()
MAX_REQUEST_BYTES = 64 * 1024
ORCHESTRATOR = Orchestrator()


class GarudaHandler(SimpleHTTPRequestHandler):
    server_version = "GarudaHTTP/1.0"

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/health":
            self.send_json({"ok": True, "service": "garuda", "version": "1.0.0"})
            return
        if path == "/api/profiles":
            self.send_json({"profiles": ORCHESTRATOR.profiles()})
            return
        if path == "/api/capabilities":
            self.send_json({"capabilities": ORCHESTRATOR.capabilities()})
            return
        if path.startswith("/api/"):
            self.send_json({"error": "API endpoint not found."}, HTTPStatus.NOT_FOUND)
            return
        self.serve_static(path)

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path != "/api/scan":
            self.send_json({"error": "API endpoint not found."}, HTTPStatus.NOT_FOUND)
            return
        if not self.valid_origin():
            self.send_json({"error": "Cross-origin requests are not permitted."}, HTTPStatus.FORBIDDEN)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json({"error": "Invalid Content-Length."}, HTTPStatus.BAD_REQUEST)
            return
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self.send_json({"error": f"Request body must be between 1 and {MAX_REQUEST_BYTES} bytes."}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return

        try:
            payload = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json({"error": "Invalid JSON payload."}, HTTPStatus.BAD_REQUEST)
            return
        if not isinstance(payload, dict):
            self.send_json({"error": "JSON payload must be an object."}, HTTPStatus.BAD_REQUEST)
            return

        try:
            result = ORCHESTRATOR.scan(
                target=str(payload.get("target", "")),
                raw_ports=payload.get("ports") or None,
                profile=str(payload.get("profile") or "external-safe"),
                authorized=payload.get("authorized") is True,
            )
        except ScopeError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        self.send_json(result)

    def valid_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlsplit(origin)
        return parsed.scheme in {"http", "https"} and parsed.hostname in {"127.0.0.1", "localhost", "::1"}

    def serve_static(self, path: str) -> None:
        requested = "index.html" if path in {"", "/"} else path.lstrip("/")
        file_path = (STATIC_DIR / requested).resolve()
        try:
            in_static = file_path.is_relative_to(STATIC_DIR)
        except AttributeError:
            in_static = STATIC_DIR == file_path or STATIC_DIR in file_path.parents
        if not in_static or not file_path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        body = file_path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mimetypes.guess_type(file_path.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}")


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
    parser = argparse.ArgumentParser(description="Run the Garuda security assessment platform.")
    parser.add_argument("--port", type=int, default=8087)
    args = parser.parse_args()
    port = available_port(args.port)
    server = ThreadingHTTPServer(("127.0.0.1", port), GarudaHandler)
    print(f"Garuda running at http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
