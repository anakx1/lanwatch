"""Local web dashboard and JSON API.

The server deliberately has no third-party dependencies: it is
``ThreadingHTTPServer`` plus a small router and an SSE stream.  Mutating
requests must carry the ``X-Lanwatch: 1`` header, which (together with the
absence of CORS headers) keeps other web pages from driving the scanner.
"""

from __future__ import annotations

import json
import mimetypes
import queue
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .discovery import ScanEngine, ScanOptions
from .model import normalize_ip
from .store import Store

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY = 64 * 1024
CLIENT_HEADER = "X-Lanwatch"
SSE_HEARTBEAT = 12.0
HISTORY_DEFAULT = 12
HISTORY_MAX = 200

_MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json; charset=utf-8",
    ".ico": "image/x-icon",
}

_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)


def _history_limit(raw: str) -> int:
    if not raw:
        return HISTORY_DEFAULT
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc
    if not 1 <= value <= HISTORY_MAX:
        raise ValueError(f"limit must be between 1 and {HISTORY_MAX}")
    return value


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = f"lanwatch/{__version__}"
    protocol_version = "HTTP/1.1"

    # -- plumbing --------------------------------------------------------

    @property
    def engine(self) -> ScanEngine:
        return self.server.engine  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        if self.path.startswith("/api/events"):
            return
        sys.stderr.write(
            f"[{time.strftime('%H:%M:%S')}] {self.address_string()} {format % args}\n"
        )

    def _common_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._common_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_error_json(self, status: int, message: str) -> None:
        # A rejected request may still have an unread body; never reuse that
        # connection, or the body bytes would be parsed as the next request.
        self.close_connection = True
        self._send_json({"ok": False, "error": message}, status)

    def _send_bytes(
        self, body: bytes, content_type: str, extra: dict[str, str] | None = None
    ) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self._common_headers()
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # -- HTTP verbs ------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        try:
            parsed = urlsplit(self.path)
            path = parsed.path
            if path in ("/", "/index.html"):
                self._serve_static("index.html")
            elif path.startswith("/static/"):
                self._serve_static(path[len("/static/") :])
            elif path == "/favicon.ico":
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif path == "/api/state":
                self._send_json(self.engine.snapshot())
            elif path == "/api/events":
                self._serve_events()
            elif path == "/api/health":
                self._send_json({"ok": True, "version": __version__, "time": time.time()})
            elif path == "/api/network":
                self._send_json(
                    {
                        "ok": True,
                        "network": self.engine.store.network,
                        "interfaces": [iface.to_dict() for iface in self.engine.interfaces],
                    }
                )
            elif path == "/api/history":
                self._serve_history(parsed.query)
            elif path in ("/api/export.csv", "/api/export.json"):
                self._serve_export(path)
            elif path.startswith("/api/"):
                self._send_error_json(404, f"unknown endpoint {path}")
            else:
                self._send_error_json(404, "not found")
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            traceback.print_exc()
            self._send_error_json(500, "internal error")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        try:
            if not self._post_allowed():
                self._send_error_json(403, "missing or invalid request header")
                return
            path = urlsplit(self.path).path
            payload = self._read_json()
            if payload is None:
                return
            if path == "/api/scan":
                self._start_scan(payload)
            elif path == "/api/stop":
                self._send_json({"ok": True, "stopped": self.engine.stop()})
            elif path == "/api/device":
                self._update_device(payload)
            elif path == "/api/probe":
                self._probe(payload)
            elif path == "/api/forget":
                self._forget(payload)
            elif path == "/api/interfaces":
                self._send_json({"ok": True, "interfaces": self.engine.refresh_interfaces()})
            else:
                self._send_error_json(404, f"unknown endpoint {path}")
        except (BrokenPipeError, ConnectionResetError):
            return
        except ValueError as exc:
            self._send_error_json(400, str(exc))
        except Exception:
            traceback.print_exc()
            self._send_error_json(500, "internal error")

    # -- request helpers -------------------------------------------------

    def _post_allowed(self) -> bool:
        if self.headers.get(CLIENT_HEADER) != "1":
            return False
        origin = self.headers.get("Origin")
        if origin:
            host = urlsplit(origin).netloc
            if host.lower() != (self.headers.get("Host") or "").lower():
                return False
        return True

    def _read_json(self) -> dict[str, Any] | None:
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        length = self.headers.get("Content-Length")
        if length is None:
            return {}
        try:
            size = int(length)
        except ValueError:
            self._send_error_json(400, "invalid Content-Length")
            return None
        if size > MAX_BODY:
            self._send_error_json(413, "request body too large")
            return None
        body = self.rfile.read(size) if size else b""
        if not body:
            return {}
        if content_type and content_type != "application/json":
            self._send_error_json(415, "expected application/json")
            return None
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self._send_error_json(400, "invalid JSON body")
            return None
        if not isinstance(payload, dict):
            self._send_error_json(400, "JSON body must be an object")
            return None
        return payload

    # -- endpoints -------------------------------------------------------

    def _serve_static(self, name: str) -> None:
        filename = Path(name).name
        if not filename or filename != name:
            self._send_error_json(404, "not found")
            return
        target = STATIC_DIR / filename
        try:
            body = target.read_bytes()
        except OSError:
            self._send_error_json(404, f"missing asset {filename}")
            return
        content_type = _MIME.get(target.suffix.lower()) or mimetypes.guess_type(filename)[0]
        extra = {"Content-Security-Policy": _CSP} if target.suffix == ".html" else {}
        self._send_bytes(body, content_type or "application/octet-stream", extra)

    def _serve_export(self, path: str) -> None:
        store: Store = self.engine.store
        stamp = time.strftime("%Y%m%d-%H%M%S")
        if path.endswith(".csv"):
            body = store.export_csv(store.devices_sorted()).encode("utf-8")
            self._send_bytes(
                body,
                "text/csv; charset=utf-8",
                {"Content-Disposition": f'attachment; filename="lanwatch-{stamp}.csv"'},
            )
        else:
            body = json.dumps(store.export_json(), indent=2, default=str).encode("utf-8")
            self._send_bytes(
                body,
                "application/json; charset=utf-8",
                {"Content-Disposition": f'attachment; filename="lanwatch-{stamp}.json"'},
            )

    def _serve_history(self, query: str) -> None:
        raw_limit = parse_qs(query).get("limit", [""])[0]
        try:
            limit = _history_limit(raw_limit)
        except ValueError as exc:
            self._send_error_json(400, str(exc))
            return
        try:
            scans = self.engine.history.recent(limit)
        except (OSError, sqlite3.Error) as exc:
            self._send_error_json(500, f"history unavailable: {exc}")
            return
        self._send_json(
            {
                "ok": True,
                "scans": scans,
                "path": str(self.engine.history.path),
                "error": self.engine.history_error,
            }
        )

    def _start_scan(self, payload: dict[str, Any]) -> None:
        try:
            options = ScanOptions.from_payload(payload, self.engine.options)
        except ValueError as exc:
            self._send_error_json(400, str(exc))
            return
        started, message = self.engine.start(options)
        if not started:
            self._send_error_json(409, message)
            return
        self._send_json({"ok": True, "state": self.engine.state_dict()}, 202)

    def _update_device(self, payload: dict[str, Any]) -> None:
        ip = payload.get("ip")
        if not isinstance(ip, str):
            raise ValueError("ip is required")
        label = payload.get("label")
        notes = payload.get("notes")
        if label is not None and not isinstance(label, str):
            raise ValueError("label must be a string")
        if notes is not None and not isinstance(notes, str):
            raise ValueError("notes must be a string")
        address = normalize_ip(ip)
        device = self.engine.store.set_user_fields(address, label, notes)
        if device is None:
            self._send_error_json(404, f"unknown device {address}")
            return
        self.engine.store.save()
        snapshot = device.to_dict()
        self.engine._emit("device", device=snapshot)
        self._send_json({"ok": True, "device": snapshot})

    def _probe(self, payload: dict[str, Any]) -> None:
        ip = payload.get("ip")
        if not isinstance(ip, str):
            raise ValueError("ip is required")
        address = normalize_ip(ip)
        if address not in self.engine.store.devices:
            self._send_error_json(404, f"unknown device {address}")
            return
        device = self.engine.probe_device(address)
        self._send_json({"ok": True, "device": device})

    def _forget(self, payload: dict[str, Any]) -> None:
        ip = payload.get("ip")
        if not isinstance(ip, str):
            raise ValueError("ip is required")
        address = normalize_ip(ip)
        removed = self.engine.store.forget(address)
        if removed:
            self.engine.store.save()
            self.engine._emit("device.removed", ip=address)
        self._send_json({"ok": True, "removed": removed})

    def _serve_events(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self._common_headers()
        self.end_headers()
        channel = self.engine.bus.subscribe()
        try:
            self._write_event(
                {
                    "type": "hello",
                    "ts": time.time(),
                    "state": self.engine.state_dict(),
                    "version": __version__,
                }
            )
            while True:
                try:
                    event = channel.get(timeout=SSE_HEARTBEAT)
                except queue.Empty:
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
                    continue
                self._write_event(event)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.engine.bus.unsubscribe(channel)
            self.close_connection = True

    def _write_event(self, event: dict[str, Any]) -> None:
        data = json.dumps(event, default=str, separators=(",", ":"))
        self.wfile.write(f"data: {data}\n\n".encode())
        self.wfile.flush()


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], engine: ScanEngine) -> None:
        self.engine = engine
        super().__init__(address, DashboardHandler)

    def handle_error(self, request: object, client_address: object) -> None:
        # Dashboards get closed mid-stream all the time; that is not an error.
        if isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)  # type: ignore[arg-type]


def _open_browser(url: str) -> None:
    def opener() -> None:
        time.sleep(0.6)
        try:
            if shutil.which("termux-open-url"):
                subprocess.Popen(
                    ["termux-open-url", url],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                webbrowser.open(url)
        except OSError:
            pass

    threading.Thread(target=opener, name="lanwatch-browser", daemon=True).start()


def serve(
    host: str = "127.0.0.1",
    port: int = 8765,
    engine: ScanEngine | None = None,
    open_browser: bool = True,
    auto_scan: bool = False,
) -> int:
    """Run the dashboard until interrupted.  Returns a process exit code."""
    if engine is None:
        engine = ScanEngine(Store())
    try:
        server = DashboardServer((host, port), engine)
    except OSError as exc:
        print(f"lanwatch: cannot bind {host}:{port}: {exc}", file=sys.stderr)
        return 1

    actual_port = server.server_address[1]
    display_host = "localhost" if host in ("127.0.0.1", "::1", "0.0.0.0") else host
    url = f"http://{display_host}:{actual_port}/"
    print(f"lanwatch dashboard  {url}")
    print(f"state file           {engine.store.path}")
    if host not in ("127.0.0.1", "::1", "localhost"):
        print(
            "warning: listening on a non-loopback address; anyone on the LAN can view "
            "and trigger scans",
            file=sys.stderr,
        )
    print("press Ctrl+C to stop")
    if open_browser:
        _open_browser(url)
    if auto_scan:
        engine.start()

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nstopping…")
    finally:
        engine.stop()
        server.shutdown()
        server.server_close()
        engine.store.save()
    return 0
