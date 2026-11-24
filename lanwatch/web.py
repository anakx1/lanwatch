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
from .events import SEVERITIES
from .model import normalize_ip, validate_trust
from .store import Store

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY = 64 * 1024
CLIENT_HEADER = "X-Lanwatch"
SSE_HEARTBEAT = 12.0
HISTORY_DEFAULT = 12
HISTORY_MAX = 200
EVENT_DEFAULT = 50
EVENT_MAX = 200
SQLITE_MAX_INT = 2**63 - 1

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


def _event_limit(raw: str) -> int:
    if not raw:
        return EVENT_DEFAULT
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc
    if not 1 <= value <= EVENT_MAX:
        raise ValueError(f"limit must be between 1 and {EVENT_MAX}")
    return value


def _positive_int(raw: str, name: str) -> int | None:
    if not raw:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < 1:
        raise ValueError(f"{name} must be positive")
    if value > SQLITE_MAX_INT:
        raise ValueError(f"{name} is too large")
    return value


def _query_flag(raw: str) -> bool:
    return raw.strip().lower() in ("1", "true", "yes", "on")


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
            elif path == "/api/networks":
                self._send_json(
                    {
                        "ok": True,
                        "networks": self.engine.networks(),
                        "active": self.engine.store.active_id,
                    }
                )
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
            elif path == "/api/event-log":
                self._serve_event_log(parsed.query)
            elif path == "/api/scan/diff":
                self._serve_scan_diff(parsed.query)
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
            elif path == "/api/event-log/read":
                self._mark_events_read(payload)
            elif path == "/api/probe":
                self._probe(payload)
            elif path == "/api/forget":
                self._forget(payload)
            elif path == "/api/network/select":
                self._network_action(payload, "select")
            elif path == "/api/network/archive":
                self._network_action(payload, "archive")
            elif path == "/api/network/rename":
                self._network_action(payload, "rename")
            elif path == "/api/network/delete":
                self._network_action(payload, "delete")
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
        if size < 0:
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

    def _network_action(self, payload: dict[str, Any], action: str) -> None:
        network_id = payload.get("id")
        if not isinstance(network_id, str) or not network_id:
            raise ValueError("id is required")
        engine = self.engine
        if action == "select":
            ok, message = engine.select_network(network_id)
        elif action == "archive":
            archived = payload.get("archived", True)
            if not isinstance(archived, bool):
                raise ValueError("archived must be a boolean")
            ok, message = engine.archive_network(network_id, archived)
        elif action == "rename":
            label = payload.get("label")
            if label is not None and not isinstance(label, str):
                raise ValueError("label must be a string")
            ok, message = engine.rename_network(network_id, label)
        else:
            ok, message = engine.delete_network(network_id)
        if not ok:
            status = 404 if message.startswith("unknown") else 409
            self._send_error_json(status, message)
            return
        self._send_json({"ok": True, **{"networks": engine.networks()}})

    def _update_device(self, payload: dict[str, Any]) -> None:
        ip = payload.get("ip")
        if not isinstance(ip, str):
            raise ValueError("ip is required")
        label = payload.get("label")
        notes = payload.get("notes")
        trust = payload.get("trust")
        if label is not None and not isinstance(label, str):
            raise ValueError("label must be a string")
        if notes is not None and not isinstance(notes, str):
            raise ValueError("notes must be a string")
        if trust is not None:
            if not isinstance(trust, str):
                raise ValueError("trust must be a string")
            validate_trust(trust)
        address = normalize_ip(ip)
        device = self.engine.store.set_user_fields(address, label, notes)
        if device is None:
            self._send_error_json(404, f"unknown device {address}")
            return
        if trust is not None:
            device, message = self.engine.set_device_trust(address, trust)
            if device is None:
                self._send_error_json(404, message)
                return
        else:
            self.engine.store.save()
            snapshot = device.to_dict()
            self.engine._emit("device", device=snapshot)
        self._send_json({"ok": True, "device": device.to_dict()})

    def _serve_event_log(self, query: str) -> None:
        params = parse_qs(query)
        try:
            limit = _event_limit(params.get("limit", [""])[0])
            before_id = _positive_int(params.get("before_id", [""])[0], "before_id")
            raw_severities = params.get("severity", [""])[0]
            severities = [item.strip().lower() for item in raw_severities.split(",") if item.strip()]
            for severity in severities:
                if severity not in SEVERITIES:
                    raise ValueError(f"unknown severity {severity!r}")
            event_type = params.get("type", [""])[0].strip() or None
            network_id = params.get("network_id", [""])[0].strip() or None
            device = params.get("device", [""])[0].strip() or None
            if device:
                device = normalize_ip(device)
            unread = _query_flag(params.get("unread", [""])[0])
        except ValueError as exc:
            self._send_error_json(400, str(exc))
            return
        try:
            events = self.engine.history.event_log(
                limit,
                before_id=before_id,
                severities=severities,
                event_type=event_type,
                network_id=network_id,
                device=device,
                unread=unread,
            )
            unread_count = self.engine.history.unread_count(network_id)
        except (OSError, sqlite3.Error) as exc:
            self._send_error_json(500, f"event log unavailable: {exc}")
            return
        self._send_json(
            {
                "ok": True,
                "events": events,
                "unread": unread_count,
                "has_more": len(events) >= limit,
                "path": str(self.engine.history.path),
                "error": self.engine.event_error or self.engine.history_error,
                "retention": {
                    "max_events": self.engine.history.max_events,
                    "max_event_age_days": self.engine.history.max_event_age_days,
                },
            }
        )

    def _mark_events_read(self, payload: dict[str, Any]) -> None:
        all_events = payload.get("all", False)
        if not isinstance(all_events, bool):
            raise ValueError("all must be a boolean")
        ids = payload.get("ids")
        if ids is not None:
            if not isinstance(ids, list) or len(ids) > EVENT_MAX:
                raise ValueError(f"ids must be a list of at most {EVENT_MAX} integers")
            try:
                ids = [int(value) for value in ids]
            except (TypeError, ValueError) as exc:
                raise ValueError("ids must contain integers") from exc
            if any(value < 1 or value > SQLITE_MAX_INT for value in ids):
                raise ValueError("ids must be positive 64-bit integers")
        if all_events and ids:
            raise ValueError("use either ids or all, not both")
        network_id = payload.get("network_id")
        if network_id is not None and not isinstance(network_id, str):
            raise ValueError("network_id must be a string")
        try:
            marked = self.engine.history.mark_events_read(
                ids, all_events=all_events, network_id=network_id
            )
            unread = self.engine.history.unread_count(network_id)
        except (OSError, sqlite3.Error) as exc:
            self._send_error_json(500, f"event log unavailable: {exc}")
            return
        self._send_json({"ok": True, "marked": marked, "unread": unread})

    def _serve_scan_diff(self, query: str) -> None:
        try:
            scan_id = _positive_int(
                parse_qs(query).get("scan_id", [""])[0], "scan_id"
            )
        except ValueError as exc:
            self._send_error_json(400, str(exc))
            return
        try:
            payload = self.engine.scan_diff(scan_id)
        except (OSError, sqlite3.Error) as exc:
            self._send_error_json(500, f"scan comparison unavailable: {exc}")
            return
        if payload is None:
            self._send_error_json(404, "no recorded scan to compare")
            return
        self._send_json({"ok": True, **payload, "error": None})

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
            hello: dict[str, Any] = {
                "type": "hello",
                "ts": time.time(),
                "state": self.engine.state_dict(),
                "version": __version__,
            }
            try:
                hello["unread"] = self.engine.history.unread_count(
                    self.engine.store.active_id
                )
            except (OSError, sqlite3.Error):
                hello["unread"] = 0
            latest_diff = self.engine.latest_diff_for_active()
            if latest_diff is not None:
                hello["latest_diff"] = latest_diff
            self._write_event(hello)
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
