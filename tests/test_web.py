"""End-to-end tests for the dashboard HTTP server and JSON API."""

from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request
from pathlib import Path

from lanwatch import web
from lanwatch.discovery import ScanEngine, ScanOptions
from lanwatch.store import Store

from .helpers import patched_scan, wait_until

HEADERS = {"X-Lanwatch": "1"}


class WebTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "inventory.json")
        self.engine = ScanEngine(self.store, ScanOptions())
        self.scan_context = patched_scan()
        self.scan_context.__enter__()
        self.server = web.DashboardServer(("127.0.0.1", 0), self.engine)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.02},
            name="lanwatch-test-http",
            daemon=True,
        )
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.engine.stop()
        self.server.shutdown()
        self.server.server_close()
        self.scan_context.__exit__(None, None, None)
        self.tmp.cleanup()

    # -- helpers ---------------------------------------------------------

    def request(
        self,
        path: str,
        method: str = "GET",
        payload: object = None,
        headers: dict[str, str] | None = None,
        raw_body: bytes | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        data = raw_body
        if payload is not None:
            data = json.dumps(payload).encode()
        request_headers = dict(headers or {})
        if data is not None:
            request_headers.setdefault("Content-Type", "application/json")
        request = urllib.request.Request(
            self.base + path, data=data, method=method, headers=request_headers
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            body = error.read()
            error.close()
            return error.code, dict(error.headers), body

    def state(self) -> dict:
        status, _, body = self.request("/api/state")
        self.assertEqual(status, 200)
        return json.loads(body)

    def start_scan(self) -> None:
        status, _, body = self.request("/api/scan", "POST", {}, HEADERS)
        self.assertEqual(status, 202, body)
        self.assertTrue(
            wait_until(
                lambda: not self.engine.running
                and self.engine.state_dict()["phase"] in ("done", "error")
            ),
            self.engine.state_dict(),
        )
        self.assertEqual(self.engine.state_dict()["phase"], "done")

    # -- tests -----------------------------------------------------------

    def test_index_and_headers(self) -> None:
        status, headers, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn("lanwatch", body.decode())
        self.assertIn("default-src 'self'", headers.get("Content-Security-Policy", ""))
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("text/html", headers.get("Content-Type", ""))

    def test_static_assets(self) -> None:
        for name in ("styles.css", "app.js", "favicon.svg"):
            status, headers, body = self.request(f"/static/{name}")
            self.assertEqual(status, 200, name)
            self.assertTrue(body)
        status, _, _ = self.request("/static/../web.py")
        self.assertEqual(status, 404)

    def test_state_shape(self) -> None:
        data = self.state()
        for key in ("state", "devices", "network", "collectors", "options", "interfaces"):
            self.assertIn(key, data)
        self.assertIn("history", data)
        self.assertIn("path", data["history"])
        self.assertFalse(data["state"]["running"])
        names = [iface["name"] for iface in data["interfaces"]]
        self.assertNotIn("lo", names)

    def test_history_endpoint(self) -> None:
        status, _, body = self.request("/api/history")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["ok"])
        self.assertEqual(data["scans"], [])
        self.assertIn("history.db", data["path"])

        self.start_scan()
        status, _, body = self.request("/api/history?limit=5")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(len(data["scans"]), 1)
        scan = data["scans"][0]
        self.assertEqual(scan["subnet"], "10.0.0.0/24")
        self.assertEqual(scan["devices_found"], 4)
        self.assertFalse(scan["stopped"])

        for query in ("limit=0", "limit=201", "limit=abc"):
            status, _, body = self.request(f"/api/history?{query}")
            self.assertEqual(status, 400, query)
            self.assertFalse(json.loads(body)["ok"])

    def test_history_endpoint_reports_read_errors(self) -> None:
        self.engine.history.recent = unittest.mock.Mock(side_effect=OSError("read-only"))
        status, _, body = self.request("/api/history")
        self.assertEqual(status, 500)
        data = json.loads(body)
        self.assertFalse(data["ok"])
        self.assertIn("history unavailable", data["error"])

    def test_index_includes_history_panel(self) -> None:
        status, _, body = self.request("/")
        self.assertEqual(status, 200)
        text = body.decode()
        self.assertIn("Scan history", text)
        self.assertIn('id="history-rows"', text)
        self.assertIn('id="history-spark"', text)

    def test_mutations_require_header_and_matching_origin(self) -> None:
        status, _, _ = self.request("/api/scan", "POST", {})
        self.assertEqual(status, 403)
        status, _, _ = self.request(
            "/api/scan", "POST", {}, {**HEADERS, "Origin": "http://evil.example"}
        )
        self.assertEqual(status, 403)
        # The rejected requests must not poison the server.
        status, _, _ = self.request("/api/health")
        self.assertEqual(status, 200)

    def test_invalid_json(self) -> None:
        status, _, body = self.request("/api/scan", "POST", raw_body=b"not json", headers=HEADERS)
        self.assertEqual(status, 400)
        self.assertFalse(json.loads(body)["ok"])

    def test_invalid_options(self) -> None:
        status, _, _ = self.request("/api/scan", "POST", {"concurrency": 0}, HEADERS)
        self.assertEqual(status, 400)

    def test_scan_labels_probe_and_export(self) -> None:
        self.start_scan()
        data = self.state()
        self.assertEqual(len(data["devices"]), 4)
        self.assertEqual(data["network"]["gateway"], "10.0.0.1")

        status, _, body = self.request(
            "/api/device",
            "POST",
            {"ip": "10.0.0.1", "label": "Living Room Router", "notes": "test"},
            HEADERS,
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["device"]["name"], "Living Room Router")

        with unittest.mock.patch(
            "lanwatch.discovery.collectors.ping_host", return_value=4.2
        ), unittest.mock.patch(
            "lanwatch.discovery.collectors.scan_ports", return_value={"10.0.0.1": [22]}
        ):
            status, _, body = self.request("/api/probe", "POST", {"ip": "10.0.0.1"}, HEADERS)
        self.assertEqual(status, 200)
        device = json.loads(body)["device"]
        self.assertTrue(device["online"])
        self.assertIn(22, device["ports"])

        status, headers, body = self.request("/api/export.csv")
        self.assertEqual(status, 200)
        self.assertIn("attachment;", headers.get("Content-Disposition", ""))
        text = body.decode()
        self.assertIn("ip,name,hostname", text)
        self.assertIn("Living Room Router", text)

        status, _, body = self.request("/api/export.json")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["devices"]), 4)

        status, _, body = self.request("/api/forget", "POST", {"ip": "10.0.0.9"}, HEADERS)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["removed"])
        self.assertNotIn("10.0.0.9", [device["ip"] for device in self.state()["devices"]])

    def test_unknown_endpoints(self) -> None:
        status, _, body = self.request("/api/nope")
        self.assertEqual(status, 404)
        self.assertFalse(json.loads(body)["ok"])

    def test_sse_hello(self) -> None:
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_address[1], timeout=8
        )
        try:
            connection.request("GET", "/api/events")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIn("text/event-stream", response.getheader("Content-Type", ""))
            line = response.readline().decode("utf-8")
            self.assertTrue(line.startswith("data: "), line)
            event = json.loads(line[len("data: ") :])
            self.assertEqual(event["type"], "hello")
            self.assertIn("state", event)
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
