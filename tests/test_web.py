"""End-to-end tests for the dashboard HTTP server and JSON API."""

from __future__ import annotations

import http.client
import json
import socket
import tempfile
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request
from pathlib import Path

from lanwatch import web
from lanwatch.discovery import ScanEngine, ScanOptions
from lanwatch.history import MAX_EVENT_AGE_DAYS, MAX_EVENTS
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

    def raw_request(self, request: bytes) -> tuple[int, bytes]:
        host, port = self.server.server_address
        with socket.create_connection((host, port), timeout=5) as connection:
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        response = b"".join(chunks)
        head, _, body = response.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0]
        return int(status_line.split()[1]), body

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

    def test_trust_event_log_and_scan_diff_endpoints(self) -> None:
        status, _, body = self.request("/api/scan/diff")
        self.assertEqual(status, 404, body)

        self.start_scan()
        data = self.state()
        self.assertIn("events", data)
        self.assertGreaterEqual(data["events"]["unread"], 1)
        self.assertEqual(data["events"]["retention"]["max_events"], MAX_EVENTS)
        self.assertEqual(
            data["events"]["retention"]["max_event_age_days"], MAX_EVENT_AGE_DAYS
        )
        self.assertTrue(data["latest_diff"]["baseline"])

        status, _, body = self.request(
            "/api/device",
            "POST",
            {"ip": "10.0.0.1", "label": "Router", "notes": "keep me"},
            HEADERS,
        )
        self.assertEqual(status, 200, body)

        status, _, body = self.request(
            "/api/device",
            "POST",
            {"ip": "10.0.0.1", "trust": "trusted"},
            HEADERS,
        )
        self.assertEqual(status, 200, body)
        updated = json.loads(body)["device"]
        self.assertEqual(updated["trust"], "trusted")
        self.assertEqual(updated["label"], "Router")
        self.assertEqual(updated["notes"], "keep me")

        status, _, _ = self.request(
            "/api/device",
            "POST",
            {"ip": "10.0.0.1", "trust": "owner"},
            HEADERS,
        )
        self.assertEqual(status, 400)

        status, _, body = self.request("/api/event-log")
        self.assertEqual(status, 200, body)
        log = json.loads(body)
        self.assertTrue(log["ok"])
        self.assertTrue(log["events"])
        self.assertEqual(log["retention"]["max_events"], MAX_EVENTS)
        self.assertEqual(log["retention"]["max_event_age_days"], MAX_EVENT_AGE_DAYS)
        self.assertEqual(log["events"][0]["type"], "device.trust_changed")
        self.assertEqual(log["events"][0]["details"]["after"], "trusted")
        event_id = log["events"][0]["id"]

        status, _, body = self.request(
            "/api/event-log/read", "POST", {"ids": [event_id]}, HEADERS
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["marked"], 1)

        status, _, body = self.request("/api/event-log?limit=0")
        self.assertEqual(status, 400, body)
        status, _, body = self.request("/api/event-log?severity=bogus")
        self.assertEqual(status, 400, body)

        status, _, body = self.request("/api/scan/diff")
        self.assertEqual(status, 200, body)
        diff = json.loads(body)
        self.assertTrue(diff["baseline"])
        self.assertEqual(diff["scan_id"], diff["scan"]["id"])
        self.assertEqual(diff["scan"]["devices_found"], 4)

        status, _, body = self.request(
            "/api/event-log/read", "POST", {"all": True}, HEADERS
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["unread"], 0)

    def test_event_log_filters_and_scan_completion(self) -> None:
        self.start_scan()
        state = self.state()
        network_id = state["latest_diff"]["network_id"]

        status, _, body = self.request("/api/event-log?type=scan.completed&limit=5")
        self.assertEqual(status, 200, body)
        log = json.loads(body)
        self.assertEqual(len(log["events"]), 1)
        completed = log["events"][0]
        self.assertEqual(completed["type"], "scan.completed")
        self.assertEqual(completed["severity"], "info")
        self.assertEqual(completed["network_id"], network_id)
        self.assertEqual(completed["description"], completed["message"])
        self.assertIsNone(completed["device_ip"])
        self.assertGreater(completed["ts"], 0)

        for query in (
            f"type=scan.completed&network_id={network_id}",
            "type=scan.completed&severity=info",
            "type=scan.completed&limit=1",
            f"before_id={completed['id'] + 1}",
        ):
            status, _, body = self.request(f"/api/event-log?{query}")
            self.assertEqual(status, 200, f"{query}: {body}")
            self.assertIn("scan.completed", {e["type"] for e in json.loads(body)["events"]})

        status, _, body = self.request(
            "/api/device",
            "POST",
            {"ip": "10.0.0.1", "trust": "trusted"},
            HEADERS,
        )
        self.assertEqual(status, 200, body)
        status, _, body = self.request(
            "/api/event-log?type=device.trust_changed&severity=info"
            "&device=10.0.0.1&limit=1"
        )
        self.assertEqual(status, 200, body)
        events = json.loads(body)["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["device_name"], "ROUTER")
        self.assertEqual(events[0]["details"]["after"], "trusted")
        status, _, body = self.request(
            "/api/event-log?type=device.trust_changed&device=10.0.0.2"
        )
        self.assertEqual(json.loads(body)["events"], [])

        status, _, body = self.request("/api/event-log?before_id=0")
        self.assertEqual(status, 400, body)

    def test_invalid_ids_and_content_length_are_rejected(self) -> None:
        for path in (
            "/api/event-log?before_id=9223372036854775808",
            "/api/scan/diff?scan_id=9223372036854775808",
        ):
            status, _, body = self.request(path)
            self.assertEqual(status, 400, f"{path}: {body}")
            self.assertFalse(json.loads(body)["ok"])

        for ids in ([9223372036854775808], [-1]):
            status, _, body = self.request(
                "/api/event-log/read", "POST", {"ids": ids}, HEADERS
            )
            self.assertEqual(status, 400, f"ids={ids}: {body}")
            self.assertFalse(json.loads(body)["ok"])

        host, port = self.server.server_address
        request = (
            b"POST /api/stop HTTP/1.1\r\n"
            + f"Host: {host}:{port}\r\n".encode()
            + b"X-Lanwatch: 1\r\n"
            + b"Content-Type: application/json\r\n"
            + b"Content-Length: -1\r\n"
            + b"Connection: close\r\n\r\n{}"
        )
        status, body = self.raw_request(request)
        self.assertEqual(status, 400, body)
        self.assertFalse(json.loads(body)["ok"])

        status, _, _ = self.request("/api/health")
        self.assertEqual(status, 200)

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
        self.assertIn('id="event-center"', text)
        self.assertIn('id="events-btn"', text)
        self.assertIn('id="drawer-trust"', text)
        self.assertIn('id="trust-filter"', text)

    def test_dashboard_topology_panel(self) -> None:
        status, _, body = self.request("/")
        self.assertEqual(status, 200)
        text = body.decode()
        for element in (
            'id="topology"',
            'id="topology-title"',
            'id="topology-context"',
            'id="topology-count"',
            'id="topology-map"',
            'id="topology-svg-host"',
            'id="topology-empty"',
            'id="topology-empty-title"',
            'id="topology-empty-text"',
            'id="topology-scan"',
            'id="topology-more"',
            'id="topology-note"',
            'id="topology-accessible-list"',
            'id="topology-controls"',
            'id="topology-search"',
            'id="topology-filters"',
            'id="topology-view-status"',
            'id="topology-zoom"',
            'id="topology-zoom-out"',
            'id="topology-zoom-in"',
            'id="topology-zoom-label"',
            'id="topology-fit"',
            'id="topology-tooltip"',
            'id="topology-selection"',
            'id="topology-selection-close"',
        ):
            self.assertIn(element, text)
        self.assertIn("Network topology", text)
        self.assertIn("Connections are logical", text)
        self.assertIn("topology-swatch online", text)
        self.assertIn("topology-swatch trust-trusted", text)
        self.assertIn('data-topology-filter="online"', text)
        self.assertIn('data-topology-filter="trusted"', text)
        self.assertIn('aria-label="Search topology devices"', text)
        self.assertNotIn("<canvas", text)

        status, _, body = self.request("/static/app.js")
        self.assertEqual(status, 200)
        script = body.decode()
        for symbol in (
            "function topologyLimit",
            "function topologyGateway",
            "function buildTopologyView",
            "function createTopologySvg",
            "function renderTopology",
            "function setupTopologyResize",
            "function bindTopologyEvents",
            "function activateTopologyNode",
            "function topologyMatchesSearch",
            "function topologyMatchesFilter",
            "function topologyNodeDisplayState",
            "function topologyNameLines",
            "function topologyTreeColumns",
            "function topologyNodeLabelMetrics",
            "function topologyHubLabelMetrics",
            "function topologyZoomScale",
            "function topologyPanView",
            "function topologyTransform",
            "function topologyRenderSignature",
            "function restoreTopologyFocus",
            "createElementNS(",
            "textContent",
            "ResizeObserver",
        ):
            self.assertIn(symbol, script)
        self.assertIn(
            "renderStats();\n  renderTopology();\n  renderScan();",
            script,
        )
        self.assertIn("$('#topology-scan').addEventListener('click'", script)
        self.assertNotIn("Math.random", script)

        status, _, body = self.request("/static/styles.css")
        self.assertEqual(status, 200)
        css = body.decode()
        for rule in (
            ".topology-svg",
            ".topology-link.is-offline",
            ".topology-node.is-offline",
            ".topology-node.trust-trusted",
            ".topology-node.trust-unknown",
            ".topology-node.trust-ignored",
            ".topology-status-dot.offline",
            ".topology-node.is-selected",
            ".topology-node.is-selected .topology-node-name",
            ".topology-link.is-selected",
            ".topology-node.is-dimmed",
            ".topology-node.is-filtered",
            ".topology-search",
            ".topology-zoom",
            ".topology-tooltip",
            ".topology-selection",
        ):
            self.assertIn(rule, css)

    def test_dashboard_topology_interactions_and_responsive_controls(self) -> None:
        status, _, body = self.request("/static/app.js")
        self.assertEqual(status, 200)
        script = body.decode()
        for marker in (
            "map.addEventListener('click', onTopologyMapClick)",
            "map.addEventListener('keydown', onTopologyMapKeydown)",
            "map.addEventListener('pointerdown', onTopologyPanStart)",
            "map.addEventListener('pointermove', onTopologyPanMove)",
            "map.addEventListener('pointerup', onTopologyPanEnd)",
            "map.addEventListener('pointercancel', onTopologyPanEnd)",
            "search.addEventListener('input', onTopologySearchInput)",
            "filters.addEventListener('click', onTopologyFilterClick)",
            "openDrawer(key)",
            "aria-current",
            "tabindex: '0'",
            "role: 'button'",
            "setPointerCapture",
            "releasePointerCapture",
            "state.topology.view = topologyFitView()",
            "TOPOLOGY_ZOOM_MIN",
            "TOPOLOGY_ZOOM_MAX",
            "safeWidth < 900",
            "Math.min(width * 0.41, 330)",
        ):
            self.assertIn(marker, script)
        self.assertNotIn("Math.random", script)
        self.assertNotIn("fetch('https://", script)
        self.assertNotIn("fetch(\"https://", script)

        status, _, body = self.request("/static/styles.css")
        self.assertEqual(status, 200)
        css = body.decode()
        self.assertIn(".topology-svg-host { display: block; touch-action: pan-y; cursor: grab; }", css)
        self.assertIn("@media (pointer: coarse)", css)
        self.assertIn(".topology-control { min-width: 40px; height: 38px; }", css)
        self.assertIn(
            ".topology-filters .filter-chip { min-height: 38px; padding: 0 12px; }",
            css,
        )
        self.assertIn(
            ".topology-zoom {\n    position: static;\n    width: max-content;\n    max-width: 100%;\n    margin: 6px 8px 0 auto;\n    flex-direction: row;\n  }",
            css,
        )
        self.assertIn("grid-template-columns: repeat(3, minmax(0, 1fr));", css)
        self.assertIn("prefers-reduced-motion: reduce", css)

    def test_topology_state_fields(self) -> None:
        self.start_scan()
        data = self.state()
        self.assertEqual(data["network"]["gateway"], "10.0.0.1")
        devices = {device["ip"]: device for device in data["devices"]}
        gateway = devices["10.0.0.1"]
        self.assertTrue(gateway["is_gateway"])
        for key in ("name", "hostname", "kind", "online", "trust", "is_gateway"):
            self.assertIn(key, gateway)
        self.assertTrue(all("is_gateway" in device for device in data["devices"]))

    def test_dashboard_event_and_trust_controls(self) -> None:
        status, _, body = self.request("/")
        self.assertEqual(status, 200)
        text = body.decode()
        for element in (
            'id="events-panel"',
            'id="events-panel-list"',
            'id="events-panel-status"',
            'id="events-refresh"',
            'id="event-device-filter"',
            'id="event-status"',
            'id="events-refresh-modal"',
            'id="scan-error"',
            'id="scan-retry"',
            'id="trust-guide"',
            'id="trust-help"',
            'id="drawer-trust-help"',
        ):
            self.assertIn(element, text)
        for severity in ("all", "info", "warning", "critical"):
            self.assertIn(f'data-severity="{severity}"', text)
        for trust in ("all", "trusted", "unknown", "ignored"):
            self.assertIn(f'<option value="{trust}"', text)
        self.assertNotIn('value="notice"', text)
        self.assertNotIn("warning-only", text)

        status, _, body = self.request("/static/app.js")
        self.assertEqual(status, 200)
        script = body.decode()
        for event_type in (
            "device.new",
            "device.online",
            "device.offline",
            "device.hostname_changed",
            "device.vendor_changed",
            "device.kind_changed",
            "port.opened",
            "port.closed",
            "scan.completed",
            "scan.failed",
            "device.ip_changed",
            "device.replaced",
            "device.trust_changed",
        ):
            self.assertIn(f"'{event_type}'", script)
        self.assertIn("function eventStatusHtml", script)
        self.assertIn("data-act=\"refresh-events\"", script)
        self.assertIn("function retentionText", script)
        self.assertIn("function trustBadge", script)
        self.assertIn("badges.push(trustBadge(device.trust || 'unknown'));", script)
        self.assertIn("scan-now", script)
        self.assertIn("state.newDevices.delete(ip)", script)

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
            self.assertIn("unread", event)
        finally:
            connection.close()

    def test_sse_hello_does_not_leak_an_inactive_diff(self) -> None:
        previous = self.store.activate("10.20.0.0/24", "aa:aa:aa:aa:aa:01")
        self.store.activate("10.30.0.0/24", "bb:bb:bb:bb:bb:01")
        self.engine.last_diff = {
            "network_id": previous.id,
            "counts": {"new": 1},
            "new_ips": ["10.20.0.2"],
            "changes": [],
        }
        self.assertNotIn("latest_diff", self.state())

        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_address[1], timeout=8
        )
        try:
            connection.request("GET", "/api/events")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            line = response.readline().decode("utf-8")
            self.assertTrue(line.startswith("data: "), line)
            event = json.loads(line[len("data: ") :])
            self.assertEqual(event["type"], "hello")
            self.assertNotIn("latest_diff", event)
        finally:
            connection.close()

    def test_sse_publishes_scan_event_new(self) -> None:
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_address[1], timeout=10
        )
        try:
            connection.request("GET", "/api/events")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            hello = response.readline().decode("utf-8")
            self.assertTrue(hello.startswith("data: "), hello)
            self.assertEqual(response.readline().decode("utf-8"), "\n")

            self.start_scan()
            published = []
            for _ in range(400):
                line = response.readline().decode("utf-8")
                if not line.startswith("data: "):
                    continue
                message = json.loads(line[len("data: ") :])
                if message["type"] == "event.new":
                    published.append(message["event"])
                if any(item["type"] == "scan.completed" for item in published):
                    break
            completed = next(
                item for item in published if item["type"] == "scan.completed"
            )
            self.assertGreater(completed["id"], 0)
            self.assertEqual(completed["network_id"], "10.0.0.0/24")
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
