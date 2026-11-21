"""Fingerprinting: kind votes, naming, web probing and TLS name extraction."""

from __future__ import annotations

import http.server
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from lanwatch import collectors, fingerprint
from lanwatch.discovery import ScanEngine, ScanOptions
from lanwatch.model import Device
from lanwatch.store import Store

from .helpers import patched_scan, wait_until


def ident(**fields):
    return fingerprint.identify(Device(ip="10.0.0.9", **fields))


class KindTests(unittest.TestCase):
    def test_unknown_device_stays_unknown(self) -> None:
        result = ident()
        self.assertEqual(result.kind, "device")
        self.assertEqual(result.confidence, 0)
        self.assertIsNone(result.name)

    def test_hostname_alone_identifies_phones_without_a_mac(self) -> None:
        self.assertEqual(ident(hostname="Johns-iPhone").kind, "phone")
        self.assertEqual(ident(hostname="Galaxy-S23").kind, "phone")
        self.assertEqual(ident(hostname="DESKTOP-4F2K").kind, "computer")
        self.assertEqual(ident(hostname="esp32-livingroom").kind, "iot")

    def test_web_title_and_server_identify_a_router(self) -> None:
        result = ident(web={"80": {"title": "TP-Link Wireless Router", "server": "uhttpd"}})
        self.assertEqual(result.kind, "router")
        self.assertGreaterEqual(result.confidence, 60)
        self.assertIn("web page looks like router admin", result.evidence)

    def test_printer_from_title(self) -> None:
        result = ident(web={"80": {"title": "HP LaserJet Pro M404"}}, ports=[80, 9100])
        self.assertEqual(result.kind, "printer")

    def test_nas_from_certificate_name(self) -> None:
        result = ident(web={"443": {"cert_cn": "DiskStation", "cert_org": "Synology"}})
        self.assertEqual(result.kind, "nas")

    def test_ssdp_internet_gateway(self) -> None:
        result = ident(ssdp={"deviceType": "urn:schemas-upnp-org:device:InternetGatewayDevice:1"})
        self.assertEqual(result.kind, "router")

    def test_tv_beats_generic_media_renderer(self) -> None:
        result = ident(ssdp={"friendlyName": "Living Room TV", "deviceType": "MediaRenderer", "model": "Bravia"})
        self.assertEqual(result.kind, "tv")

    def test_mdns_services_vote(self) -> None:
        self.assertEqual(ident(mdns_services=["_ipp._tcp"]).kind, "printer")
        self.assertEqual(ident(mdns_services=["_googlecast._tcp"]).kind, "tv")
        self.assertEqual(ident(mdns_services=["_sonos._tcp"]).kind, "speaker")
        self.assertEqual(ident(mdns_services=["_hap._tcp"]).kind, "iot")

    def test_vendor_votes_are_weak_for_ambiguous_makers(self) -> None:
        self.assertEqual(ident(vendor="Hikvision Digital").kind, "camera")
        self.assertEqual(ident(vendor="Espressif Inc.").kind, "iot")
        # Apple alone is too ambiguous to commit to a confident guess
        self.assertLess(ident(vendor="Apple, Inc.").confidence, 40)

    def test_conflicting_evidence_lowers_confidence(self) -> None:
        clear = ident(ports=[9100, 631])
        mixed = ident(ports=[9100, 631, 3389, 5900])
        self.assertEqual(clear.kind, "printer")
        self.assertLess(mixed.confidence, clear.confidence)

    def test_weak_evidence_is_not_enough(self) -> None:
        self.assertEqual(ident(ports=[22]).kind, "device")

    def test_port_rules(self) -> None:
        self.assertEqual(ident(ports=[3389]).kind, "computer")
        self.assertEqual(ident(ports=[32400]).kind, "nas")
        self.assertEqual(ident(ports=[62078]).kind, "phone")
        self.assertEqual(ident(ports=[445, 22]).kind, "nas")

    def test_ttl_hints(self) -> None:
        self.assertEqual(fingerprint.os_from_ttl(64), "Linux / Android / Apple")
        self.assertEqual(fingerprint.os_from_ttl(57), "Linux / Android / Apple")  # decremented
        self.assertEqual(fingerprint.os_from_ttl(128), "Windows")
        self.assertEqual(fingerprint.os_from_ttl(255), "Network equipment")
        self.assertIsNone(fingerprint.os_from_ttl(None))
        self.assertEqual(ident(ttl=255).kind, "router")
        self.assertEqual(ident(ttl=128, ports=[135]).os, "Windows")

    def test_randomized_mac_without_vendor_suggests_phone(self) -> None:
        self.assertEqual(ident(mac="da:a1:19:00:00:01").kind, "phone")
        self.assertEqual(ident(mac="3c:22:fb:00:00:01", vendor="Apple").kind, "device")

    def test_self_and_gateway(self) -> None:
        self.assertEqual(ident(is_self=True).kind, "self")
        self.assertEqual(ident(is_gateway=True).kind, "router")

    def test_os_detection(self) -> None:
        self.assertEqual(ident(hostname="iPad-Pro").os, "iOS")
        self.assertEqual(ident(ports=[5555]).os, "Android")
        self.assertEqual(
            ident(banners={"22": "SSH-2.0-OpenSSH_9.2p1 Debian-2"}).os, "Linux (Debian)"
        )


class NamingTests(unittest.TestCase):
    def test_clean_title(self) -> None:
        self.assertIsNone(fingerprint.clean_title("Login"))
        self.assertIsNone(fingerprint.clean_title("192.168.1.1"))
        self.assertIsNone(fingerprint.clean_title(None))
        self.assertEqual(fingerprint.clean_title("  Archer  AX50 \n"), "Archer AX50")
        self.assertEqual(len(fingerprint.clean_title("x" * 200)), 48)

    def test_name_prefers_vendor_and_model(self) -> None:
        result = ident(vendor="TP-Link Technologies Co., Ltd.", ssdp={"model": "Archer AX50"})
        self.assertEqual(result.name, "TP-Link Archer AX50")
        self.assertEqual(result.model, "Archer AX50")

    def test_name_falls_back_to_title_then_kind(self) -> None:
        self.assertEqual(ident(web={"80": {"title": "Living Room Hub"}}).name, "Living Room Hub")
        named = ident(vendor="Brother Industries, Ltd.", ports=[9100, 631])
        self.assertEqual(named.name, "Brother Industries printer")

    def test_display_name_uses_fingerprint_instead_of_unknown(self) -> None:
        device = Device(ip="10.0.0.9", web={"80": {"title": "Reolink Camera"}})
        self.assertEqual(device.display_name, "Reolink Camera")
        self.assertEqual(Device(ip="10.0.0.9").display_name, "Unknown device")

    def test_user_label_and_hostname_still_win(self) -> None:
        device = Device(ip="10.0.0.9", hostname="nas1", web={"80": {"title": "Synology"}})
        self.assertEqual(device.display_name, "nas1")
        device.label = "Attic NAS"
        self.assertEqual(device.display_name, "Attic NAS")

    def test_to_dict_exposes_identity(self) -> None:
        data = Device(ip="10.0.0.9", ttl=64, web={"80": {"title": "Printer"}}).to_dict()
        self.assertEqual(data["kind"], "printer")
        self.assertEqual(data["identity"]["kind"], "printer")
        self.assertEqual(data["ttl"], 64)
        self.assertIn("web", data)

    def test_round_trip_preserves_new_fields(self) -> None:
        original = Device(ip="10.0.0.9", ttl=128, web={"443": {"cert_cn": "nas", "title": "Hi there"}})
        restored = Device.from_dict(original.to_dict())
        self.assertEqual(restored.ttl, 128)
        self.assertEqual(restored.web, {"443": {"cert_cn": "nas", "title": "Hi there"}})

    def test_merge_combines_web_info_per_port(self) -> None:
        device = Device(ip="10.0.0.9", web={"80": {"title": "A"}})
        device.merge(Device(ip="10.0.0.9", web={"80": {"server": "nginx"}, "443": {"cert_cn": "x"}}, ttl=64))
        self.assertEqual(device.web["80"], {"title": "A", "server": "nginx"})
        self.assertEqual(device.web["443"], {"cert_cn": "x"})
        self.assertEqual(device.ttl, 64)


class HttpParsingTests(unittest.TestCase):
    def test_parse_title_server_realm(self) -> None:
        info = collectors.parse_http_response(
            {"server": "GoAhead-Webs", "www-authenticate": 'Basic realm="TP-LINK Router WR841N"'},
            b"<html><head><TITLE>\n  My &amp; Router </TITLE></head>",
            401,
        )
        self.assertEqual(info["title"], "My & Router")
        self.assertEqual(info["server"], "GoAhead-Webs")
        self.assertEqual(info["realm"], "TP-LINK Router WR841N")
        self.assertEqual(info["status"], "401")

    def test_binary_and_missing_title(self) -> None:
        info = collectors.parse_http_response({}, b"\xff\xfe<not html", 200)
        self.assertNotIn("title", info)

    def test_cert_names_reads_subject_after_issuer(self) -> None:
        issuer = b"\x55\x04\x03\x0c\x06Issuer"
        subject = b"\x55\x04\x0a\x0c\x08Synology\x55\x04\x03\x0c\x0bDiskStation"
        names = collectors.cert_names(b"\x30\x00" + issuer + b"\x00" * 6 + subject + b"\x00")
        self.assertEqual(names, {"cert_cn": "DiskStation", "cert_org": "Synology"})

    def test_cert_names_tolerates_garbage(self) -> None:
        self.assertEqual(collectors.cert_names(b""), {})
        self.assertEqual(collectors.cert_names(b"\x55\x04\x03"), {})
        self.assertEqual(collectors.cert_names(b"\x55\x04\x03\x0c\xff"), {})
        self.assertEqual(collectors.cert_names(b"\x55\x04\x03\x0c\x09abc"), {})


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"<html><title>Acme Printer 3000</title></html>"
        self.send_response(200)
        self.send_header("Server", "Acme-httpd/1.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # noqa: D401
        return


class LiveHttpProbeTests(unittest.TestCase):
    """Talks to a throwaway server on 127.0.0.1 only."""

    def setUp(self) -> None:
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def test_probe_reads_title_and_server(self) -> None:
        info = collectors.http_probe("127.0.0.1", self.port, timeout=3)
        self.assertEqual(info["title"], "Acme Printer 3000")
        self.assertEqual(info["server"], "Acme-httpd/1.0")

    def test_probe_many_only_touches_web_ports(self) -> None:
        collectors.WEB_PORTS[self.port] = False
        try:
            result = collectors.http_probe_many({"127.0.0.1": [self.port, 22]}, timeout=3)
        finally:
            collectors.WEB_PORTS.pop(self.port, None)
        self.assertEqual(list(result["127.0.0.1"]), [str(self.port)])

    def test_closed_port_returns_nothing(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.assertEqual(collectors.http_probe("127.0.0.1", self.port, timeout=1), {})
        # tearDown shuts down again; make that harmless
        self.server.shutdown = lambda: None  # type: ignore[method-assign]
        self.server.server_close = lambda: None  # type: ignore[method-assign]


@unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
class LiveTlsProbeTests(unittest.TestCase):
    """A real self-signed certificate on 127.0.0.1 must yield its subject names."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        key, cert = Path(self.tmp.name) / "k.pem", Path(self.tmp.name) / "c.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
             "-out", str(cert), "-days", "2", "-subj", "/O=Synology/CN=DiskStation"],
            check=True, capture_output=True,
        )
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        collectors.WEB_PORTS[self.port] = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        collectors.WEB_PORTS.pop(self.port, None)
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def test_certificate_names_are_extracted(self) -> None:
        info = collectors.http_probe("127.0.0.1", self.port, timeout=5)
        self.assertEqual(info["cert_cn"], "DiskStation")
        self.assertEqual(info["cert_org"], "Synology")
        self.assertEqual(fingerprint.identify(Device(ip="10.0.0.9", web={str(self.port): info})).kind, "nas")


class EngineFingerprintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "inventory.json")
        self.engine = ScanEngine(self.store, ScanOptions())

    def tearDown(self) -> None:
        self.engine.stop()
        self.tmp.cleanup()

    def scan(self, options: ScanOptions | None = None) -> None:
        started, message = self.engine.start(options)
        self.assertTrue(started, message)
        self.assertTrue(wait_until(lambda: not self.engine.running), self.engine.state_dict())

    def test_scan_records_web_fingerprint_and_reports_collector(self) -> None:
        with patched_scan():
            self.scan()
        router = self.store.devices["10.0.0.1"]
        self.assertEqual(router.web["80"]["title"], "Acme Router Login")
        self.assertIn("http", router.sources)
        state = self.engine.collectors_dict()["http"]
        self.assertEqual((state["status"], state["count"]), ("ok", 1))
        self.assertEqual(router.to_dict()["identity"]["kind"], "router")

    def test_http_probe_can_be_turned_off(self) -> None:
        with patched_scan() as _:
            options = ScanOptions.from_payload({"http": False})
            self.scan(options)
        self.assertEqual(self.engine.collectors_dict()["http"]["status"], "skipped")
        self.assertEqual(self.store.devices["10.0.0.1"].web, {})

    def test_ttl_from_ping_reaches_the_device(self) -> None:
        with patched_scan({"lanwatch.discovery.collectors.ttl_for": lambda ip: 128 if ip == "10.0.0.1" else None}):
            self.scan()
        self.assertEqual(self.store.devices["10.0.0.1"].ttl, 128)
        self.assertIsNone(self.store.devices["10.0.0.5"].ttl)

    def test_options_validation(self) -> None:
        with self.assertRaises(ValueError):
            ScanOptions.from_payload({"http": "yes"})
        self.assertTrue(ScanOptions().to_dict()["http"])


if __name__ == "__main__":
    unittest.main()
