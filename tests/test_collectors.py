"""Tests for the collector parsers and bounded helpers."""

from __future__ import annotations

import struct
import time
import unittest

from lanwatch import collectors


class ArpParsingTests(unittest.TestCase):
    def test_ip_neigh(self) -> None:
        text = (
            "10.0.0.1 dev wlan0 lladdr 3C:22:FB:11:22:33 REACHABLE\n"
            "10.0.0.2 dev wlan0 FAILED\n"
            "fe80::1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff router\n"
        )
        self.assertEqual(collectors._parse_ip_neigh(text), {"10.0.0.1": "3c:22:fb:11:22:33"})

    def test_arp_an(self) -> None:
        text = (
            "? (10.0.0.1) at 3c:22:fb:11:22:33 [ether] on wlan0\n"
            "? (10.0.0.2) at <incomplete> on wlan0\n"
        )
        self.assertEqual(collectors._parse_arp_output(text), {"10.0.0.1": "3c:22:fb:11:22:33"})


class NbnsTests(unittest.TestCase):
    def build_nbstat(self) -> bytes:
        question = b"\x20CK" + b"A" * 30 + b"\x00" + struct.pack(">HH", 0x21, 1)
        names = [
            (b"DESKTOP-ABC    ", 0x0400),
            (b"WORKGROUP      ", 0x8400),
        ]
        rdata = bytes([len(names)])
        for label, flags in names:
            rdata += label + struct.pack(">H", flags)
        answer = (
            b"\xc0\x0c"
            + struct.pack(">HHIH", 0x21, 1, 0, len(rdata))
            + rdata
        )
        header = struct.pack(">HHHHHH", 0x4C57, 0x8400, 1, 1, 0, 0)
        return header + question + answer

    def test_parse_nbstat(self) -> None:
        self.assertEqual(collectors.parse_nbstat(self.build_nbstat()), "DESKTOP-ABC")

    def test_malformed_nbstat(self) -> None:
        self.assertIsNone(collectors.parse_nbstat(b""))
        self.assertIsNone(collectors.parse_nbstat(b"\x00" * 20))

    def test_query_packet(self) -> None:
        packet = collectors.nbns_query_packet()
        self.assertEqual(len(packet), 12 + 34 + 4)
        self.assertEqual(packet[12], 0x20)


class SsdpParsingTests(unittest.TestCase):
    RESPONSE = (
        b"HTTP/1.1 200 OK\r\n"
        b"CACHE-CONTROL: max-age=1800\r\n"
        b"LOCATION: http://10.0.0.1:80/desc.xml\r\n"
        b"SERVER: Linux/5.0 UPnP/1.1\r\n"
        b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
        b"USN: uuid:abc::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
        b"\r\n"
    )

    def test_parse(self) -> None:
        entry = collectors._parse_ssdp_response(self.RESPONSE, "10.0.0.1")
        assert entry is not None
        self.assertEqual(entry["ip"], "10.0.0.1")
        self.assertEqual(entry["location"], "http://10.0.0.1:80/desc.xml")
        self.assertIn("InternetGatewayDevice", entry["st"])

    def test_reject_non_200(self) -> None:
        self.assertIsNone(collectors._parse_ssdp_response(b"HTTP/1.1 404 Not Found\r\n\r\n", "10.0.0.1"))


class BoundedTests(unittest.TestCase):
    def test_results(self) -> None:
        result = collectors.run_bounded(lambda value: value.upper(), ["a", "b"], timeout=2)
        self.assertEqual(result, {"a": "A", "b": "B"})

    def test_timeout_does_not_block(self) -> None:
        def slow(value: str) -> str:
            time.sleep(1.0)
            return value

        started = time.monotonic()
        result = collectors.run_bounded(slow, ["a"], timeout=0.15)
        self.assertEqual(result, {})
        self.assertLess(time.monotonic() - started, 0.9)


class PortTests(unittest.TestCase):
    def test_probe_local_listener(self) -> None:
        import socket

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            self.assertTrue(collectors.probe_port("127.0.0.1", port, timeout=0.5))
            self.assertFalse(collectors.probe_port("127.0.0.1", 1, timeout=0.05))
            self.assertEqual(
                collectors.scan_ports(["127.0.0.1"], [port], timeout=0.5).get("127.0.0.1"),
                [port],
            )
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
