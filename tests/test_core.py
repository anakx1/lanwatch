"""Tests for the data model, interface maths, OUI lookup and DNS codec."""

from __future__ import annotations

import ipaddress
import socket
import struct
import unittest

from lanwatch import dnsparse, netif, oui
from lanwatch.model import Device, ip_sort_key, normalize_ip


class ModelTests(unittest.TestCase):
    def test_normalize_ip(self) -> None:
        self.assertEqual(normalize_ip(" 192.168.1.5 "), "192.168.1.5")
        with self.assertRaises(ValueError):
            normalize_ip("not-an-ip")
        with self.assertRaises(ValueError):
            normalize_ip("::1")

    def test_hostname_priority(self) -> None:
        device = Device(ip="10.0.0.1")
        self.assertTrue(device.offer_hostname("router.lan", "rdns"))
        self.assertTrue(device.offer_hostname("ROUTER", "nbns"))
        # Reverse DNS must not overwrite a NetBIOS name.
        self.assertFalse(device.offer_hostname("old.lan", "rdns"))
        self.assertEqual(device.hostname, "ROUTER")
        # mDNS outranks everything.
        self.assertTrue(device.offer_hostname("printer.local", "mdns"))
        self.assertEqual(device.hostname, "printer.local")
        self.assertEqual(device.hostname_source, "mdns")

    def test_merge_keeps_first_mac_and_unions_ports(self) -> None:
        device = Device(ip="10.0.0.2", mac="3c:22:fb:11:22:33", ports=[80])
        other = Device(ip="10.0.0.2", mac="ff:ff:ff:ff:ff:ff", ports=[443, 80], online=True)
        device.merge(other)
        self.assertEqual(device.mac, "3c:22:fb:11:22:33")
        self.assertEqual(device.ports, [80, 443])
        self.assertTrue(device.online)

    def test_display_name_and_kind(self) -> None:
        self.assertEqual(Device(ip="10.0.0.1").display_name, "Unknown device")
        self.assertEqual(Device(ip="10.0.0.1", label="TV").display_name, "TV")
        self.assertEqual(Device(ip="10.0.0.1", is_gateway=True).guess_kind(), "router")
        self.assertEqual(Device(ip="10.0.0.1", ports=[631]).guess_kind(), "printer")
        self.assertEqual(Device(ip="10.0.0.1", is_self=True).guess_kind(), "self")
        self.assertEqual(
            Device(ip="10.0.0.1", mdns_services=["_googlecast._tcp"]).guess_kind(), "tv"
        )

    def test_round_trip(self) -> None:
        device = Device(
            ip="10.0.0.9",
            mac="3c:22:fb:11:22:33",
            hostname="tv.local",
            hostname_source="mdns",
            ports=[80, 443],
            notes="living room",
            online=True,
            ssdp={"friendlyName": "TV"},
        )
        again = Device.from_dict(device.to_dict())
        self.assertEqual(again.ip, device.ip)
        self.assertEqual(again.ports, [80, 443])
        self.assertEqual(again.ssdp, {"friendlyName": "TV"})
        self.assertEqual(again.display_name, "tv.local")

    def test_ip_sort_key(self) -> None:
        addresses = ["10.0.0.10", "10.0.0.2", "10.0.0.1"]
        self.assertEqual(sorted(addresses, key=ip_sort_key), ["10.0.0.1", "10.0.0.2", "10.0.0.10"])


class NetifTests(unittest.TestCase):
    IFACES = [
        netif.Interface("lo", "127.0.0.1", "255.0.0.0", netif.IFF_UP | netif.IFF_LOOPBACK),
        netif.Interface(
            "wlan0", "192.168.1.9", "255.255.255.0", netif.IFF_UP | netif.IFF_BROADCAST
        ),
        netif.Interface("rmnet1", "192.0.0.4", "255.255.255.255", netif.IFF_UP | netif.IFF_POINTOPOINT),
    ]

    def test_host_capacity(self) -> None:
        self.assertEqual(netif.host_capacity(ipaddress.ip_network("10.0.0.0/24")), 254)
        self.assertEqual(netif.host_capacity(ipaddress.ip_network("10.0.0.0/30")), 2)
        self.assertEqual(netif.host_capacity(ipaddress.ip_network("10.0.0.0/31")), 2)

    def test_choose_interface_skips_loopback_and_cellular(self) -> None:
        chosen = netif.choose_interface(self.IFACES)
        self.assertEqual(chosen.name, "wlan0")

    def test_usable(self) -> None:
        self.assertFalse(netif.usable(self.IFACES[0]))
        self.assertFalse(netif.usable(self.IFACES[2]))
        self.assertTrue(netif.usable(self.IFACES[1]))

    def test_parse_ifconfig(self) -> None:
        text = """
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.9  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>
"""
        parsed = netif.parse_ifconfig(text)
        self.assertEqual([iface.name for iface in parsed], ["lo", "wlan0"])
        self.assertEqual(parsed[1].cidr, "192.168.1.0/24")
        self.assertEqual(parsed[1].address, "192.168.1.9")

    def test_resolve_cidr(self) -> None:
        network, iface, hosts = netif.resolve_target("10.0.0.0/30", interfaces=[])
        self.assertEqual(str(network), "10.0.0.0/30")
        self.assertIsNone(iface)
        self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2"])

    def test_resolve_interface_name(self) -> None:
        network, iface, hosts = netif.resolve_target("wlan0", interfaces=self.IFACES)
        self.assertEqual(str(network), "192.168.1.0/24")
        self.assertEqual(iface.name, "wlan0")
        self.assertEqual(len(hosts), 254)

    def test_resolve_bare_address_assumes_slash_24(self) -> None:
        network, _, hosts = netif.resolve_target("10.1.2.3", interfaces=[])
        self.assertEqual(str(network), "10.1.2.0/24")
        self.assertEqual(len(hosts), 254)

    def test_resolve_rejects_large_and_invalid(self) -> None:
        with self.assertRaises(netif.SubnetTooLarge):
            netif.resolve_target("10.0.0.0/8", interfaces=[], max_hosts=1024)
        with self.assertRaises(netif.InterfaceError):
            netif.resolve_target("bogus/24", interfaces=[])
        with self.assertRaises(netif.InterfaceError):
            netif.resolve_target("nosuchiface", interfaces=self.IFACES)

    def test_guess_gateway(self) -> None:
        network = ipaddress.ip_network("10.0.0.0/24")
        self.assertEqual(netif.guess_gateway(network, {"10.0.0.1", "10.0.0.9"}), "10.0.0.1")
        self.assertEqual(netif.guess_gateway(network, {"10.0.0.9"}), "10.0.0.9")
        self.assertEqual(netif.guess_gateway(network, set()), "10.0.0.1")


class OuiTests(unittest.TestCase):
    def test_normalize(self) -> None:
        self.assertEqual(oui.normalize_mac("3C:22:FB:11:22:33"), "3c:22:fb:11:22:33")
        self.assertEqual(oui.normalize_mac("3c22.fb11.2233"), "3c:22:fb:11:22:33")
        self.assertEqual(oui.normalize_mac("3c-22-fb-11-22-33"), "3c:22:fb:11:22:33")
        self.assertIsNone(oui.normalize_mac("nope"))
        self.assertIsNone(oui.normalize_mac("00:00:00:00:00:00"))

    def test_local_bit(self) -> None:
        self.assertTrue(oui.is_locally_administered("02:11:22:33:44:55"))
        self.assertFalse(oui.is_locally_administered("3c:22:fb:11:22:33"))

    def test_vendor_lookup(self) -> None:
        vendor = oui.vendor_for("3C:22:FB:11:22:33")
        self.assertIsNotNone(vendor)
        self.assertIn("apple", (vendor or "").lower())
        self.assertEqual(oui.vendor_for("02:11:22:33:44:55"), "Locally administered")
        self.assertIsNone(oui.vendor_for(None))

    def test_parse_nmap_format(self) -> None:
        parsed = oui._parse_oui_text("00000C  Cisco Systems, Inc\n# comment\nBADLINE\n")
        self.assertEqual(parsed["00000C"], "Cisco Systems, Inc")

    def test_parse_ieee_format(self) -> None:
        parsed = oui._parse_oui_text("00-00-0C   (hex)        Cisco Systems, Inc\n")
        self.assertEqual(parsed["00000C"], "Cisco Systems, Inc")


def _name(text: str) -> bytes:
    out = bytearray()
    for label in text.split("."):
        out.append(len(label))
        out.extend(label.encode())
    out.append(0)
    return bytes(out)


def _record(name: bytes, rtype: int, rdata: bytes, ttl: int = 120) -> bytes:
    return name + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata


class DnsTests(unittest.TestCase):
    def build_packet(self) -> bytes:
        question = _name("Living Room._airplay._tcp.local") + struct.pack(">HH", 12, 1)
        instance = b"\xc0\x0c"  # pointer to the question name
        strings = [b"model=AppleTV", b"fn=Living Room"]
        txt_data = b"".join(bytes([len(item)]) + item for item in strings)
        answers = (
            _record(instance, 12, _name("TV._airplay._tcp.local"))
            + _record(instance, 33, struct.pack(">HHH", 0, 0, 7000) + _name("tv.local"))
            + _record(instance, 16, txt_data)
        )
        additional = _record(_name("tv.local"), 1, socket.inet_aton("10.0.0.9"))
        header = struct.pack(">HHHHHH", 0x1234, 0x8400, 1, 3, 0, 1)
        return header + question + answers + additional

    def test_parse_response(self) -> None:
        message = dnsparse.parse_message(self.build_packet())
        self.assertTrue(message.is_response)
        self.assertEqual(message.questions[0][0], "Living Room._airplay._tcp.local")
        self.assertEqual(len(message.answers), 3)
        self.assertEqual(message.answers[0].data, "TV._airplay._tcp.local")
        self.assertEqual(message.answers[1].data["port"], 7000)
        self.assertEqual(message.answers[1].data["target"], "tv.local")
        self.assertEqual(dnsparse.txt_dict(message.answers[2])["model"], "AppleTV")
        self.assertEqual(message.additional[0].data, "10.0.0.9")

    def test_bad_packets_raise(self) -> None:
        with self.assertRaises(dnsparse.DnsError):
            dnsparse.parse_message(b"\x00" * 8)
        packet = self.build_packet()
        with self.assertRaises(dnsparse.DnsError):
            dnsparse.parse_message(packet[: len(packet) // 2])

    def test_encode_query_unicast_bit(self) -> None:
        packet = dnsparse.encode_query("_http._tcp.local", unicast=True)
        self.assertEqual(struct.unpack(">H", packet[-2:])[0], 0x8001)
        message = dnsparse.parse_message(packet)
        self.assertEqual(message.questions[0][0], "_http._tcp.local")
        self.assertEqual(message.questions[0][1], dnsparse.TYPE_PTR)

    def test_service_type_and_instance(self) -> None:
        self.assertEqual(dnsparse.service_type("TV._airplay._tcp.local"), "_airplay._tcp")
        self.assertEqual(dnsparse.instance_name("TV._airplay._tcp.local"), "TV")
        self.assertIsNone(dnsparse.service_type("plain.host.local"))


if __name__ == "__main__":
    unittest.main()
