"""Per-network inventories: identity, migration, switching and the API."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from lanwatch import netif, web
from lanwatch.discovery import ScanEngine, ScanOptions
from lanwatch.model import Device
from lanwatch.store import Store

from .helpers import patched_scan, wait_until

HEADERS = {"X-Lanwatch": "1"}


class StoreNetworkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "inventory.json"
        self.store = Store(self.path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_networks_do_not_share_devices(self) -> None:
        self.store.activate("192.168.1.0/24")
        self.store.upsert(Device(ip="192.168.1.1", online=True, is_gateway=True))
        self.store.activate("192.168.220.0/24")
        self.store.upsert(Device(ip="192.168.220.1", online=True, is_gateway=True))
        self.assertEqual(set(self.store.devices), {"192.168.220.1"})
        self.store.select("192.168.1.0/24")
        self.assertEqual(set(self.store.devices), {"192.168.1.1"})

    def test_same_cidr_different_gateway_mac_is_a_new_network(self) -> None:
        home = self.store.activate("192.168.1.0/24", "aa:aa:aa:aa:aa:01")
        self.store.upsert(Device(ip="192.168.1.2", online=True))
        office = self.store.activate("192.168.1.0/24", "bb:bb:bb:bb:bb:02")
        self.assertNotEqual(home.id, office.id)
        self.assertEqual(self.store.devices, {})
        again = self.store.activate("192.168.1.0/24", "aa:aa:aa:aa:aa:01")
        self.assertEqual(again.id, home.id)
        self.assertIn("192.168.1.2", self.store.devices)

    def test_first_gateway_mac_is_adopted_by_a_macless_record(self) -> None:
        legacy = self.store.activate("10.0.0.0/24")
        adopted = self.store.activate("10.0.0.0/24", "cc:cc:cc:cc:cc:03")
        self.assertEqual(legacy.id, adopted.id)
        self.assertEqual(adopted.gateway_mac, "cc:cc:cc:cc:cc:03")

    def test_set_network_adopts_the_placeholder(self) -> None:
        self.store.upsert(Device(ip="10.0.0.1", online=True))
        self.store.set_network({"cidr": "10.0.0.0/24", "gateway": "10.0.0.1"})
        self.assertEqual(self.store.active_id, "10.0.0.0/24")
        self.assertIn("10.0.0.1", self.store.devices)

    def test_persistence_round_trip_keeps_every_network(self) -> None:
        self.store.activate("192.168.1.0/24")
        self.store.upsert(Device(ip="192.168.1.1", online=True))
        self.store.set_network({"cidr": "192.168.1.0/24"})
        self.store.activate("192.168.220.0/24", "dd:dd:dd:dd:dd:04")
        self.store.upsert(Device(ip="192.168.220.1", online=True))
        self.store.set_network({"cidr": "192.168.220.0/24", "gateway": "192.168.220.1"})
        self.assertTrue(self.store.save())

        reloaded = Store(self.path)
        self.assertEqual(len(reloaded.networks), 2)
        self.assertEqual(reloaded.active_id, "192.168.220.0/24")
        self.assertEqual(reloaded.active.gateway_mac, "dd:dd:dd:dd:dd:04")
        self.assertEqual(set(reloaded.devices), {"192.168.220.1"})

    def test_empty_networks_are_not_persisted(self) -> None:
        self.store.activate("172.16.0.0/24")
        self.store.save()
        self.assertEqual(Store(self.path).networks, {})

    def test_legacy_flat_inventory_is_split_by_subnet(self) -> None:
        legacy = {
            "version": 1,
            "network": {"cidr": "192.168.220.0/24", "interface": "wlan0", "gateway": "192.168.220.1"},
            "devices": [
                Device(ip="192.168.1.1", is_gateway=True).to_dict(),
                Device(ip="192.168.1.4").to_dict(),
                Device(ip="192.168.220.1", is_gateway=True).to_dict(),
                Device(ip="192.168.220.2", is_self=True).to_dict(),
            ],
        }
        self.path.write_text(json.dumps(legacy), encoding="utf-8")
        store = Store(self.path)
        self.assertEqual(set(store.networks), {"192.168.1.0/24", "192.168.220.0/24"})
        self.assertEqual(store.active_id, "192.168.220.0/24")
        self.assertEqual(set(store.devices), {"192.168.220.1", "192.168.220.2"})
        self.assertEqual(store.network["interface"], "wlan0")
        # exactly one gateway badge per network
        for record in store.networks.values():
            self.assertEqual(sum(d.is_gateway for d in record.devices.values()), 1)

    def test_archive_and_delete_rules(self) -> None:
        old = self.store.activate("192.168.1.0/24")
        self.store.upsert(Device(ip="192.168.1.1", online=True))
        self.store.activate("192.168.2.0/24")
        self.store.archive(old.id)
        self.assertTrue(self.store.networks[old.id].archived)
        with self.assertRaises(ValueError):
            self.store.archive(self.store.active_id)
        with self.assertRaises(ValueError):
            self.store.delete_network(self.store.active_id)
        self.assertTrue(self.store.delete_network(old.id))
        self.assertFalse(self.store.delete_network(old.id))

    def test_selecting_an_archived_network_unarchives_it(self) -> None:
        old = self.store.activate("192.168.1.0/24")
        self.store.activate("192.168.2.0/24")
        self.store.archive(old.id)
        self.store.select(old.id)
        self.assertFalse(self.store.networks[old.id].archived)

    def test_rename_and_summary_order(self) -> None:
        home = self.store.activate("192.168.1.0/24")
        self.store.upsert(Device(ip="192.168.1.1", online=True))
        self.store.rename_network(home.id, "  Home Wi-Fi  ")
        self.store.activate("192.168.2.0/24")
        self.store.upsert(Device(ip="192.168.2.1", online=True))
        rows = self.store.networks_summary()
        self.assertEqual(rows[0]["cidr"], "192.168.2.0/24")  # active first
        self.assertTrue(rows[0]["active"])
        self.assertEqual(rows[1]["title"], "Home Wi-Fi")


class RouteParsingTests(unittest.TestCase):
    def test_proc_route_default_gateway(self) -> None:
        text = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\n"
            "wlan0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
        )
        self.assertEqual(netif._gateways_from_proc_route(text), ["192.168.1.1"])

    def test_ip_route_default_gateway(self) -> None:
        text = "default via 10.1.2.1 dev wlan0 proto dhcp metric 600\n"
        self.assertEqual(netif._gateways_from_ip_route(text), ["10.1.2.1"])

    def test_gateway_outside_network_is_ignored(self) -> None:
        import ipaddress

        with mock.patch.object(netif, "_gateways_from_proc_route", return_value=["10.9.9.1"]), mock.patch(
            "builtins.open", mock.mock_open(read_data="x")
        ):
            self.assertIsNone(netif.default_gateway(ipaddress.ip_network("192.168.1.0/24")))


class EngineNetworkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "inventory.json")
        self.engine = ScanEngine(self.store, ScanOptions())

    def tearDown(self) -> None:
        self.engine.stop()
        self.tmp.cleanup()

    def scan(self) -> None:
        started, message = self.engine.start()
        self.assertTrue(started, message)
        self.assertTrue(wait_until(lambda: not self.engine.running), self.engine.state_dict())

    def test_scan_creates_and_activates_its_network(self) -> None:
        with patched_scan():
            self.scan()
        self.assertEqual(self.store.active_id, "10.0.0.0/24")
        self.assertEqual(self.store.networks_summary()[0]["devices"], 4)
        self.assertEqual(self.store.network["network_id"], "10.0.0.0/24")

    def test_scan_marks_only_the_real_gateway(self) -> None:
        self.store.activate("10.0.0.0/24")
        self.store.upsert(Device(ip="10.0.0.2", online=True, is_gateway=True))
        with patched_scan():
            self.scan()
        gateways = [ip for ip, d in self.store.devices.items() if d.is_gateway]
        self.assertEqual(gateways, ["10.0.0.1"])

    def test_switching_is_refused_during_a_scan(self) -> None:
        self.store.activate("192.168.7.0/24")
        self.store.upsert(Device(ip="192.168.7.1", online=True))
        with self.engine._lock:
            self.engine.state["running"] = True
        ok, message = self.engine.select_network("192.168.7.0/24")
        self.assertFalse(ok)
        self.assertIn("scan", message)

    def test_startup_selects_a_known_current_network(self) -> None:
        iface = netif.Interface(
            name="wlan0", address="192.168.220.2", netmask="255.255.255.0",
            flags=netif.IFF_UP | netif.IFF_BROADCAST,
        )
        self.store.activate("192.168.1.0/24")
        self.store.upsert(Device(ip="192.168.1.1", online=True))
        self.store.activate("192.168.220.0/24")
        self.store.upsert(Device(ip="192.168.220.1", online=True))
        self.store.select("192.168.1.0/24")
        with mock.patch("lanwatch.discovery.netif.detect_interfaces", return_value=[iface]), mock.patch(
            "lanwatch.discovery.netif.default_gateway", return_value=None
        ):
            engine = ScanEngine(self.store, ScanOptions())
        self.assertEqual(engine.store.active_id, "192.168.220.0/24")

    def test_startup_does_not_create_unknown_networks(self) -> None:
        iface = netif.Interface(
            name="wlan0", address="172.20.0.2", netmask="255.255.255.0",
            flags=netif.IFF_UP | netif.IFF_BROADCAST,
        )
        with mock.patch("lanwatch.discovery.netif.detect_interfaces", return_value=[iface]):
            ScanEngine(self.store, ScanOptions())
        self.assertEqual(self.store.networks, {})


class NetworkApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "inventory.json")
        self.store.activate("192.168.1.0/24")
        self.store.upsert(Device(ip="192.168.1.1", online=True))
        self.store.activate("192.168.2.0/24")
        self.store.upsert(Device(ip="192.168.2.1", online=True))
        # Keep the suite independent of the host's real Wi-Fi subnet.
        with mock.patch("lanwatch.discovery.netif.detect_interfaces", return_value=[]):
            self.engine = ScanEngine(self.store, ScanOptions())
        self.server = web.DashboardServer(("127.0.0.1", 0), self.engine)
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def call(self, path: str, payload: object = None) -> tuple[int, dict]:
        data = None if payload is None else json.dumps(payload).encode()
        headers = dict(HEADERS)
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base + path, data=data, method="GET" if payload is None else "POST", headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            body = json.loads(error.read())
            error.close()
            return error.code, body

    def test_state_lists_networks_and_the_active_one(self) -> None:
        status, body = self.call("/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(body["active_network"]["cidr"], "192.168.2.0/24")
        self.assertEqual({n["cidr"] for n in body["networks"]}, {"192.168.1.0/24", "192.168.2.0/24"})
        self.assertEqual([d["ip"] for d in body["devices"]], ["192.168.2.1"])

    def test_select_switches_inventory(self) -> None:
        status, _ = self.call("/api/network/select", {"id": "192.168.1.0/24"})
        self.assertEqual(status, 200)
        _, body = self.call("/api/state")
        self.assertEqual([d["ip"] for d in body["devices"]], ["192.168.1.1"])

    def test_unknown_network_is_404(self) -> None:
        status, _ = self.call("/api/network/select", {"id": "nope"})
        self.assertEqual(status, 404)

    def test_archive_active_network_is_conflict(self) -> None:
        status, body = self.call("/api/network/archive", {"id": "192.168.2.0/24"})
        self.assertEqual(status, 409)
        self.assertIn("active", body["error"])

    def test_rename_archive_delete(self) -> None:
        self.assertEqual(self.call("/api/network/rename", {"id": "192.168.1.0/24", "label": "Home"})[0], 200)
        self.assertEqual(self.call("/api/network/archive", {"id": "192.168.1.0/24"})[0], 200)
        _, listing = self.call("/api/networks")
        home = next(n for n in listing["networks"] if n["cidr"] == "192.168.1.0/24")
        self.assertEqual((home["title"], home["archived"]), ("Home", True))
        self.assertEqual(self.call("/api/network/delete", {"id": "192.168.1.0/24"})[0], 200)

    def test_validation_errors(self) -> None:
        self.assertEqual(self.call("/api/network/select", {})[0], 400)
        self.assertEqual(self.call("/api/network/archive", {"id": "x", "archived": "yes"})[0], 400)

    def test_post_requires_client_header(self) -> None:
        request = urllib.request.Request(
            self.base + "/api/network/select",
            data=b'{"id":"192.168.1.0/24"}',
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(caught.exception.code, 403)
        caught.exception.close()


if __name__ == "__main__":
    unittest.main()
