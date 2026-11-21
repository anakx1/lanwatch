"""Tests for options, persistence, the scan engine and its event bus."""

from __future__ import annotations

import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from lanwatch import collectors, netif
from lanwatch.discovery import EventBus, ScanEngine, ScanOptions
from lanwatch.model import Device
from lanwatch.store import Store

from .helpers import patched_scan, wait_until


class OptionsTests(unittest.TestCase):
    def test_defaults(self) -> None:
        options = ScanOptions()
        self.assertIsNone(options.subnet)
        self.assertEqual(options.ports, collectors.DEFAULT_PORTS)
        self.assertTrue(options.mdns and options.ssdp and options.nbns and options.rdns)

    def test_ports_parsing(self) -> None:
        options = ScanOptions.from_payload({"ports": "22, 80, 80"})
        self.assertEqual(options.ports, [22, 80])
        self.assertEqual(ScanOptions.from_payload({"ports": []}).ports, collectors.DEFAULT_PORTS)
        self.assertEqual(ScanOptions.from_payload({"ports": ""}).ports, collectors.DEFAULT_PORTS)
        with self.assertRaises(ValueError):
            ScanOptions.from_payload({"ports": "ssh"})
        with self.assertRaises(ValueError):
            ScanOptions.from_payload({"ports": [0, 70000]})

    def test_validation(self) -> None:
        with self.assertRaises(ValueError):
            ScanOptions.from_payload({"concurrency": 0})
        with self.assertRaises(ValueError):
            ScanOptions.from_payload({"timeout": 0.01})
        with self.assertRaises(ValueError):
            ScanOptions.from_payload({"deep": "yes"})
        with self.assertRaises(ValueError):
            ScanOptions.from_payload({"subnet": 42})
        options = ScanOptions.from_payload({"subnet": "10.0.0.0/24", "deep": True})
        self.assertEqual(options.subnet, "10.0.0.0/24")
        self.assertTrue(options.deep)

    def test_base_is_copied(self) -> None:
        base = ScanOptions(subnet="192.168.1.0/24", ports=[80], rdns=False)
        options = ScanOptions.from_payload({"deep": True}, base)
        self.assertEqual(options.subnet, "192.168.1.0/24")
        self.assertEqual(options.ports, [80])
        self.assertFalse(options.rdns)
        self.assertTrue(options.deep)


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "inventory.json"
        self.store = Store(self.path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_round_trip(self) -> None:
        self.store.upsert(
            Device(ip="10.0.0.1", mac="3c:22:fb:11:22:33", ports=[80], online=True, sources=["icmp"])
        )
        self.store.set_network({"cidr": "10.0.0.0/24", "interface": "wlan0"})
        self.assertTrue(self.store.save())

        reloaded = Store(self.path)
        device = reloaded.devices["10.0.0.1"]
        self.assertEqual(device.ports, [80])
        self.assertTrue(device.online)
        self.assertEqual(reloaded.network["cidr"], "10.0.0.0/24")
        self.assertIsNone(reloaded.load_error)

    def test_seen_count_dedupes_per_scan(self) -> None:
        self.store.begin_scan()
        self.store.upsert(Device(ip="10.0.0.1", online=True))
        self.store.upsert(Device(ip="10.0.0.1", online=True, ports=[80]))
        self.assertEqual(self.store.devices["10.0.0.1"].seen_count, 1)
        self.store.begin_scan()
        self.store.upsert(Device(ip="10.0.0.1", online=True))
        self.assertEqual(self.store.devices["10.0.0.1"].seen_count, 2)

    def test_mark_offline_scoped_to_subnet(self) -> None:
        self.store.upsert(Device(ip="10.0.0.1", online=True))
        self.store.upsert(Device(ip="10.0.0.2", online=True))
        self.store.upsert(Device(ip="192.168.1.5", online=True))
        changed = self.store.mark_offline({"10.0.0.1"}, "10.0.0.0/24")
        self.assertEqual([device.ip for device in changed], ["10.0.0.2"])
        self.assertTrue(self.store.devices["192.168.1.5"].online)

    def test_user_fields(self) -> None:
        self.store.upsert(Device(ip="10.0.0.1", online=True))
        device = self.store.set_user_fields("10.0.0.1", "  Living Room TV  ", " note ")
        assert device is not None
        self.assertEqual(device.label, "Living Room TV")
        self.assertEqual(device.notes, "note")
        self.assertEqual(device.display_name, "Living Room TV")
        self.assertIsNone(self.store.set_user_fields("10.0.0.2", "x", None))

    def test_forget(self) -> None:
        self.store.upsert(Device(ip="10.0.0.1", online=True))
        self.assertTrue(self.store.forget("10.0.0.1"))
        self.assertFalse(self.store.forget("10.0.0.1"))

    def test_export_csv(self) -> None:
        self.store.upsert(Device(ip="10.0.0.1", online=True, ports=[80], sources=["icmp"]))
        text = self.store.export_csv(self.store.devices_sorted())
        self.assertIn("ip,name,hostname", text)
        self.assertIn("10.0.0.1", text)

    def test_corrupt_snapshot_is_tolerated(self) -> None:
        self.path.write_text("{ not json", encoding="utf-8")
        store = Store(self.path)
        self.assertEqual(store.devices, {})
        self.assertIsNotNone(store.load_error)

    def test_export_json_shape(self) -> None:
        self.store.upsert(Device(ip="10.0.0.1", online=True))
        payload = self.store.export_json()
        self.assertIn("devices", payload)
        self.assertIn("exported_at", payload)
        json.dumps(payload)  # must be serialisable


class EventBusTests(unittest.TestCase):
    def test_fanout_and_drop_oldest(self) -> None:
        bus = EventBus()
        channel = bus.subscribe(maxsize=2)
        bus.publish({"type": "a"})
        bus.publish({"type": "b"})
        bus.publish({"type": "c"})
        self.assertEqual(channel.get_nowait()["type"], "b")
        self.assertEqual(channel.get_nowait()["type"], "c")
        bus.unsubscribe(channel)
        bus.publish({"type": "d"})
        self.assertTrue(channel.empty())


class EngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "inventory.json")
        self.engine = ScanEngine(self.store, ScanOptions())
        self.context = patched_scan()
        self.context.__enter__()

    def tearDown(self) -> None:
        self.engine.stop()
        self.context.__exit__(None, None, None)
        self.tmp.cleanup()

    def run_scan(self) -> None:
        started, message = self.engine.start()
        self.assertTrue(started, message)
        self.assertTrue(
            wait_until(lambda: not self.engine.running and self.engine.state_dict()["phase"] == "done"),
            self.engine.state_dict(),
        )

    def test_full_scan_merges_every_source(self) -> None:
        self.run_scan()
        devices = self.store.devices

        self.assertEqual(set(devices), {"10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.9"})

        router = devices["10.0.0.1"]
        self.assertEqual(router.hostname, "ROUTER")  # NetBIOS outranks PTR
        self.assertEqual(router.hostname_source, "nbns")
        self.assertEqual(router.ports, [80, 443])
        self.assertTrue(router.is_gateway)
        self.assertTrue(router.online)

        printer = devices["10.0.0.2"]
        self.assertEqual(printer.mac, "3c:22:fb:11:22:33")
        self.assertIsNotNone(printer.vendor)
        self.assertEqual(printer.hostname, "printer")  # mDNS outranks nothing else
        self.assertIn("_ipp._tcp", printer.mdns_services)
        self.assertEqual(printer.ssdp.get("model"), "Brother HL-2270DW")
        self.assertEqual(printer.guess_kind(), "printer")

        self.assertTrue(devices["10.0.0.5"].is_self)
        self.assertEqual(devices["10.0.0.5"].ports, [8080])

        television = devices["10.0.0.9"]
        self.assertTrue(television.online)
        self.assertEqual(television.ssdp.get("friendlyName"), "Living Room TV")
        self.assertEqual(television.guess_kind(), "media")

        collectors_state = self.engine.collectors_dict()
        self.assertEqual(collectors_state["icmp"]["status"], "ok")
        self.assertEqual(collectors_state["icmp"]["count"], 2)
        self.assertEqual(collectors_state["arp"]["count"], 1)  # only in-subnet entry
        self.assertEqual(collectors_state["tcp"]["count"], 3)
        self.assertEqual(collectors_state["mdns"]["count"], 1)
        self.assertEqual(collectors_state["ssdp"]["count"], 1)
        self.assertEqual(collectors_state["nbns"]["count"], 1)
        self.assertEqual(collectors_state["rdns"]["count"], 1)

        network = self.store.network
        assert network is not None
        self.assertEqual(network["cidr"], "10.0.0.0/24")
        self.assertEqual(network["gateway"], "10.0.0.1")

    def test_unseen_devices_go_offline(self) -> None:
        self.store.upsert(Device(ip="10.0.0.77", online=True))
        self.run_scan()
        self.assertFalse(self.store.devices["10.0.0.77"].online)

    def test_events_are_published(self) -> None:
        channel = self.engine.bus.subscribe()
        self.run_scan()
        kinds = set()
        while not channel.empty():
            kinds.add(channel.get_nowait()["type"])
        self.assertIn("scan.started", kinds)
        self.assertIn("device", kinds)
        self.assertIn("collector", kinds)
        self.assertIn("scan.finished", kinds)

    def test_scan_is_recorded_in_history(self) -> None:
        self.run_scan()
        scans = self.engine.history.recent(5)
        self.assertEqual(len(scans), 1)
        scan = scans[0]
        self.assertEqual(scan["subnet"], "10.0.0.0/24")
        self.assertEqual(scan["devices_found"], 4)
        self.assertEqual(scan["hosts_up"], 2)
        self.assertFalse(scan["stopped"])
        self.assertIsNone(scan["error"])

        visits = self.engine.history.device_history("10.0.0.1")
        self.assertEqual(len(visits), 1)
        self.assertEqual(visits[0]["name"], "ROUTER")
        self.assertEqual(visits[0]["ports"], [80, 443])
        self.assertEqual(visits[0]["latency_ms"], 3.0)

    def test_stopped_scan_is_recorded(self) -> None:
        def stop_sweep(
            hosts: list[str],
            timeout: float,
            concurrency: int,
            on_up: object,
            cancel: object,
            on_result: object,
        ) -> dict[str, float]:
            assert hasattr(cancel, "set")
            cancel.set()  # type: ignore[attr-defined]
            return {}

        extra = {
            "lanwatch.discovery.collectors.ping_sweep": unittest.mock.Mock(
                side_effect=stop_sweep
            )
        }
        with patched_scan(extra):
            started, message = self.engine.start()
            self.assertTrue(started, message)
            self.assertTrue(wait_until(lambda: not self.engine.running))

        scans = self.engine.history.recent(5)
        self.assertEqual(len(scans), 1)
        self.assertTrue(scans[0]["stopped"])

    def test_history_write_failure_does_not_break_scan(self) -> None:
        self.engine.history = unittest.mock.Mock()
        self.engine.history.record_scan.side_effect = OSError("disk full")
        self.run_scan()
        self.assertEqual(self.engine.state_dict()["phase"], "done")
        self.assertIn("disk full", self.engine.history_error or "")
        self.assertTrue(self.store.devices["10.0.0.1"].online)

    def test_probe_device_toggles_online(self) -> None:
        self.store.upsert(Device(ip="10.0.0.1", online=True))
        with unittest.mock.patch(
            "lanwatch.discovery.collectors.ping_host", return_value=12.5
        ), unittest.mock.patch(
            "lanwatch.discovery.collectors.scan_ports", return_value={"10.0.0.1": [22]}
        ):
            device = self.engine.probe_device("10.0.0.1")
        self.assertTrue(device["online"])
        self.assertEqual(device["ports"], [22])

        with unittest.mock.patch(
            "lanwatch.discovery.collectors.ping_host", return_value=None
        ), unittest.mock.patch("lanwatch.discovery.collectors.scan_ports", return_value={}):
            device = self.engine.probe_device("10.0.0.1")
        self.assertFalse(device["online"])

    def test_bad_subnet_reports_error(self) -> None:
        with unittest.mock.patch(
            "lanwatch.discovery.netif.resolve_target",
            side_effect=netif.InterfaceError("no LAN"),
        ):
            started, _ = self.engine.start()
            self.assertTrue(started)
            self.assertTrue(wait_until(lambda: not self.engine.running))
        state = self.engine.state_dict()
        self.assertEqual(state["phase"], "error")
        self.assertIn("no LAN", state["error"] or "")


if __name__ == "__main__":
    unittest.main()
