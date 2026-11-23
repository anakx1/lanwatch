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

from .helpers import fake_target, patched_scan, wait_until


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
        self.assertEqual(television.guess_kind(), "tv")  # Bravia + "TV" outranks generic UPnP renderer

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
        self.assertIn("event.new", kinds)

    def test_scan_events_are_published_with_storage_fields(self) -> None:
        channel = self.engine.bus.subscribe()
        self.run_scan()
        published = []
        while not channel.empty():
            message = channel.get_nowait()
            if message["type"] == "event.new":
                published.append(message["event"])
        self.assertTrue(published)
        completed = next(
            event for event in published if event["type"] == "scan.completed"
        )
        self.assertGreater(completed["id"], 0)
        self.assertEqual(completed["severity"], "info")
        self.assertEqual(completed["network_id"], "10.0.0.0/24")
        self.assertGreater(completed["ts"], 0)
        self.assertIsNotNone(completed["scan_id"])
        self.assertTrue(completed["description"])

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

    def test_scan_comparison_and_events_are_recorded(self) -> None:
        record = self.store.activate("10.0.0.0/24")
        self.store.set_network(
            {
                "cidr": "10.0.0.0/24",
                "interface": "wlan0",
                "address": "10.0.0.5",
                "network_id": record.id,
            }
        )
        self.engine.history.record_scan(
            [
                Device(ip="10.0.0.1", hostname="ROUTER", ports=[80, 443], online=True),
                Device(ip="10.0.0.77", hostname="OLD", online=True),
            ],
            started_at=1.0,
            finished_at=2.0,
            subnet="10.0.0.0/24",
            network_id=record.id,
            baseline=True,
        )

        self.run_scan()
        diff = self.engine.last_diff
        assert diff is not None
        self.assertFalse(diff["baseline"])
        self.assertEqual(diff["counts"]["new"], 3)
        self.assertEqual(diff["counts"]["offline"], 1)
        self.assertEqual(diff["counts"]["changed"], 0)
        events = self.engine.history.event_log(20)
        types = {event["type"] for event in events}
        self.assertIn("device.new", types)
        self.assertIn("device.offline", types)
        self.assertIn("scan.completed", types)
        new_event = next(event for event in events if event["type"] == "device.new")
        self.assertEqual(new_event["severity"], "warning")
        self.assertNotEqual(new_event["severity"], "critical")
        self.assertTrue(new_event["device_name"])
        self.assertGreater(self.engine.history.unread_count(), 0)

        self.run_scan()
        diff = self.engine.last_diff
        assert diff is not None
        self.assertEqual(sum(diff["counts"].values()), 0)

    def test_subsequent_scan_reports_new_device(self) -> None:
        self.run_scan()

        def sweep_with_new_device(hosts, timeout, concurrency, on_up, cancel, on_result):
            answers = {"10.0.0.1": 3.0, "10.0.0.5": 0.4, "10.0.0.7": 2.0}
            for host in hosts:
                rtt = answers.get(host)
                if rtt is not None:
                    on_up(host, rtt)
                on_result(host, rtt)
            return dict(answers)

        def ports_with_new_device(hosts, ports, timeout=0.3, workers=128, cancel=None):
            mapping = {"10.0.0.1": [80, 443], "10.0.0.5": [8080], "10.0.0.7": [22]}
            return {host: mapping[host] for host in hosts if host in mapping}

        def target_with_new_device(*args, **kwargs):
            network, interface, hosts = fake_target()
            return network, interface, [*hosts, "10.0.0.7"]

        with patched_scan(
            {
                "lanwatch.discovery.netif.resolve_target": unittest.mock.Mock(
                    side_effect=target_with_new_device
                ),
                "lanwatch.discovery.collectors.ping_sweep": unittest.mock.Mock(
                    side_effect=sweep_with_new_device
                ),
                "lanwatch.discovery.collectors.scan_ports": unittest.mock.Mock(
                    side_effect=ports_with_new_device
                ),
            }
        ):
            self.run_scan()

        diff = self.engine.last_diff
        assert diff is not None
        self.assertEqual(diff["counts"]["new"], 1)
        self.assertEqual(diff["counts"]["offline"], 0)
        self.assertEqual(diff["new_ips"], ["10.0.0.7"])
        new_event = next(
            event
            for event in self.engine.history.event_log(20)
            if event["type"] == "device.new"
        )
        self.assertEqual(new_event["device_ip"], "10.0.0.7")
        self.assertEqual(new_event["details"]["device"]["ip"], "10.0.0.7")

    def test_device_goes_offline_and_returns(self) -> None:
        self.run_scan()

        def sweep_without_router(hosts, timeout, concurrency, on_up, cancel, on_result):
            answers = {"10.0.0.5": 0.4}
            for host in hosts:
                rtt = answers.get(host)
                if rtt is not None:
                    on_up(host, rtt)
                on_result(host, rtt)
            return dict(answers)

        def ports_without_router(hosts, ports, timeout=0.3, workers=128, cancel=None):
            mapping = {"10.0.0.5": [8080]}
            return {host: mapping[host] for host in hosts if host in mapping}

        with patched_scan(
            {
                "lanwatch.discovery.collectors.ping_sweep": unittest.mock.Mock(
                    side_effect=sweep_without_router
                ),
                "lanwatch.discovery.collectors.scan_ports": unittest.mock.Mock(
                    side_effect=ports_without_router
                ),
                "lanwatch.discovery.collectors.http_probe_many": unittest.mock.Mock(
                    return_value={}
                ),
                "lanwatch.discovery.collectors.reverse_dns_many": unittest.mock.Mock(
                    return_value={}
                ),
            }
        ):
            self.run_scan()

        offline = self.engine.last_diff
        assert offline is not None
        self.assertEqual(offline["counts"]["offline"], 1)
        self.assertEqual(offline["offline_ips"], ["10.0.0.1"])

        self.run_scan()
        returned = self.engine.last_diff
        assert returned is not None
        self.assertEqual(returned["counts"]["returned"], 1)
        self.assertEqual(returned["counts"]["new"], 0)
        self.assertEqual(returned["changed_ips"], ["10.0.0.1"])

    def test_port_removal_uses_scan_snapshot(self) -> None:
        self.run_scan()

        def ports_without_443(hosts, ports, timeout=0.3, workers=128, cancel=None):
            mapping = {"10.0.0.1": [80], "10.0.0.5": [8080]}
            return {host: mapping[host] for host in hosts if host in mapping}

        with patched_scan(
            {
                "lanwatch.discovery.collectors.scan_ports": unittest.mock.Mock(
                    side_effect=ports_without_443
                )
            }
        ):
            self.run_scan()

        # The inventory keeps the historical union, but the comparison and the
        # persisted snapshot use the ports observed by this scan.
        self.assertIn(443, self.store.devices["10.0.0.1"].ports)
        diff = self.engine.last_diff
        assert diff is not None
        self.assertEqual(diff["counts"]["changed"], 1)
        change = diff["changes"][0]
        self.assertEqual(change["event_type"], "device.services_changed")
        self.assertEqual(change["details"]["ports_removed"], [443])
        self.assertIn("Port 443 closed", change["message"])
        event = next(
            item
            for item in self.engine.history.event_log(20)
            if item["type"] == "port.closed"
        )
        self.assertEqual(event["scan_id"], diff["scan_id"])
        self.assertEqual(event["details"]["ports_removed"], [443])
        self.assertEqual(event["details"]["ports"], [443])
        self.assertEqual(self.engine.history.event_log(1)[0]["type"], "scan.completed")
        snapshot = self.engine.history.scan_snapshot(diff["scan_id"])
        assert snapshot is not None
        saved = next(item for item in snapshot["devices"] if item["ip"] == "10.0.0.1")
        self.assertEqual(saved["ports"], [80])
        recomputed = self.engine.scan_diff(diff["scan_id"])
        assert recomputed is not None
        self.assertEqual(recomputed["changes"][0]["details"]["ports_removed"], [443])

    def test_failed_scan_does_not_report_offline(self) -> None:
        self.run_scan()
        scan_count = len(self.engine.history.recent(10))
        self.assertEqual(
            [event for event in self.engine.history.event_log(20) if event["type"] == "device.offline"],
            [],
        )

        with unittest.mock.patch(
            "lanwatch.discovery.netif.resolve_target",
            side_effect=netif.InterfaceError("no LAN"),
        ):
            started, _ = self.engine.start()
            self.assertTrue(started)
            self.assertTrue(wait_until(lambda: not self.engine.running))

        self.assertIsNone(self.engine.last_diff)
        self.assertEqual(len(self.engine.history.recent(10)), scan_count)
        self.assertEqual(
            [event for event in self.engine.history.event_log(20) if event["type"] == "device.offline"],
            [],
        )
        self.assertEqual(self.engine.history.event_log(1)[0]["type"], "scan.failed")

    def test_stopped_scan_does_not_report_offline(self) -> None:
        self.run_scan()

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

        with patched_scan(
            {
                "lanwatch.discovery.collectors.ping_sweep": unittest.mock.Mock(
                    side_effect=stop_sweep
                )
            }
        ):
            started, message = self.engine.start()
            self.assertTrue(started, message)
            self.assertTrue(wait_until(lambda: not self.engine.running))

        self.assertIsNone(self.engine.last_diff)
        self.assertTrue(self.engine.history.recent(1)[0]["stopped"])
        self.assertEqual(
            [event for event in self.engine.history.event_log(20) if event["type"] == "device.offline"],
            [],
        )

    def test_restart_reuses_history_for_comparison(self) -> None:
        self.run_scan()

        restarted = ScanEngine(Store(self.store.path), ScanOptions())
        started, message = restarted.start()
        self.assertTrue(started, message)
        self.assertTrue(
            wait_until(
                lambda: not restarted.running and restarted.state_dict()["phase"] == "done"
            )
        )
        diff = restarted.last_diff
        assert diff is not None
        self.assertEqual(sum(diff["counts"].values()), 0)
        self.assertEqual(diff["counts"]["new"], 0)
        self.assertEqual(diff["counts"]["offline"], 0)

    def test_trust_change_is_persisted_and_published(self) -> None:
        self.run_scan()
        self.store.set_user_fields("10.0.0.1", "Router", "keep this note")
        channel = self.engine.bus.subscribe()
        device, message = self.engine.set_device_trust("10.0.0.1", "trusted")
        self.assertEqual(message, "")
        assert device is not None
        self.assertEqual(device.trust, "trusted")
        self.assertEqual(self.store.devices["10.0.0.1"].trust, "trusted")
        kinds = []
        while not channel.empty():
            kinds.append(channel.get_nowait()["type"])
        self.assertIn("device", kinds)
        self.assertIn("event.new", kinds)
        events = self.engine.history.event_log(10)
        self.assertEqual(events[0]["type"], "device.trust_changed")
        self.assertEqual(events[0]["details"]["after"], "trusted")
        with self.assertRaises(ValueError):
            self.engine.set_device_trust("10.0.0.1", "owner")

        self.run_scan()
        self.assertEqual(self.store.devices["10.0.0.1"].trust, "trusted")
        self.assertEqual(self.store.devices["10.0.0.1"].label, "Router")
        self.assertEqual(self.store.devices["10.0.0.1"].notes, "keep this note")
        reloaded = Store(self.store.path)
        self.assertEqual(reloaded.devices["10.0.0.1"].trust, "trusted")
        self.assertEqual(reloaded.devices["10.0.0.1"].label, "Router")
        self.assertEqual(reloaded.devices["10.0.0.1"].notes, "keep this note")

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
        self.assertEqual(self.engine.history.recent(5), [])
        events = self.engine.history.event_log(5)
        self.assertEqual(events[0]["type"], "scan.failed")
        self.assertEqual(events[0]["severity"], "warning")
        self.assertNotIn("scan.completed", {event["type"] for event in events})


if __name__ == "__main__":
    unittest.main()
