"""Tests for device trust, scan comparison and the persistent event log."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from lanwatch.changes import SnapshotDevice, compare_snapshots
from lanwatch.events import (
    EVENT_TYPES,
    SEVERITIES,
    Event,
    events_for_diff,
    scan_failure_event,
    severity_for,
    trust_event,
)
from lanwatch.history import HistoryStore
from lanwatch.model import Device
from lanwatch.store import SCHEMA_VERSION, Store


class TrustModelTests(unittest.TestCase):
    def test_trust_round_trip(self) -> None:
        device = Device(ip="10.0.0.5", trust="trusted", trust_updated_at=123.5)
        again = Device.from_dict(device.to_dict())
        self.assertEqual(again.trust, "trusted")
        self.assertEqual(again.trust_updated_at, 123.5)

    def test_invalid_saved_trust_falls_back_to_unknown(self) -> None:
        device = Device.from_dict({"ip": "10.0.0.5", "trust": "definitely-not-a-level"})
        self.assertEqual(device.trust, "unknown")

    def test_new_device_defaults_to_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "inventory.json"
            store = Store(path)
            store.activate("10.0.0.0/24")
            device = store.upsert(Device(ip="10.0.0.5"))
            self.assertEqual(device.trust, "unknown")
            self.assertTrue(store.save())

            again = Store(path)
            self.assertEqual(again.devices["10.0.0.5"].trust, "unknown")

    def test_merge_does_not_copy_collector_default_trust(self) -> None:
        device = Device(ip="10.0.0.5", trust="trusted")
        device.merge(Device(ip="10.0.0.5", hostname="printer", ports=[631]))
        self.assertEqual(device.trust, "trusted")
        self.assertEqual(device.hostname, "printer")

    def test_store_persists_trust(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "inventory.json"
            store = Store(path)
            store.activate("10.0.0.0/24")
            store.devices["10.0.0.5"] = Device(ip="10.0.0.5")
            device = store.set_trust("10.0.0.5", "ignored")
            self.assertIsNotNone(device)
            assert device is not None
            self.assertEqual(device.trust, "ignored")
            self.assertIsNotNone(device.trust_updated_at)
            self.assertTrue(store.save())

            again = Store(path)
            self.assertEqual(again.devices["10.0.0.5"].trust, "ignored")
            self.assertEqual(again.counts()["ignored"], 1)

    def test_store_rejects_invalid_trust(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "inventory.json")
            store.activate("10.0.0.0/24")
            store.devices["10.0.0.5"] = Device(ip="10.0.0.5")
            with self.assertRaises(ValueError):
                store.set_trust("10.0.0.5", "owner")

    def test_trust_update_preserves_labels_notes_and_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "inventory.json")
            store.activate("10.0.0.0/24")
            device = Device(
                ip="10.0.0.5",
                mac="3c:22:fb:11:22:33",
                vendor="Example",
                hostname="printer",
                hostname_source="mdns",
                ports=[80, 631],
                banners={"80": "Example HTTP"},
                web={"80": {"title": "Printer"}},
                mdns_services=["_http._tcp.local"],
                sources=["arp", "mdns"],
                first_seen=100.0,
                last_seen=200.0,
                seen_count=4,
            )
            store.devices[device.ip] = device
            store.set_user_fields(device.ip, "Office printer", "Second floor")

            updated = store.set_trust(device.ip, "trusted")

            self.assertIsNotNone(updated)
            assert updated is not None
            self.assertEqual(updated.trust, "trusted")
            self.assertEqual(updated.label, "Office printer")
            self.assertEqual(updated.notes, "Second floor")
            self.assertEqual(updated.mac, "3c:22:fb:11:22:33")
            self.assertEqual(updated.hostname, "printer")
            self.assertEqual(updated.ports, [80, 631])
            self.assertEqual(updated.banners, {"80": "Example HTTP"})
            self.assertEqual(updated.web, {"80": {"title": "Printer"}})
            self.assertEqual(updated.mdns_services, ["_http._tcp.local"])
            self.assertEqual(updated.sources, ["arp", "mdns"])
            self.assertEqual(updated.first_seen, 100.0)
            self.assertEqual(updated.last_seen, 200.0)
            self.assertEqual(updated.seen_count, 4)

    def test_trust_is_scoped_to_each_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "inventory.json"
            store = Store(path)
            home = store.activate("192.168.1.0/24", "aa:bb:cc:dd:ee:01")
            store.upsert(Device(ip="192.168.1.50", label="Home printer"))
            store.set_trust("192.168.1.50", "trusted")

            office = store.activate("192.168.1.0/24", "aa:bb:cc:dd:ee:02")
            self.assertNotEqual(home.id, office.id)
            office_device = store.upsert(Device(ip="192.168.1.50", label="Office printer"))
            self.assertEqual(office_device.trust, "unknown")
            store.set_trust("192.168.1.50", "ignored")

            store.select(home.id)
            self.assertEqual(store.devices["192.168.1.50"].trust, "trusted")
            self.assertEqual(store.devices["192.168.1.50"].label, "Home printer")

            self.assertTrue(store.save())
            again = Store(path)
            again.select(office.id)
            self.assertEqual(again.devices["192.168.1.50"].trust, "ignored")
            self.assertEqual(again.devices["192.168.1.50"].label, "Office printer")
            again.select(home.id)
            self.assertEqual(again.devices["192.168.1.50"].trust, "trusted")

    def test_v1_inventory_migrates_with_unknown_trust(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "inventory.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "network": {
                            "cidr": "10.0.0.0/24",
                            "interface": "wlan0",
                            "gateway": "10.0.0.1",
                        },
                        "devices": [
                            {"ip": "10.0.0.5", "hostname": "printer", "label": "Old printer"}
                        ],
                    }
                ),
                encoding="utf-8",
            )

            store = Store(path)
            self.assertEqual(store.load_error, None)
            self.assertEqual(store.active_id, "10.0.0.0/24")
            device = store.devices["10.0.0.5"]
            self.assertEqual(device.trust, "unknown")
            self.assertEqual(device.label, "Old printer")

            self.assertTrue(store.save())
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(raw["version"], SCHEMA_VERSION)
            saved = raw["networks"][0]["devices"][0]
            self.assertEqual(saved["trust"], "unknown")

    def test_v2_inventory_migrates_with_unknown_trust(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "inventory.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "active": "net-a",
                        "networks": [
                            {
                                "id": "net-a",
                                "cidr": "10.0.0.0/24",
                                "info": {"cidr": "10.0.0.0/24"},
                                "devices": [
                                    {
                                        "ip": "10.0.0.5",
                                        "notes": "kept",
                                        "seen_count": 2,
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            store = Store(path)
            self.assertEqual(store.load_error, None)
            device = store.devices["10.0.0.5"]
            self.assertEqual(device.trust, "unknown")
            self.assertEqual(device.notes, "kept")

            self.assertTrue(store.save())
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(raw["version"], SCHEMA_VERSION)
            saved = raw["networks"][0]["devices"][0]
            self.assertEqual(saved["trust"], "unknown")
            self.assertEqual(saved["notes"], "kept")


def snapshot(
    ip: str,
    *,
    mac: str | None = None,
    hostname: str | None = None,
    vendor: str | None = None,
    kind: str | None = None,
    ports: tuple[int, ...] = (),
    trust: str = "unknown",
    name: str | None = None,
) -> SnapshotDevice:
    return SnapshotDevice(
        ip=ip,
        name=name or hostname or ip,
        hostname=hostname,
        mac=mac,
        vendor=vendor,
        kind=kind,
        ports=ports,
        trust=trust,
    )


class ScanComparisonTests(unittest.TestCase):
    def test_first_scan_is_a_silent_baseline(self) -> None:
        diff = compare_snapshots(
            None,
            [snapshot("10.0.0.1"), snapshot("10.0.0.2")],
        )
        self.assertTrue(diff.baseline)
        self.assertEqual(diff.changes, [])
        self.assertEqual(diff.current_devices, 2)

    def test_new_and_offline_devices(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.1"), snapshot("10.0.0.2")],
            [snapshot("10.0.0.1"), snapshot("10.0.0.3")],
        )
        self.assertFalse(diff.baseline)
        self.assertEqual(diff.new_devices, 1)
        self.assertEqual(diff.offline_devices, 1)
        kinds = {change.event_type for change in diff.changes}
        self.assertEqual(kinds, {"device.new", "device.offline"})
        self.assertEqual(diff.new_ips, ["10.0.0.3"])
        self.assertEqual(diff.offline_ips, ["10.0.0.2"])

    def test_new_device_records_available_identity(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.1")],
            [
                snapshot("10.0.0.1"),
                snapshot(
                    "10.0.0.7",
                    hostname="camera.lan",
                    vendor="Acme",
                    kind="camera",
                ),
            ],
        )
        change = diff.changes[0]
        self.assertEqual(change.event_type, "device.new")
        self.assertEqual(change.details["device"]["ip"], "10.0.0.7")
        self.assertEqual(change.details["device"]["hostname"], "camera.lan")
        self.assertEqual(change.details["device"]["vendor"], "Acme")
        self.assertEqual(change.details["device"]["kind"], "camera")
        self.assertIn("camera.lan", change.message)
        self.assertIn("Acme", change.message)
        self.assertIn("camera", change.message)

    def test_service_change_lists_opened_ports(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.5", ports=(80,))],
            [snapshot("10.0.0.5", ports=(80, 443))],
        )
        self.assertEqual(diff.changed_devices, 1)
        change = diff.changes[0]
        self.assertEqual(change.event_type, "device.services_changed")
        self.assertEqual(change.details["ports_added"], [443])
        self.assertIn("Port 443 opened", change.message)

    def test_service_change_lists_removed_ports(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.5", ports=(80, 443))],
            [snapshot("10.0.0.5", ports=(443,))],
        )
        change = diff.changes[0]
        self.assertEqual(change.event_type, "device.services_changed")
        self.assertNotIn("ports_added", change.details)
        self.assertEqual(change.details["ports_removed"], [80])
        self.assertIn("Port 80 closed", change.message)

    def test_hostname_change_is_reported(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.5", hostname="old-name")],
            [snapshot("10.0.0.5", hostname="new-name")],
        )
        change = diff.changes[0]
        self.assertEqual(change.event_type, "device.hostname_changed")
        self.assertEqual(change.details["hostname_before"], "old-name")
        self.assertEqual(change.details["hostname_after"], "new-name")
        self.assertEqual(change.details["fields"], ["hostname"])

    def test_vendor_becoming_available_is_reported(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.5")],
            [snapshot("10.0.0.5", vendor="Acme")],
        )
        change = diff.changes[0]
        self.assertEqual(change.event_type, "device.vendor_changed")
        self.assertIsNone(change.details["vendor_before"])
        self.assertEqual(change.details["vendor_after"], "Acme")
        self.assertIn("vendor became Acme", change.message)

        changed = compare_snapshots(
            [snapshot("10.0.0.5", vendor="Old Corp")],
            [snapshot("10.0.0.5", vendor="New Corp")],
        ).changes[0]
        self.assertEqual(changed.event_type, "device.vendor_changed")
        self.assertIn("Old Corp → New Corp", changed.message)

    def test_fingerprint_type_change_is_reported(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.5", kind="computer")],
            [snapshot("10.0.0.5", kind="camera")],
        )
        change = diff.changes[0]
        self.assertEqual(change.event_type, "device.fingerprint_changed")
        self.assertEqual(change.details["kind_before"], "computer")
        self.assertEqual(change.details["kind_after"], "camera")
        self.assertTrue(change.details["fields"])

    def test_missing_old_type_does_not_create_noise(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.5")],
            [snapshot("10.0.0.5", kind="router")],
        )
        self.assertEqual(diff.changes, [])

    def test_combined_information_change_is_one_record(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.5", hostname="old", vendor="Old", kind="device", ports=(80,))],
            [snapshot("10.0.0.5", hostname="new", vendor="New", kind="router", ports=(80, 443))],
        )
        self.assertEqual(len(diff.changes), 1)
        self.assertEqual(diff.changed_devices, 1)
        change = diff.changes[0]
        self.assertEqual(change.event_type, "device.services_changed")
        self.assertEqual(
            change.details["fields"],
            ["hostname", "vendor", "type", "ports_added"],
        )

    def test_ip_address_change_matches_by_mac(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.5", mac="3c:22:fb:11:22:33")],
            [snapshot("10.0.0.9", mac="3c:22:fb:11:22:33")],
        )
        self.assertEqual([change.event_type for change in diff.changes], ["device.ip_changed"])
        self.assertEqual(diff.changes[0].details["before"]["ip"], "10.0.0.5")
        self.assertEqual(diff.changes[0].details["after"]["ip"], "10.0.0.9")

    def test_replaced_device_is_critical(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.5", mac="3c:22:fb:11:22:33")],
            [snapshot("10.0.0.5", mac="00:11:22:33:44:55")],
        )
        change = diff.changes[0]
        self.assertEqual(change.event_type, "device.replaced")
        self.assertEqual(change.severity, "critical")

    def test_returning_device_uses_seen_before_callback(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.1")],
            [snapshot("10.0.0.1"), snapshot("10.0.0.7")],
            is_returning=lambda ip: ip == "10.0.0.7",
        )
        self.assertEqual(diff.returned_devices, 1)
        self.assertEqual(diff.new_devices, 0)
        self.assertEqual(diff.changes[0].event_type, "device.returned")

    def test_ignored_devices_are_hidden_from_changes(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.1", trust="ignored"), snapshot("10.0.0.2")],
            [snapshot("10.0.0.1", trust="ignored"), snapshot("10.0.0.3", trust="ignored")],
            inventory_trust={"10.0.0.1": "ignored", "10.0.0.2": "ignored"},
        )
        self.assertEqual(diff.changes, [])
        self.assertEqual(diff.current_devices, 0)

    def test_partial_scan_skips_comparison(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.1")],
            [snapshot("10.0.0.1")],
            partial=True,
        )
        self.assertTrue(diff.partial)
        self.assertEqual(diff.changes, [])


class EventBuilderTests(unittest.TestCase):
    def events_for(
        self,
        previous: list[SnapshotDevice],
        current: list[SnapshotDevice],
        *,
        returning: tuple[str, ...] = (),
    ) -> list[Event]:
        diff = compare_snapshots(
            previous,
            current,
            is_returning=lambda ip: ip in returning,
        )
        return events_for_diff(diff, "net-a")

    def by_type(self, events: list[Event]) -> dict[str, Event]:
        return {event.type: event for event in events}

    def test_required_categories_and_documented_severities(self) -> None:
        required = {
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
        }
        self.assertTrue(required.issubset(EVENT_TYPES))
        for event_type in EVENT_TYPES:
            self.assertIn(severity_for(event_type), SEVERITIES)

    def test_comparison_changes_create_every_event_category(self) -> None:
        one = snapshot("10.0.0.5", hostname="printer")
        cases = {
            "device.new": (
                [snapshot("10.0.0.1")],
                [snapshot("10.0.0.1"), snapshot("10.0.0.7", hostname="camera")],
                (),
            ),
            "device.online": (
                [snapshot("10.0.0.1")],
                [snapshot("10.0.0.1"), snapshot("10.0.0.7", hostname="camera")],
                ("10.0.0.7",),
            ),
            "device.offline": (
                [snapshot("10.0.0.1"), one],
                [snapshot("10.0.0.1")],
                (),
            ),
            "device.hostname_changed": (
                [one],
                [snapshot("10.0.0.5", hostname="scanner")],
                (),
            ),
            "device.vendor_changed": (
                [snapshot("10.0.0.5", vendor="Old Corp")],
                [snapshot("10.0.0.5", vendor="New Corp")],
                (),
            ),
            "device.kind_changed": (
                [snapshot("10.0.0.5", kind="computer")],
                [snapshot("10.0.0.5", kind="camera")],
                (),
            ),
            "port.opened": (
                [snapshot("10.0.0.5", ports=(80,))],
                [snapshot("10.0.0.5", ports=(80, 443))],
                (),
            ),
            "port.closed": (
                [snapshot("10.0.0.5", ports=(80, 443))],
                [snapshot("10.0.0.5", ports=(80,))],
                (),
            ),
            "device.ip_changed": (
                [snapshot("10.0.0.5", mac="3c:22:fb:11:22:33")],
                [snapshot("10.0.0.9", mac="3c:22:fb:11:22:33")],
                (),
            ),
            "device.replaced": (
                [snapshot("10.0.0.5", mac="3c:22:fb:11:22:33")],
                [snapshot("10.0.0.5", mac="00:11:22:33:44:55")],
                (),
            ),
        }
        self.assertEqual(
            set(cases) | {"scan.completed", "scan.failed", "device.trust_changed"},
            set(EVENT_TYPES),
        )
        for expected, (previous, current, returning) in cases.items():
            with self.subTest(event_type=expected):
                events = self.events_for(previous, current, returning=returning)
                by_type = self.by_type(events)
                self.assertIn(expected, by_type)
                event = by_type[expected]
                self.assertEqual(event.severity, severity_for(expected))
                self.assertEqual(event.network_id, "net-a")
                self.assertGreater(event.ts, 0)
                self.assertTrue(event.title)
                self.assertTrue(event.message)
                if expected not in {"device.new", "device.online"}:
                    self.assertIsNotNone(event.device_ip)
                    self.assertIsNotNone(event.device_name)

        failed = scan_failure_event("no LAN", "net-a")
        self.assertEqual(failed.type, "scan.failed")
        self.assertEqual(failed.severity, severity_for("scan.failed"))
        self.assertEqual(failed.network_id, "net-a")
        self.assertGreater(failed.ts, 0)
        self.assertIsNone(failed.device_ip)
        self.assertEqual(failed.details["error"], "no LAN")

        trusted = trust_event(
            Device(ip="10.0.0.5", hostname="router", trust="trusted"),
            "unknown",
            "net-a",
        )
        self.assertEqual(trusted.type, "device.trust_changed")
        self.assertEqual(trusted.severity, "info")
        self.assertEqual(trusted.device_name, "router")
        self.assertEqual(trusted.details["after"], "trusted")

    def test_scan_completed_is_always_recorded(self) -> None:
        events = self.events_for(
            [snapshot("10.0.0.1")],
            [snapshot("10.0.0.1"), snapshot("10.0.0.7")],
        )
        completed = self.by_type(events)["scan.completed"]
        self.assertEqual(completed.severity, "info")
        self.assertFalse(completed.details["baseline"])
        self.assertEqual(completed.details["counts"]["new"], 1)
        self.assertIn("1 new", completed.message)

        baseline = events_for_diff(
            compare_snapshots(None, [snapshot("10.0.0.1")]),
            "net-a",
        )
        self.assertEqual([event.type for event in baseline], ["scan.completed"])
        self.assertTrue(baseline[0].details["baseline"])
        self.assertIn("baseline", baseline[0].title.casefold())

        linked = events_for_diff(
            compare_snapshots(
                [snapshot("10.0.0.1")],
                [snapshot("10.0.0.1"), snapshot("10.0.0.7")],
            ),
            "net-a",
            scan_id=42,
        )
        self.assertTrue(all(event.scan_id == 42 for event in linked))

    def test_combined_change_expands_to_specific_events(self) -> None:
        events = self.events_for(
            [
                snapshot(
                    "10.0.0.5",
                    hostname="old",
                    vendor="Old Corp",
                    kind="computer",
                    ports=(80, 443),
                )
            ],
            [
                snapshot(
                    "10.0.0.5",
                    hostname="new",
                    vendor="New Corp",
                    kind="router",
                    ports=(80, 8080),
                )
            ],
        )
        types = [event.type for event in events]
        self.assertEqual(
            set(types),
            {
                "device.hostname_changed",
                "device.vendor_changed",
                "device.kind_changed",
                "port.opened",
                "port.closed",
                "scan.completed",
            },
        )
        self.assertNotIn("device.services_changed", types)
        self.assertEqual(types[-1], "scan.completed")
        by_type = self.by_type(events)
        self.assertEqual(by_type["port.opened"].details["ports"], [8080])
        self.assertEqual(by_type["port.closed"].details["ports"], [443])
        self.assertEqual(by_type["device.hostname_changed"].details["fields"], ["hostname"])
        self.assertEqual(by_type["device.kind_changed"].details["kind_after"], "router")

    def test_new_device_is_not_exaggerated(self) -> None:
        events = self.by_type(
            self.events_for(
                [snapshot("10.0.0.1")],
                [snapshot("10.0.0.1"), snapshot("10.0.0.7", hostname="tv")],
            )
        )
        self.assertEqual(events["device.new"].severity, "warning")
        self.assertNotEqual(events["device.new"].severity, "critical")
        self.assertNotIn("malicious", events["device.new"].message.casefold())
        self.assertEqual(events["device.new"].device_name, "tv")
        self.assertEqual(events["device.new"].details["device"]["ip"], "10.0.0.7")

    def test_returned_device_is_device_online(self) -> None:
        events = self.by_type(
            self.events_for(
                [snapshot("10.0.0.1")],
                [snapshot("10.0.0.1"), snapshot("10.0.0.7", hostname="camera")],
                returning=("10.0.0.7",),
            )
        )
        self.assertIn("device.online", events)
        self.assertNotIn("device.returned", events)
        self.assertEqual(events["device.online"].severity, "info")


class EventHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "history.db"
        self.history = HistoryStore(self.path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def record(self, ip: str, scan_id: int | None = None) -> int:
        return self.history.record_scan(
            [Device(ip=ip, hostname="ROUTER", ports=[80, 443], online=True)],
            started_at=1000.0,
            finished_at=1005.0,
            duration_s=5.0,
            subnet="10.0.0.0/24",
            interface="wlan0",
            network_id="10.0.0.0/24",
            baseline=scan_id is None,
            events=[],
        )

    def test_events_are_stored_filtered_and_marked_read(self) -> None:
        event = Event(
            type="device.new",
            severity="warning",
            title="New device: camera",
            message="10.0.0.7",
            network_id="10.0.0.0/24",
            device_ip="10.0.0.7",
            details={"ports": [80]},
        )
        event_id = self.history.record_event(event)
        self.assertGreater(event_id, 0)
        self.assertEqual(event.id, event_id)
        self.assertEqual(self.history.unread_count(), 1)

        events = self.history.event_log(10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["id"], event_id)
        self.assertEqual(events[0]["details"], {"ports": [80]})
        self.assertFalse(events[0]["read"])
        self.assertEqual(
            [item["id"] for item in self.history.event_log(10, severities=["warning"])],
            [event_id],
        )
        self.assertEqual(self.history.event_log(10, severities=["critical"]), [])

        self.assertEqual(self.history.mark_events_read([event_id]), 1)
        self.assertEqual(self.history.unread_count(), 0)
        self.assertTrue(self.history.event_log(10)[0]["read"])

    def test_scan_events_store_device_scan_and_change_fields(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.5", hostname="old", ports=(80,))],
            [snapshot("10.0.0.5", hostname="new", ports=(80, 443))],
        )
        events = events_for_diff(diff, "net-a")
        scan_id = self.history.record_scan(
            [Device(ip="10.0.0.5", hostname="new", ports=[80, 443], online=True)],
            started_at=1000.0,
            finished_at=1005.0,
            subnet="10.0.0.0/24",
            network_id="net-a",
            events=events,
        )

        stored = self.history.event_log(
            10,
            event_type="device.hostname_changed",
            severities=["info"],
            network_id="net-a",
            device="10.0.0.5",
        )
        self.assertEqual(len(stored), 1)
        event = stored[0]
        self.assertEqual(event["scan_id"], scan_id)
        self.assertEqual(event["network_id"], "net-a")
        self.assertEqual(event["device_ip"], "10.0.0.5")
        self.assertEqual(event["device_name"], "new")
        self.assertEqual(event["description"], event["message"])
        self.assertEqual(event["before"]["hostname"], "old")
        self.assertEqual(event["after"]["hostname"], "new")
        self.assertEqual(event["details"]["hostname_before"], "old")
        self.assertGreater(event["ts"], 0)

        port = self.history.event_log(10, event_type="port.opened")[0]
        self.assertEqual(port["scan_id"], scan_id)
        self.assertEqual(port["details"]["ports"], [443])
        completed = self.history.event_log(10, event_type="scan.completed")[0]
        self.assertEqual(completed["scan_id"], scan_id)
        self.assertEqual(completed["details"]["counts"]["changed"], 1)

        self.assertEqual(len(self.history.event_log(1)), 1)

    def test_event_type_and_limit_filters(self) -> None:
        for index, event_type in enumerate(("device.new", "port.opened", "scan.failed")):
            self.history.record_event(
                Event(
                    type=event_type,
                    severity=severity_for(event_type),
                    title=f"event {index}",
                    device_ip="10.0.0.7" if index < 2 else None,
                    network_id="net-a",
                )
            )
        self.assertEqual(
            [event["type"] for event in self.history.event_log(10, event_type="port.opened")],
            ["port.opened"],
        )
        self.assertEqual(
            len(self.history.event_log(10, device="10.0.0.7")),
            2,
        )
        self.assertEqual(len(self.history.event_log(2)), 2)
        newest = self.history.event_log(1)[0]
        older = self.history.event_log(10, before_id=newest["id"])
        self.assertEqual([event["type"] for event in older], ["port.opened", "device.new"])

    def test_duplicate_scan_processing_does_not_duplicate_events(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.5", hostname="old")],
            [snapshot("10.0.0.5", hostname="new")],
        )

        def process() -> int:
            events = events_for_diff(diff, "net-a")
            return self.history.record_scan(
                [Device(ip="10.0.0.5", hostname="new", online=True)],
                started_at=2000.0,
                finished_at=2005.0,
                subnet="10.0.0.0/24",
                network_id="net-a",
                events=events,
            )

        first_scan = process()
        count = self.history.event_count()
        self.assertEqual(count, 2)
        second_scan = process()
        self.assertNotEqual(first_scan, second_scan)
        self.assertEqual(self.history.event_count(), count)
        stored = self.history.event_log(10, event_type="device.hostname_changed")
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["scan_id"], first_scan)

    def test_event_retention_by_age(self) -> None:
        history = HistoryStore(self.path, max_event_age_days=1)
        history.record_event(
            Event(
                type="device.new",
                severity="warning",
                title="old event",
                ts=time.time() - 2 * 86400,
            )
        )
        self.assertEqual(history.event_count(), 0)

    def test_event_schema_migration_and_notice_normalisation(self) -> None:
        legacy = Path(self.tmp.name) / "legacy-events.db"
        connection = sqlite3.connect(legacy)
        connection.executescript(
            """
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                network_id TEXT,
                scan_id INTEGER,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                device_ip TEXT,
                title TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '{}',
                read_at REAL
            );
            INSERT INTO events (ts, type, severity, title, message)
            VALUES (1, 'device.new', 'notice', 'old', 'old');
            """
        )
        connection.commit()
        connection.close()

        history = HistoryStore(legacy)
        events = history.event_log(5)
        connection = sqlite3.connect(legacy)
        try:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(events)")
            }
            indexes = connection.execute("PRAGMA index_list(events)").fetchall()
        finally:
            connection.close()
        self.assertIn("device_name", columns)
        self.assertIn("event_key", columns)
        self.assertIn("events_event_key", {row[1] for row in indexes})
        self.assertEqual(events[0]["severity"], "info")
        self.assertIsNone(events[0]["device_name"])

    def test_concurrent_event_reads_and_writes(self) -> None:
        self.history.record_event(
            Event(type="device.new", severity="warning", title="seed")
        )

        def write(worker: int) -> None:
            for index in range(10):
                self.history.record_event(
                    Event(
                        type="device.new",
                        severity="warning",
                        title=f"writer {worker} event {index}",
                        device_ip=f"10.0.0.{worker + 10}",
                    )
                )

        def read(_: int) -> None:
            for _ in range(10):
                self.history.event_log(20)
                self.history.unread_count()

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [
                pool.submit(write, 0),
                pool.submit(write, 1),
                pool.submit(read, 0),
                pool.submit(read, 1),
            ]
            for future in futures:
                future.result()
        self.assertEqual(self.history.event_count(), 21)

    def test_network_filter_includes_global_events(self) -> None:
        self.history.record_event(
            Event(type="a", severity="info", title="network", network_id="net-a")
        )
        self.history.record_event(Event(type="b", severity="info", title="global"))
        self.assertEqual(
            {event["title"] for event in self.history.event_log(10, network_id="net-a")},
            {"network", "global"},
        )
        self.assertEqual(
            [event["title"] for event in self.history.event_log(10, network_id="net-b")],
            ["global"],
        )
        self.assertEqual(self.history.unread_count("net-b"), 1)

    def test_scan_and_events_commit_together(self) -> None:
        event = Event(
            type="scan.completed",
            severity="info",
            title="Scan completed",
            network_id="10.0.0.0/24",
        )
        scan_id = self.history.record_scan(
            [Device(ip="10.0.0.1", online=True)],
            started_at=1.0,
            finished_at=2.0,
            subnet="10.0.0.0/24",
            network_id="10.0.0.0/24",
            baseline=True,
            events=[event],
        )
        events = self.history.event_log(10)
        self.assertEqual(events[0]["scan_id"], scan_id)
        self.assertTrue(self.history.recent(1)[0]["baseline"])

    def test_event_retention(self) -> None:
        history = HistoryStore(self.path, max_events=2)
        for index in range(4):
            history.record_event(
                Event(type="test", severity="info", title=f"event {index}")
            )
        self.assertEqual(history.event_count(), 2)
        self.assertEqual([event["title"] for event in history.event_log(10)], ["event 3", "event 2"])

    def test_previous_snapshot_and_seen_before(self) -> None:
        self.record("10.0.0.1")
        second = self.record("10.0.0.2")
        previous = self.history.previous_snapshot("10.0.0.0/24", "10.0.0.0/24")
        self.assertIsNotNone(previous)
        assert previous is not None
        self.assertEqual(previous["id"], second)
        self.assertEqual([device["ip"] for device in previous["devices"]], ["10.0.0.2"])
        self.assertTrue(
            self.history.seen_before("10.0.0.0/24", "10.0.0.0/24", "10.0.0.1", second)
        )
        self.assertFalse(
            self.history.seen_before("10.0.0.0/24", "10.0.0.0/24", "10.0.0.9", second)
        )

    def test_previous_snapshot_is_network_specific(self) -> None:
        def record(network_id: str, hostname: str) -> int:
            return self.history.record_scan(
                [Device(ip="10.0.0.5", hostname=hostname, ports=[80], online=True)],
                started_at=1000.0,
                finished_at=1005.0,
                subnet="10.0.0.0/24",
                network_id=network_id,
            )

        network_a = record("net-a", "A")
        network_b = record("net-b", "B")

        previous_a = self.history.previous_snapshot("net-a", "10.0.0.0/24")
        previous_b = self.history.previous_snapshot("net-b", "10.0.0.0/24")
        assert previous_a is not None
        assert previous_b is not None
        self.assertEqual(previous_a["id"], network_a)
        self.assertEqual(previous_a["devices"][0]["hostname"], "A")
        self.assertEqual(previous_b["id"], network_b)
        self.assertEqual(previous_b["devices"][0]["hostname"], "B")
        self.assertEqual(
            compare_snapshots(
                previous_a["devices"],
                [snapshot("10.0.0.5", hostname="A", ports=(80,))],
            ).changes,
            [],
        )

    def test_comparison_survives_history_reopen(self) -> None:
        first = self.record("10.0.0.1")
        reopened = HistoryStore(self.path)
        previous = reopened.previous_snapshot("10.0.0.0/24", "10.0.0.0/24")
        self.assertIsNotNone(previous)
        assert previous is not None
        self.assertEqual(previous["id"], first)

        diff = compare_snapshots(
            previous["devices"],
            [snapshot("10.0.0.1", hostname="ROUTER", ports=(80, 443))],
        )
        self.assertEqual(diff.changes, [])
        self.assertEqual(diff.new_devices, 0)
        self.assertEqual(diff.offline_devices, 0)

    def test_scan_snapshot_stores_device_type(self) -> None:
        device = Device(ip="10.0.0.1", hostname="printer", ports=[631])
        scan_id = self.history.record_scan(
            [device],
            started_at=1.0,
            finished_at=2.0,
            subnet="10.0.0.0/24",
            network_id="10.0.0.0/24",
        )
        snapshot = self.history.scan_snapshot(scan_id)
        assert snapshot is not None
        self.assertEqual(snapshot["devices"][0]["kind"], device.guess_kind())

    def test_legacy_schema_is_migrated(self) -> None:
        legacy = Path(self.tmp.name) / "legacy.db"
        connection = sqlite3.connect(legacy)
        connection.executescript(
            """
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at REAL NOT NULL,
                finished_at REAL NOT NULL,
                duration_s REAL,
                subnet TEXT,
                interface TEXT,
                hosts_total INTEGER NOT NULL DEFAULT 0,
                hosts_up INTEGER NOT NULL DEFAULT 0,
                devices_found INTEGER NOT NULL DEFAULT 0,
                stopped INTEGER NOT NULL DEFAULT 0,
                error TEXT
            );
            CREATE TABLE scan_devices (
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                ip TEXT NOT NULL,
                name TEXT,
                hostname TEXT,
                mac TEXT,
                vendor TEXT,
                latency_ms REAL,
                ports TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (scan_id, ip)
            );
            INSERT INTO scans (started_at, finished_at, subnet, hosts_total, hosts_up, devices_found)
            VALUES (1, 2, '10.0.0.0/24', 254, 1, 1);
            INSERT INTO scan_devices (scan_id, ip, name, ports) VALUES (1, '10.0.0.1', 'old', '80');
            """
        )
        connection.commit()
        connection.close()

        history = HistoryStore(legacy)
        scan = history.recent(1)[0]
        self.assertEqual(scan["devices_found"], 1)
        self.assertFalse(scan["baseline"])
        self.assertEqual(scan["new_devices"], 0)
        self.assertTrue(history.seen_before(None, "10.0.0.0/24", "10.0.0.1", 2))
        snapshot = history.scan_snapshot(1)
        assert snapshot is not None
        self.assertIsNone(snapshot["devices"][0]["kind"])
        self.assertEqual(history.event_log(5), [])


if __name__ == "__main__":
    unittest.main()
