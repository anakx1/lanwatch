"""Tests for device trust, scan comparison and the persistent event log."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lanwatch.changes import SnapshotDevice, compare_snapshots
from lanwatch.events import Event
from lanwatch.history import HistoryStore
from lanwatch.model import Device
from lanwatch.store import Store


class TrustModelTests(unittest.TestCase):
    def test_trust_round_trip(self) -> None:
        device = Device(ip="10.0.0.5", trust="trusted", trust_updated_at=123.5)
        again = Device.from_dict(device.to_dict())
        self.assertEqual(again.trust, "trusted")
        self.assertEqual(again.trust_updated_at, 123.5)

    def test_invalid_saved_trust_falls_back_to_unknown(self) -> None:
        device = Device.from_dict({"ip": "10.0.0.5", "trust": "definitely-not-a-level"})
        self.assertEqual(device.trust, "unknown")

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


def snapshot(
    ip: str,
    *,
    mac: str | None = None,
    hostname: str | None = None,
    ports: tuple[int, ...] = (),
    trust: str = "unknown",
    name: str | None = None,
) -> SnapshotDevice:
    return SnapshotDevice(
        ip=ip,
        name=name or hostname or ip,
        hostname=hostname,
        mac=mac,
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

    def test_service_change_lists_opened_ports(self) -> None:
        diff = compare_snapshots(
            [snapshot("10.0.0.5", ports=(80,))],
            [snapshot("10.0.0.5", ports=(80, 443))],
        )
        self.assertEqual(diff.changed_devices, 1)
        change = diff.changes[0]
        self.assertEqual(change.event_type, "device.services_changed")
        self.assertEqual(change.details["ports_added"], [443])

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
            type="scan.baseline",
            severity="info",
            title="Network baseline recorded",
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
        self.assertEqual(history.event_log(5), [])


if __name__ == "__main__":
    unittest.main()
