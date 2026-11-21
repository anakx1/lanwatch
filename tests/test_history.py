"""Tests for the SQLite scan history."""

from __future__ import annotations

import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from lanwatch.history import HistoryStore, default_history_path
from lanwatch.model import Device


class HistoryPathTests(unittest.TestCase):
    def test_derived_from_inventory_path(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"LANWATCH_HISTORY": ""}):
            expected = Path("/tmp/lanwatch/devices-history.db")
            self.assertEqual(default_history_path(Path("/tmp/lanwatch/devices.json")), expected)

    def test_environment_override(self) -> None:
        with unittest.mock.patch.dict(os.environ, {"LANWATCH_HISTORY": "~/custom.db"}):
            self.assertEqual(
                default_history_path(Path("/tmp/devices.json")),
                Path("~/custom.db").expanduser(),
            )


class HistoryStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "history.db"
        self.history = HistoryStore(self.path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def record(
        self,
        devices: list[Device],
        *,
        started: float = 1000.0,
        finished: float = 1005.0,
        stopped: bool = False,
    ) -> int:
        return self.history.record_scan(
            devices,
            started_at=started,
            finished_at=finished,
            duration_s=finished - started,
            subnet="10.0.0.0/24",
            interface="wlan0",
            hosts_total=254,
            hosts_up=len(devices),
            stopped=stopped,
        )

    def test_records_scan_and_devices(self) -> None:
        scan_id = self.record(
            [
                Device(
                    ip="10.0.0.1",
                    hostname="ROUTER",
                    hostname_source="nbns",
                    mac="3c:22:fb:11:22:33",
                    vendor="Apple",
                    rtt_ms=3.2,
                    ports=[443, 80],
                    online=True,
                )
            ]
        )
        self.assertGreater(scan_id, 0)

        scans = self.history.recent(5)
        self.assertEqual(len(scans), 1)
        scan = scans[0]
        self.assertEqual(scan["id"], scan_id)
        self.assertEqual(scan["subnet"], "10.0.0.0/24")
        self.assertEqual(scan["interface"], "wlan0")
        self.assertEqual(scan["devices_found"], 1)
        self.assertEqual(scan["hosts_up"], 1)
        self.assertEqual(scan["duration_s"], 5.0)
        self.assertFalse(scan["stopped"])
        self.assertIsNone(scan["error"])

        visits = self.history.device_history("10.0.0.1")
        self.assertEqual(len(visits), 1)
        self.assertEqual(visits[0]["name"], "ROUTER")
        self.assertEqual(visits[0]["hostname"], "ROUTER")
        self.assertEqual(visits[0]["latency_ms"], 3.2)
        self.assertEqual(visits[0]["ports"], [80, 443])
        self.assertEqual(visits[0]["subnet"], "10.0.0.0/24")

    def test_recent_is_newest_first_and_limit_is_clamped(self) -> None:
        for index in range(4):
            self.record(
                [Device(ip=f"10.0.0.{index + 1}", online=True)],
                started=float(index),
                finished=float(index) + 1,
            )
        scans = self.history.recent(2)
        self.assertEqual(len(scans), 2)
        self.assertEqual([scan["devices_found"] for scan in scans], [1, 1])
        self.assertEqual(len(self.history.recent(0)), 1)
        self.assertEqual(len(self.history.recent(500)), 4)
        self.assertEqual(self.history.count(), 4)

    def test_stopped_flag_and_empty_scan(self) -> None:
        scan_id = self.record([], stopped=True)
        scans = self.history.recent(5)
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["id"], scan_id)
        self.assertTrue(scans[0]["stopped"])
        self.assertEqual(scans[0]["devices_found"], 0)
        self.assertEqual(self.history.device_history("10.0.0.1"), [])

    def test_retention_prunes_old_scans_and_devices(self) -> None:
        history = HistoryStore(self.path, max_scans=2)
        for index in range(3):
            history.record_scan(
                [Device(ip=f"10.0.0.{index + 1}", online=True)],
                started_at=float(index),
                finished_at=float(index) + 1,
                subnet="10.0.0.0/24",
            )
        scans = history.recent(10)
        self.assertEqual(len(scans), 2)
        self.assertEqual([scan["devices_found"] for scan in scans], [1, 1])
        self.assertEqual(history.device_history("10.0.0.1"), [])
        self.assertEqual(len(history.device_history("10.0.0.3")), 1)

    def test_persists_across_instances(self) -> None:
        self.record([Device(ip="10.0.0.9", online=True)])
        again = HistoryStore(self.path)
        self.assertEqual(again.count(), 1)
        self.assertEqual(again.recent(1)[0]["devices_found"], 1)

    def test_invalid_ip_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.history.device_history("not-an-ip")


if __name__ == "__main__":
    unittest.main()
