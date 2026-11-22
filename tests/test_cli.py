"""Tests for the history command line output."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from lanwatch import cli
from lanwatch.events import Event
from lanwatch.history import HistoryStore, default_history_path
from lanwatch.model import Device


class HistoryCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "devices.json"
        self.env = unittest.mock.patch.dict(os.environ, {"LANWATCH_HISTORY": ""})
        self.env.start()
        self.history = HistoryStore(default_history_path(self.state))

    def tearDown(self) -> None:
        self.env.stop()
        self.tmp.cleanup()

    def record(self, ip: str = "10.0.0.1", name: str = "ROUTER") -> None:
        self.history.record_scan(
            [Device(ip=ip, hostname=name, ports=[80, 443], rtt_ms=3.0, online=True)],
            started_at=1000.0,
            finished_at=1005.0,
            duration_s=5.0,
            subnet="10.0.0.0/24",
            interface="wlan0",
            hosts_total=254,
            hosts_up=1,
        )

    def args(self, **values: object) -> argparse.Namespace:
        base = {"state": str(self.state), "limit": 20, "device": None, "json": False}
        base.update(values)
        return argparse.Namespace(**base)

    def run_command(self, **values: object) -> tuple[int, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.cmd_history(self.args(**values))
        return code, output.getvalue()

    def test_empty_history(self) -> None:
        code, output = self.run_command(json=False)
        self.assertEqual(code, 0)
        self.assertIn("No scan history yet", output)

    def test_json_history(self) -> None:
        self.record()
        code, output = self.run_command(json=True)
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(data["history_path"], str(self.history.path))
        self.assertEqual(len(data["scans"]), 1)
        self.assertEqual(data["scans"][0]["devices_found"], 1)

    def test_text_history(self) -> None:
        self.record()
        code, output = self.run_command()
        self.assertEqual(code, 0)
        self.assertIn("10.0.0.0/24", output)
        self.assertIn("ok", output)
        self.assertIn("history", output)

    def test_device_history(self) -> None:
        self.record()
        code, output = self.run_command(device="10.0.0.1")
        self.assertEqual(code, 0)
        self.assertIn("ROUTER", output)
        self.assertIn("http", output)

        code, output = self.run_command(device="10.0.0.1", json=True)
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(data["ip"], "10.0.0.1")
        self.assertEqual(len(data["visits"]), 1)
        self.assertEqual(data["visits"][0]["ports"], [80, 443])

    def test_command_is_registered(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["history", "--limit", "3"])
        self.assertEqual(args.func, cli.cmd_history)
        self.assertEqual(args.limit, 3)
        self.assertIn("history", cli.COMMANDS)

        trust_args = parser.parse_args(["trust", "10.0.0.1", "trusted"])
        self.assertEqual(trust_args.func, cli.cmd_trust)
        self.assertEqual(trust_args.level, "trusted")
        self.assertIn("trust", cli.COMMANDS)

        event_args = parser.parse_args(["events", "--unread", "--json"])
        self.assertEqual(event_args.func, cli.cmd_events)
        self.assertTrue(event_args.unread)
        self.assertIn("events", cli.COMMANDS)

    def test_trust_command_updates_store_and_event_log(self) -> None:
        from lanwatch.store import Store

        store = Store(self.state)
        store.activate("10.0.0.0/24")
        store.upsert(Device(ip="10.0.0.1", online=True))
        self.assertTrue(store.save())

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.cmd_trust(
                argparse.Namespace(state=str(self.state), ip="10.0.0.1", level="trusted")
            )
        self.assertEqual(code, 0)
        self.assertIn("trusted", output.getvalue())
        again = Store(self.state)
        self.assertEqual(again.devices["10.0.0.1"].trust, "trusted")

        history = HistoryStore(default_history_path(self.state))
        events = history.event_log(10)
        self.assertEqual(events[0]["type"], "device.trust_changed")
        self.assertEqual(events[0]["details"]["after"], "trusted")

    def test_events_command(self) -> None:
        self.history.record_event(
            Event(
                type="device.new",
                severity="warning",
                title="New device: camera",
                message="10.0.0.7",
                device_ip="10.0.0.7",
            )
        )
        args = argparse.Namespace(
            state=str(self.state),
            limit=10,
            severity="warning",
            type=None,
            device=None,
            unread=False,
            json=False,
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.cmd_events(args)
        self.assertEqual(code, 0)
        self.assertIn("New device: camera", output.getvalue())


if __name__ == "__main__":
    unittest.main()
