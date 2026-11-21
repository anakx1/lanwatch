"""SQLite-backed scan history.

The inventory file stays the source of truth for the current state; this
module records one row per completed scan so the dashboard and CLI can show
trends and per-device presence.  SQLite is part of the standard library, so
it works on Termux without extra packages.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import threading
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from .model import Device, normalize_ip
from .store import default_state_path

SCHEMA_VERSION = 1
MAX_SCANS = 500
MAX_LIMIT = 200

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
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

CREATE TABLE IF NOT EXISTS scan_devices (
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

CREATE INDEX IF NOT EXISTS scan_devices_ip ON scan_devices(ip);
"""


def default_history_path(state_path: Path | str | None = None) -> Path:
    """Return the history database path for an inventory file."""
    override = os.environ.get("LANWATCH_HISTORY")
    if override:
        return Path(override).expanduser()
    base = Path(state_path).expanduser() if state_path else default_state_path()
    return base.with_name(f"{base.stem}-history.db")


class HistoryStore:
    """SQLite scan history with a bounded number of retained scans."""

    def __init__(self, path: Path | str | None = None, max_scans: int = MAX_SCANS) -> None:
        self.path = Path(path) if path else default_history_path()
        self.max_scans = max(1, int(max_scans))
        self._schema_lock = threading.Lock()
        self._schema_ready = False

    # -- connection handling ---------------------------------------------

    @contextlib.contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            self._ensure_schema(connection)
            yield connection
        finally:
            connection.close()

    def _ensure_schema(self, connection: sqlite3.Connection) -> None:
        with self._schema_lock:
            if self._schema_ready:
                return
            connection.executescript(_SCHEMA)
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            connection.commit()
            self._schema_ready = True

    # -- writing ---------------------------------------------------------

    def record_scan(
        self,
        devices: Iterable[Device],
        *,
        started_at: float,
        finished_at: float,
        duration_s: float | None = None,
        subnet: str | None = None,
        interface: str | None = None,
        hosts_total: int = 0,
        hosts_up: int = 0,
        stopped: bool = False,
        error: str | None = None,
    ) -> int:
        """Persist one scan and its devices, returning the scan row id."""
        rows = [
            (
                device.ip,
                device.display_name,
                device.hostname or device.nbns_name,
                device.mac,
                device.vendor,
                device.rtt_ms,
                ",".join(str(port) for port in sorted(set(device.ports))),
            )
            for device in devices
        ]
        found = len(rows)
        with self._connection() as connection, connection:
            cursor = connection.execute(
                """
                INSERT INTO scans (
                    started_at, finished_at, duration_s, subnet, interface,
                    hosts_total, hosts_up, devices_found, stopped, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    float(started_at),
                    float(finished_at),
                    None if duration_s is None else float(duration_s),
                    subnet,
                    interface,
                    int(hosts_total),
                    int(hosts_up),
                    found,
                    1 if stopped else 0,
                    error,
                ),
            )
            scan_id = int(cursor.lastrowid or 0)
            if rows:
                connection.executemany(
                    """
                    INSERT INTO scan_devices (
                        scan_id, ip, name, hostname, mac, vendor, latency_ms, ports
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [(scan_id, *row) for row in rows],
                )
            connection.execute(
                """
                DELETE FROM scans
                WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?)
                """,
                (self.max_scans,),
            )
        return scan_id

    # -- reading ---------------------------------------------------------

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the newest scans first."""
        count = _clamp_limit(limit, 20)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, started_at, finished_at, duration_s, subnet, interface,
                       hosts_total, hosts_up, devices_found, stopped, error
                FROM scans
                ORDER BY id DESC
                LIMIT ?
                """,
                (count,),
            ).fetchall()
        return [_scan_dict(row) for row in rows]

    def device_history(self, ip: str, limit: int = 50) -> list[dict[str, Any]]:
        """Return the scans in which *ip* was seen, newest first."""
        address = normalize_ip(ip)
        count = _clamp_limit(limit, 50)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT s.id AS scan_id, s.finished_at, s.subnet,
                       d.name, d.hostname, d.mac, d.vendor, d.latency_ms, d.ports
                FROM scan_devices AS d
                JOIN scans AS s ON s.id = d.scan_id
                WHERE d.ip = ?
                ORDER BY s.id DESC
                LIMIT ?
                """,
                (address, count),
            ).fetchall()
        visits = []
        for row in rows:
            visit = _row_dict(row)
            visit["ports"] = _decode_ports(str(visit.get("ports") or ""))
            visits.append(visit)
        return visits

    def count(self) -> int:
        with self._connection() as connection:
            row = connection.execute("SELECT COUNT(*) FROM scans").fetchone()
        return int(row[0]) if row else 0


def _clamp_limit(limit: int, default: int) -> int:
    try:
        number = int(limit)
    except (TypeError, ValueError):
        return default
    return max(1, min(MAX_LIMIT, number))


def _row_dict(row: sqlite3.Row) -> dict[str, Any]:
    keys = row.keys()
    return {key: row[key] for key in keys}


def _scan_dict(row: sqlite3.Row) -> dict[str, Any]:
    scan = _row_dict(row)
    scan["stopped"] = bool(scan.get("stopped"))
    return scan


def _decode_ports(value: str) -> list[int]:
    ports = set()
    for part in value.split(","):
        part = part.strip()
        if part.isdigit():
            port = int(part)
            if 0 < port < 65536:
                ports.add(port)
    return sorted(ports)
