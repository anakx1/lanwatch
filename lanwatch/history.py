"""SQLite-backed scan history and Event Center storage.

The inventory file stays the source of truth for the current state; this
module records one row per completed scan so the dashboard and CLI can show
trends and per-device presence.  The same database also stores durable events
for the Event Center.  SQLite is part of the standard library, so it works on
Termux without extra packages.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import threading
import time
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from .events import Event
from .model import Device, normalize_ip
from .store import default_state_path

SCHEMA_VERSION = 4
MAX_SCANS = 500
MAX_LIMIT = 200
MAX_EVENTS = 5000
MAX_EVENT_AGE_DAYS = 180

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
    error TEXT,
    network_id TEXT,
    baseline INTEGER NOT NULL DEFAULT 0,
    new_devices INTEGER NOT NULL DEFAULT 0,
    returned_devices INTEGER NOT NULL DEFAULT 0,
    offline_devices INTEGER NOT NULL DEFAULT 0,
    changed_devices INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_devices (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    name TEXT,
    hostname TEXT,
    mac TEXT,
    vendor TEXT,
    kind TEXT,
    latency_ms REAL,
    ports TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, ip)
);

CREATE INDEX IF NOT EXISTS scan_devices_ip ON scan_devices(ip);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    network_id TEXT,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    device_ip TEXT,
    device_name TEXT,
    title TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',
    read_at REAL,
    event_key TEXT
);

CREATE INDEX IF NOT EXISTS events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS events_unread ON events(read_at, ts DESC);
CREATE INDEX IF NOT EXISTS events_network ON events(network_id, ts DESC);
CREATE INDEX IF NOT EXISTS events_device ON events(device_ip, ts DESC);
CREATE INDEX IF NOT EXISTS events_type ON events(type, ts DESC);
CREATE INDEX IF NOT EXISTS events_severity ON events(severity, ts DESC);
"""

_EXTRA_SCAN_COLUMNS = {
    "network_id": "TEXT",
    "baseline": "INTEGER NOT NULL DEFAULT 0",
    "new_devices": "INTEGER NOT NULL DEFAULT 0",
    "returned_devices": "INTEGER NOT NULL DEFAULT 0",
    "offline_devices": "INTEGER NOT NULL DEFAULT 0",
    "changed_devices": "INTEGER NOT NULL DEFAULT 0",
}

_EXTRA_SCAN_DEVICE_COLUMNS = {
    "kind": "TEXT",
}

_EXTRA_EVENT_COLUMNS = {
    "device_name": "TEXT",
    "event_key": "TEXT",
}


def default_history_path(state_path: Path | str | None = None) -> Path:
    """Return the history database path for an inventory file."""
    override = os.environ.get("LANWATCH_HISTORY")
    if override:
        return Path(override).expanduser()
    base = Path(state_path).expanduser() if state_path else default_state_path()
    return base.with_name(f"{base.stem}-history.db")


class HistoryStore:
    """SQLite scan history and durable events, bounded in size."""

    def __init__(
        self,
        path: Path | str | None = None,
        max_scans: int = MAX_SCANS,
        max_events: int = MAX_EVENTS,
        max_event_age_days: int = MAX_EVENT_AGE_DAYS,
    ) -> None:
        self.path = Path(path) if path else default_history_path()
        self.max_scans = max(1, int(max_scans))
        self.max_events = max(1, int(max_events))
        self.max_event_age_days = max(1, int(max_event_age_days))
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
            _add_missing_columns(connection, "scans", _EXTRA_SCAN_COLUMNS)
            _add_missing_columns(
                connection, "scan_devices", _EXTRA_SCAN_DEVICE_COLUMNS
            )
            _add_missing_columns(connection, "events", _EXTRA_EVENT_COLUMNS)
            connection.execute(
                "UPDATE events SET severity = 'info' WHERE severity = 'notice'"
            )
            # Keyed scan events are idempotent.  Remove any pre-index duplicate
            # keys before adding the unique index.
            connection.execute(
                """
                DELETE FROM events
                WHERE event_key IS NOT NULL
                  AND id NOT IN (
                      SELECT MIN(id) FROM events
                      WHERE event_key IS NOT NULL
                      GROUP BY event_key
                  )
                """
            )
            connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS events_event_key
                ON events(event_key) WHERE event_key IS NOT NULL
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS scans_network ON scans(network_id, id DESC)"
            )
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
        network_id: str | None = None,
        baseline: bool = False,
        new_devices: int = 0,
        returned_devices: int = 0,
        offline_devices: int = 0,
        changed_devices: int = 0,
        events: Iterable[Event] | None = None,
    ) -> int:
        """Persist one scan, its devices and optional events in one transaction."""
        rows = [
            (
                device.ip,
                device.display_name,
                device.hostname or device.nbns_name,
                device.mac,
                device.vendor,
                device.guess_kind(),
                device.rtt_ms,
                ",".join(str(port) for port in sorted(set(device.ports))),
            )
            for device in devices
        ]
        found = len(rows)
        event_list = list(events or [])
        scan_stamp = (
            network_id or "",
            round(float(started_at), 6),
            round(float(finished_at), 6),
        )
        for event in event_list:
            if event.key is None:
                event.key = _scan_event_key(scan_stamp, event)
        with self._connection() as connection, connection:
            cursor = connection.execute(
                """
                INSERT INTO scans (
                    started_at, finished_at, duration_s, subnet, interface,
                    hosts_total, hosts_up, devices_found, stopped, error,
                    network_id, baseline, new_devices, returned_devices,
                    offline_devices, changed_devices
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    network_id,
                    1 if baseline else 0,
                    int(new_devices),
                    int(returned_devices),
                    int(offline_devices),
                    int(changed_devices),
                ),
            )
            scan_id = int(cursor.lastrowid or 0)
            if rows:
                connection.executemany(
                    """
                    INSERT INTO scan_devices (
                        scan_id, ip, name, hostname, mac, vendor, kind,
                        latency_ms, ports
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [(scan_id, *row) for row in rows],
                )
            for event in event_list:
                self._insert_event(connection, event, scan_id)
            self._prune_scans(connection)
            if event_list:
                self._prune_events(connection)
        return scan_id

    def record_event(self, event: Event) -> int:
        """Persist one durable event and return its row id."""
        with self._connection() as connection, connection:
            event_id = self._insert_event(connection, event, None)
            self._prune_events(connection)
        return event_id

    def _insert_event(
        self, connection: sqlite3.Connection, event: Event, scan_id: int | None
    ) -> int:
        actual_scan_id = event.scan_id if event.scan_id is not None else scan_id
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO events (
                ts, network_id, scan_id, type, severity, device_ip,
                device_name, title, message, details, read_at, event_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                float(event.ts),
                event.network_id,
                actual_scan_id,
                event.type,
                event.severity,
                event.device_ip,
                event.device_name,
                event.title,
                event.message,
                json.dumps(event.details, default=str),
                event.read_at,
                event.key,
            ),
        )
        if cursor.rowcount == 0 and event.key:
            row = connection.execute(
                "SELECT id, scan_id FROM events WHERE event_key = ?", (event.key,)
            ).fetchone()
            if row is not None:
                event.id = int(row["id"])
                event.scan_id = (
                    int(row["scan_id"]) if row["scan_id"] is not None else actual_scan_id
                )
                return event.id
        event_id = int(cursor.lastrowid or 0)
        event.id = event_id
        event.scan_id = actual_scan_id
        return event_id

    def _prune_scans(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            DELETE FROM scans
            WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?)
            """,
            (self.max_scans,),
        )

    def _prune_events(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            DELETE FROM events
            WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)
            """,
            (self.max_events,),
        )
        cutoff = time.time() - self.max_event_age_days * 86400
        connection.execute("DELETE FROM events WHERE ts < ?", (cutoff,))

    # -- readings --------------------------------------------------------

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return the newest scans first."""
        count = _clamp_limit(limit, 20)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, started_at, finished_at, duration_s, subnet, interface,
                       hosts_total, hosts_up, devices_found, stopped, error,
                       network_id, baseline, new_devices, returned_devices,
                       offline_devices, changed_devices
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
                SELECT s.id AS scan_id, s.finished_at, s.subnet, s.network_id,
                       d.name, d.hostname, d.mac, d.vendor, d.kind, d.latency_ms, d.ports
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

    def scan_snapshot(self, scan_id: int) -> dict[str, Any] | None:
        """Return one scan including its decoded device rows."""
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT id, started_at, finished_at, duration_s, subnet, interface,
                       hosts_total, hosts_up, devices_found, stopped, error,
                       network_id, baseline, new_devices, returned_devices,
                       offline_devices, changed_devices
                FROM scans
                WHERE id = ?
                """,
                (int(scan_id),),
            ).fetchone()
            if row is None:
                return None
            devices = connection.execute(
                """
                SELECT ip, name, hostname, mac, vendor, kind, latency_ms, ports
                FROM scan_devices
                WHERE scan_id = ?
                ORDER BY ip
                """,
                (int(scan_id),),
            ).fetchall()
        snapshot = _scan_dict(row)
        snapshot["devices"] = [_snapshot_device(row) for row in devices]
        return snapshot

    def previous_snapshot(
        self,
        network_id: str | None,
        subnet: str | None,
        before_scan_id: int | None = None,
    ) -> dict[str, Any] | None:
        """Return the latest completed scan for this network before a scan."""
        where = ["stopped = 0", "error IS NULL"]
        params: list[Any] = []
        if before_scan_id is not None:
            where.append("id < ?")
            params.append(int(before_scan_id))
        if network_id:
            where.append("(network_id = ? OR (network_id IS NULL AND subnet = ?))")
            params.extend([network_id, subnet])
        else:
            where.append("network_id IS NULL AND subnet = ?")
            params.append(subnet)
        with self._connection() as connection:
            row = connection.execute(
                f"""
                SELECT id, started_at, finished_at, duration_s, subnet, interface,
                       hosts_total, hosts_up, devices_found, stopped, error,
                       network_id, baseline, new_devices, returned_devices,
                       offline_devices, changed_devices
                FROM scans
                WHERE {' AND '.join(where)}
                ORDER BY id DESC
                LIMIT 1
                """,
                params,
            ).fetchone()
            if row is None:
                return None
            devices = connection.execute(
                """
                SELECT ip, name, hostname, mac, vendor, kind, latency_ms, ports
                FROM scan_devices
                WHERE scan_id = ?
                ORDER BY ip
                """,
                (int(row["id"]),),
            ).fetchall()
        snapshot = _scan_dict(row)
        snapshot["devices"] = [_snapshot_device(item) for item in devices]
        return snapshot

    def seen_before(
        self,
        network_id: str | None,
        subnet: str | None,
        ip: str,
        before_scan_id: int | None,
    ) -> bool:
        """Whether *ip* appeared in an older completed scan on this network."""
        if before_scan_id is None:
            return False
        where = ["s.stopped = 0", "s.error IS NULL", "s.id < ?", "d.ip = ?"]
        params: list[Any] = [int(before_scan_id), ip]
        if network_id:
            where.append("(s.network_id = ? OR (s.network_id IS NULL AND s.subnet = ?))")
            params.extend([network_id, subnet])
        else:
            where.append("s.network_id IS NULL AND s.subnet = ?")
            params.append(subnet)
        with self._connection() as connection:
            row = connection.execute(
                f"""
                SELECT 1
                FROM scan_devices AS d
                JOIN scans AS s ON s.id = d.scan_id
                WHERE {' AND '.join(where)}
                LIMIT 1
                """,
                params,
            ).fetchone()
        return row is not None

    def count(self) -> int:
        with self._connection() as connection:
            row = connection.execute("SELECT COUNT(*) FROM scans").fetchone()
        return int(row[0]) if row else 0

    # -- event log -------------------------------------------------------

    def event_log(
        self,
        limit: int = 50,
        *,
        before_id: int | None = None,
        severities: Iterable[str] | None = None,
        event_type: str | None = None,
        network_id: str | None = None,
        device: str | None = None,
        unread: bool = False,
    ) -> list[dict[str, Any]]:
        """Return the newest Event Center entries first."""
        count = _clamp_limit(limit, 50)
        where: list[str] = []
        params: list[Any] = []
        if before_id is not None:
            where.append("id < ?")
            params.append(int(before_id))
        if severities:
            values = [value for value in severities if value]
            if values:
                where.append(f"severity IN ({', '.join('?' for _ in values)})")
                params.extend(values)
        if event_type:
            where.append("type = ?")
            params.append(event_type)
        if network_id:
            where.append("(network_id = ? OR network_id IS NULL)")
            params.append(network_id)
        if device:
            where.append("device_ip = ?")
            params.append(device)
        if unread:
            where.append("read_at IS NULL")
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        with self._connection() as connection:
            rows = connection.execute(
                f"""
                SELECT id, ts, network_id, scan_id, type, severity, device_ip,
                       device_name, title, message, details, read_at
                FROM events
                {clause}
                ORDER BY id DESC
                LIMIT ?
                """,
                [*params, count],
            ).fetchall()
        return [Event.from_mapping(_row_dict(row)).to_dict() for row in rows]

    def unread_count(self, network_id: str | None = None) -> int:
        where = "read_at IS NULL"
        params: list[Any] = []
        if network_id:
            where += " AND (network_id = ? OR network_id IS NULL)"
            params.append(network_id)
        with self._connection() as connection:
            row = connection.execute(
                f"SELECT COUNT(*) FROM events WHERE {where}", params
            ).fetchone()
        return int(row[0]) if row else 0

    def mark_events_read(
        self,
        ids: Iterable[int] | None = None,
        *,
        all_events: bool = False,
        network_id: str | None = None,
    ) -> int:
        """Mark events read and return the number of rows changed."""
        with self._connection() as connection, connection:
            if all_events:
                where = "read_at IS NULL"
                params: list[Any] = [time.time()]
                if network_id:
                    where += " AND (network_id = ? OR network_id IS NULL)"
                    params.append(network_id)
                cursor = connection.execute(
                    f"UPDATE events SET read_at = ? WHERE {where}", params
                )
                return int(cursor.rowcount or 0)
            values = [int(value) for value in (ids or [])]
            if not values:
                return 0
            placeholders = ", ".join("?" for _ in values)
            params = [time.time(), *values]
            where = f"id IN ({placeholders}) AND read_at IS NULL"
            if network_id:
                where += " AND (network_id = ? OR network_id IS NULL)"
                params.append(network_id)
            cursor = connection.execute(
                f"UPDATE events SET read_at = ? WHERE {where}", params
            )
            return int(cursor.rowcount or 0)

    def event_count(self) -> int:
        with self._connection() as connection:
            row = connection.execute("SELECT COUNT(*) FROM events").fetchone()
        return int(row[0]) if row else 0


def _scan_event_key(scan_stamp: tuple[str, float, float], event: Event) -> str:
    """Stable key for idempotent scan-event insertion.

    A scan is identified by its network and start/finish timestamps.  If the
    same completed scan is handed to the recorder twice, all event keys match
    and the unique index keeps the log unchanged.
    """
    payload = json.dumps(
        {
            "scan": scan_stamp,
            "type": event.type,
            "device_ip": event.device_ip,
            "device_name": event.device_name,
            "title": event.title,
            "message": event.message,
            "details": event.details,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _add_missing_columns(
    connection: sqlite3.Connection, table: str, definitions: dict[str, str]
) -> None:
    """Apply additive schema migrations, tolerating a concurrent migrator."""
    columns = {
        str(row["name"])
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }
    for name, definition in definitions.items():
        if name in columns:
            continue
        try:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise


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
    scan["baseline"] = bool(scan.get("baseline"))
    for key in (
        "new_devices",
        "returned_devices",
        "offline_devices",
        "changed_devices",
        "hosts_total",
        "hosts_up",
        "devices_found",
    ):
        scan[key] = int(scan.get(key) or 0)
    return scan


def _snapshot_device(row: sqlite3.Row) -> dict[str, Any]:
    device = _row_dict(row)
    device["ports"] = _decode_ports(str(device.get("ports") or ""))
    return device


def _decode_ports(value: str) -> list[int]:
    ports = set()
    for part in value.split(","):
        part = part.strip()
        if part.isdigit():
            port = int(part)
            if 0 < port < 65536:
                ports.add(port)
    return sorted(ports)
