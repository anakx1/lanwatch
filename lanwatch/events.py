"""Persistent network events used by the Event Center.

The scan engine already publishes short-lived SSE messages.  This module is the
small, pure part of the durable event log: event records and builders.  SQLite
persistence lives in :mod:`lanwatch.history` so the event log shares the same
database and migration path as scan history.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .changes import DeviceChange
    from .model import Device

SEVERITIES = ("info", "notice", "warning", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


@dataclass
class Event:
    """One durable Event Center entry."""

    type: str
    severity: str
    title: str
    message: str = ""
    ts: float = field(default_factory=time.time)
    network_id: str | None = None
    scan_id: int | None = None
    device_ip: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    id: int | None = None
    read_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts,
            "network_id": self.network_id,
            "scan_id": self.scan_id,
            "type": self.type,
            "severity": self.severity,
            "device_ip": self.device_ip,
            "title": self.title,
            "message": self.message,
            "details": self.details,
            "read_at": self.read_at,
            "read": self.read_at is not None,
        }

    @classmethod
    def from_mapping(cls, row: Mapping[str, Any]) -> Event:
        details = row.get("details")
        if isinstance(details, str):
            try:
                import json

                parsed = json.loads(details)
                details = parsed if isinstance(parsed, dict) else {}
            except ValueError:
                details = {}
        if not isinstance(details, dict):
            details = {}
        event_id = row.get("id")
        scan_id = row.get("scan_id")
        read_at = row.get("read_at")
        return cls(
            id=int(event_id) if isinstance(event_id, (int, float)) else None,
            ts=float(row.get("ts") or time.time()),
            network_id=str(row["network_id"]) if row.get("network_id") is not None else None,
            scan_id=int(scan_id) if isinstance(scan_id, (int, float)) else None,
            type=str(row.get("type") or "unknown"),
            severity=str(row.get("severity") or "info"),
            device_ip=str(row["device_ip"]) if row.get("device_ip") is not None else None,
            title=str(row.get("title") or ""),
            message=str(row.get("message") or ""),
            details=details,
            read_at=float(read_at) if isinstance(read_at, (int, float)) else None,
        )


def event_from_change(
    change: DeviceChange, network_id: str | None, scan_id: int | None = None
) -> Event:
    """Turn a scan-comparison change into a durable event."""
    return Event(
        type=change.event_type,
        severity=change.severity,
        title=change.title,
        message=change.message,
        network_id=network_id,
        scan_id=scan_id,
        device_ip=change.ip,
        details=change.details,
    )


def trust_event(device: Device, previous: str, network_id: str | None) -> Event:
    name = device.display_name
    title = f"{name} marked {device.trust}"
    return Event(
        type="device.trust_changed",
        severity="notice",
        title=title,
        message=f"{device.ip}: {previous} → {device.trust}",
        network_id=network_id,
        device_ip=device.ip,
        details={"before": previous, "after": device.trust},
    )


def scan_failure_event(error: str, network_id: str | None, scan_id: int | None = None) -> Event:
    return Event(
        type="scan.failed",
        severity="warning",
        title="Scan failed",
        message=error,
        network_id=network_id,
        scan_id=scan_id,
        details={"error": error},
    )


def baseline_event(network_id: str | None, devices: int) -> Event:
    return Event(
        type="scan.baseline",
        severity="info",
        title="Network baseline recorded",
        message=f"{devices} device{'s' if devices != 1 else ''} in the first completed scan",
        network_id=network_id,
        details={"devices": devices},
    )


def events_for_diff(
    diff: Any, network_id: str | None, scan_id: int | None = None
) -> list[Event]:
    """Build durable events for a :class:`lanwatch.changes.ScanDiff`."""
    if getattr(diff, "baseline", False):
        return [baseline_event(network_id, int(getattr(diff, "current_devices", 0)))]
    events = [
        event_from_change(change, network_id, scan_id)
        for change in getattr(diff, "changes", [])
    ]
    return events
