"""Persistent network events used by the Event Center.

The scan engine already publishes short-lived SSE messages.  This module is the
small, pure part of the durable event log: event records and builders.  SQLite
persistence lives in :mod:`lanwatch.history` so the event log shares the same
database and migration path as scan history.

Severity is deliberately conservative.  A new device is noteworthy, not
malicious.  ``critical`` is reserved for a same-address MAC replacement, which
is the only change detected here that can indicate identity spoofing.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .changes import DeviceChange
    from .model import Device

SEVERITIES = ("info", "warning", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

# Required Event Center categories, plus three comparison-only categories that
# preserve useful Phase 2 identity signals and the existing trust control.
EVENT_TYPES = (
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
    "device.ip_changed",
    "device.replaced",
    "device.trust_changed",
)

SEVERITY_BY_TYPE = {
    "device.new": "warning",
    "device.online": "info",
    "device.offline": "warning",
    "device.hostname_changed": "info",
    "device.vendor_changed": "info",
    "device.kind_changed": "info",
    "port.opened": "info",
    "port.closed": "info",
    "scan.completed": "info",
    "scan.failed": "warning",
    "device.ip_changed": "info",
    "device.replaced": "critical",
    "device.trust_changed": "info",
}


def severity_for(event_type: str) -> str:
    """Return the documented severity for an event type."""
    return SEVERITY_BY_TYPE.get(event_type, "info")


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
    device_name: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    id: int | None = None
    read_at: float | None = None
    # Stable internal dedupe key for events produced by a scan.  It is not
    # exposed through the public API.
    key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts,
            "network_id": self.network_id,
            "scan_id": self.scan_id,
            "type": self.type,
            "severity": self.severity,
            "device_ip": self.device_ip,
            "device_name": self.device_name,
            "title": self.title,
            "message": self.message,
            "description": self.message,
            "details": self.details,
            "before": self.details.get("before"),
            "after": self.details.get("after"),
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
            device_name=(
                str(row["device_name"])
                if row.get("device_name") is not None
                else None
            ),
            title=str(row.get("title") or ""),
            message=str(row.get("message") or ""),
            details=details,
            read_at=float(read_at) if isinstance(read_at, (int, float)) else None,
            key=str(row["event_key"]) if row.get("event_key") is not None else None,
        )


def _details_dict(change: DeviceChange) -> dict[str, Any]:
    return dict(change.details) if isinstance(change.details, dict) else {}


def _device_name(change: DeviceChange) -> str | None:
    details = _details_dict(change)
    for key in ("after", "device", "before"):
        value = details.get(key)
        if isinstance(value, Mapping):
            name = value.get("name") or value.get("hostname") or value.get("ip")
            if name:
                return str(name)
    return None


def _ports_label(ports: list[int]) -> str:
    label = "Port" if len(ports) == 1 else "Ports"
    return f"{label} {', '.join(str(port) for port in ports)}"


def _field_event(
    change: DeviceChange,
    *,
    event_type: str,
    field_name: str,
    label: str,
    network_id: str | None,
) -> Event:
    details = _details_dict(change)
    before = details.get(f"{field_name}_before")
    after = details.get(f"{field_name}_after")
    name = _device_name(change)
    description = (
        f"{name or change.ip} ({change.ip}): {label} "
        f"{before or 'unknown'} → {after or 'unknown'}"
    )
    return Event(
        type=event_type,
        severity=severity_for(event_type),
        title=f"{label.capitalize()} changed on {name or change.ip}",
        message=description,
        network_id=network_id,
        scan_id=None,
        device_ip=change.ip,
        device_name=name,
        details={
            "before": details.get("before"),
            "after": details.get("after"),
            f"{field_name}_before": before,
            f"{field_name}_after": after,
            "fields": [field_name],
        },
    )


def _port_event(
    change: DeviceChange,
    *,
    event_type: str,
    ports: list[int],
    network_id: str | None,
) -> Event:
    details = _details_dict(change)
    name = _device_name(change)
    action = "opened" if event_type == "port.opened" else "closed"
    label = _ports_label(ports)
    return Event(
        type=event_type,
        severity=severity_for(event_type),
        title=f"{label} {action}",
        message=f"{name or change.ip} ({change.ip}): {label} {action}",
        network_id=network_id,
        device_ip=change.ip,
        device_name=name,
        details={
            "before": details.get("before"),
            "after": details.get("after"),
            "fields": ["ports_added" if action == "opened" else "ports_removed"],
            "ports": ports,
            "ports_added" if action == "opened" else "ports_removed": ports,
        },
    )


def events_from_change(
    change: DeviceChange, network_id: str | None
) -> list[Event]:
    """Expand one combined comparison change into Event Center records."""
    details = _details_dict(change)
    fields = set(details.get("fields") or [])
    name = _device_name(change)
    events: list[Event] = []

    if change.event_type == "device.services_changed":
        if "hostname" in fields:
            events.append(
                _field_event(
                    change,
                    event_type="device.hostname_changed",
                    field_name="hostname",
                    label="hostname",
                    network_id=network_id,
                )
            )
        if "vendor" in fields:
            events.append(
                _field_event(
                    change,
                    event_type="device.vendor_changed",
                    field_name="vendor",
                    label="vendor",
                    network_id=network_id,
                )
            )
        if "type" in fields:
            events.append(
                _field_event(
                    change,
                    event_type="device.kind_changed",
                    field_name="kind",
                    label="device type",
                    network_id=network_id,
                )
            )
        added = list(details.get("ports_added") or [])
        removed = list(details.get("ports_removed") or [])
        if added:
            events.append(
                _port_event(
                    change,
                    event_type="port.opened",
                    ports=added,
                    network_id=network_id,
                )
            )
        if removed:
            events.append(
                _port_event(
                    change,
                    event_type="port.closed",
                    ports=removed,
                    network_id=network_id,
                )
            )
        if events:
            return events

    event_type = {
        "device.returned": "device.online",
        "device.fingerprint_changed": "device.kind_changed",
    }.get(change.event_type, change.event_type)
    return [
        Event(
            type=event_type,
            severity=severity_for(event_type),
            title=change.title,
            message=change.message,
            network_id=network_id,
            device_ip=change.ip,
            device_name=name,
            details=details,
        )
    ]


def trust_event(device: Device, previous: str, network_id: str | None) -> Event:
    name = device.display_name
    title = f"{name} marked {device.trust}"
    return Event(
        type="device.trust_changed",
        severity=severity_for("device.trust_changed"),
        title=title,
        message=f"{device.ip}: {previous} → {device.trust}",
        network_id=network_id,
        device_ip=device.ip,
        device_name=name,
        details={"before": previous, "after": device.trust},
    )


def scan_failure_event(error: str, network_id: str | None, scan_id: int | None = None) -> Event:
    return Event(
        type="scan.failed",
        severity=severity_for("scan.failed"),
        title="Scan failed",
        message=error,
        network_id=network_id,
        scan_id=scan_id,
        details={"error": error},
    )


def scan_completed_event(
    diff: Any, network_id: str | None, scan_id: int | None = None
) -> Event:
    """Build the completion event for a successful scan."""
    counts = dict(getattr(diff, "counts", {}) or {})
    current = int(getattr(diff, "current_devices", 0))
    baseline = bool(getattr(diff, "baseline", False))
    if baseline:
        title = "Scan completed — baseline"
        message = f"Baseline recorded with {current} device{'s' if current != 1 else ''}"
    else:
        title = "Scan completed"
        changes = (
            f"{counts.get('new', 0)} new · "
            f"{counts.get('returned', 0)} online again · "
            f"{counts.get('offline', 0)} offline · "
            f"{counts.get('changed', 0)} changed"
        )
        if not any(int(value or 0) for value in counts.values()):
            changes = "no changes"
        message = f"{current} device{'s' if current != 1 else ''} seen · {changes}"
    return Event(
        type="scan.completed",
        severity=severity_for("scan.completed"),
        title=title,
        message=message,
        network_id=network_id,
        scan_id=scan_id,
        details={
            "baseline": baseline,
            "current_devices": current,
            "counts": counts,
            "previous_scan_id": getattr(diff, "previous_scan_id", None),
        },
    )


def events_for_diff(
    diff: Any, network_id: str | None, scan_id: int | None = None
) -> list[Event]:
    """Build durable events for a :class:`lanwatch.changes.ScanDiff`."""
    events: list[Event] = []
    for change in getattr(diff, "changes", []):
        events.extend(events_from_change(change, network_id))
    # Keep the completion event last so a newest-first Event Center shows the
    # scan summary above the individual changes it contains.
    events.append(scan_completed_event(diff, network_id, scan_id))
    if scan_id is not None:
        for event in events:
            event.scan_id = scan_id
    return events
