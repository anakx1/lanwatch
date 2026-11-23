"""Pure scan comparison.

The inventory is keyed by IP, but a device can keep its MAC while moving to a
new address.  Comparison therefore tries IP first, MAC second, and only then
classifies a host as new.  This module does no I/O, which keeps the rules easy
to test and makes the Event Center independent from SQLite.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from . import oui
from .model import DEFAULT_TRUST, Device

INFO = "info"
NOTICE = "notice"
WARNING = "warning"
CRITICAL = "critical"


def _clean(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _ports(value: object) -> tuple[int, ...]:
    if isinstance(value, str):
        parts: Iterable[object] = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        parts = value
    else:
        parts = ()
    found: set[int] = set()
    for part in parts:
        try:
            number = int(str(part).strip())
        except (TypeError, ValueError):
            continue
        if 0 < number < 65536:
            found.add(number)
    return tuple(sorted(found))


@dataclass(frozen=True)
class SnapshotDevice:
    """The subset of a device persisted in a scan snapshot."""

    ip: str
    name: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    kind: str | None = None
    ports: tuple[int, ...] = ()
    trust: str = DEFAULT_TRUST

    @classmethod
    def from_device(cls, device: Device) -> SnapshotDevice:
        return cls(
            ip=device.ip,
            name=device.display_name,
            hostname=_clean(device.hostname or device.nbns_name),
            mac=oui.normalize_mac(device.mac),
            vendor=_clean(device.vendor),
            kind=_clean(device.guess_kind()),
            ports=tuple(sorted(set(device.ports))),
            trust=device.trust,
        )

    @classmethod
    def from_history(cls, raw: Mapping[str, Any]) -> SnapshotDevice:
        return cls(
            ip=str(raw.get("ip") or ""),
            name=str(raw.get("name") or raw.get("hostname") or raw.get("ip") or ""),
            hostname=_clean(raw.get("hostname")),
            mac=oui.normalize_mac(_clean(raw.get("mac"))),
            vendor=_clean(raw.get("vendor")),
            kind=_clean(raw.get("kind")),
            ports=_ports(raw.get("ports")),
            trust=str(raw.get("trust") or DEFAULT_TRUST),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "name": self.name,
            "hostname": self.hostname,
            "mac": self.mac,
            "vendor": self.vendor,
            "kind": self.kind,
            "ports": list(self.ports),
            "trust": self.trust,
        }


@dataclass
class DeviceChange:
    event_type: str
    severity: str
    ip: str
    title: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "ip": self.ip,
            "title": self.title,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ScanDiff:
    baseline: bool = False
    partial: bool = False
    previous_scan_id: int | None = None
    changes: list[DeviceChange] = field(default_factory=list)
    new_devices: int = 0
    returned_devices: int = 0
    offline_devices: int = 0
    changed_devices: int = 0
    current_devices: int = 0
    new_ips: list[str] = field(default_factory=list)
    changed_ips: list[str] = field(default_factory=list)
    offline_ips: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return {
            "new": self.new_devices,
            "returned": self.returned_devices,
            "offline": self.offline_devices,
            "changed": self.changed_devices,
        }

    @property
    def total_changes(self) -> int:
        return len(self.changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline,
            "partial": self.partial,
            "previous_scan_id": self.previous_scan_id,
            "counts": self.counts,
            "new_ips": list(self.new_ips),
            "changed_ips": list(self.changed_ips),
            "offline_ips": list(self.offline_ips),
            "changes": [change.to_dict() for change in self.changes],
            "current_devices": self.current_devices,
        }


def _ignored(snapshot: SnapshotDevice, trust_by_ip: Mapping[str, str] | None) -> bool:
    if snapshot.trust == "ignored":
        return True
    return bool(trust_by_ip and trust_by_ip.get(snapshot.ip) == "ignored")


def _text_key(value: object) -> str:
    return str(value or "").strip().casefold()


def _device_summary(device: SnapshotDevice) -> str:
    """Compact identity line for new/returned device events."""
    parts = [device.ip]
    for value in (device.hostname, device.vendor, device.kind):
        if value and value != "device" and value not in parts:
            parts.append(value)
    return " · ".join(parts)


def _port_summary(ports: list[int], action: str) -> str:
    label = "Port" if len(ports) == 1 else "Ports"
    return f"{label} {', '.join(str(port) for port in ports)} {action}"


def _changed_fields(
    previous: SnapshotDevice, current: SnapshotDevice
) -> DeviceChange | None:
    added = sorted(set(current.ports) - set(previous.ports))
    removed = sorted(set(previous.ports) - set(current.ports))
    hostname_changed = _text_key(previous.hostname) != _text_key(current.hostname)
    vendor_changed = _text_key(previous.vendor) != _text_key(current.vendor)
    # Older history rows have no type column.  Do not report every device as
    # "changed" just because it was recorded before type snapshots existed.
    kind_changed = bool(
        _text_key(previous.kind)
        and _text_key(current.kind)
        and _text_key(previous.kind) != _text_key(current.kind)
    )
    if not added and not removed and not hostname_changed and not vendor_changed and not kind_changed:
        return None

    fields = []
    if hostname_changed:
        fields.append("hostname")
    if vendor_changed:
        fields.append("vendor")
    if kind_changed:
        fields.append("type")
    if added:
        fields.append("ports_added")
    if removed:
        fields.append("ports_removed")

    details: dict[str, Any] = {
        "before": previous.to_dict(),
        "after": current.to_dict(),
        "fields": fields,
    }
    if added:
        details["ports_added"] = added
    if removed:
        details["ports_removed"] = removed
    if hostname_changed:
        details["hostname_before"] = previous.hostname
        details["hostname_after"] = current.hostname
    if vendor_changed:
        details["vendor_before"] = previous.vendor
        details["vendor_after"] = current.vendor
    if kind_changed:
        details["kind_before"] = previous.kind
        details["kind_after"] = current.kind

    bits = []
    if hostname_changed:
        bits.append(f"hostname {previous.hostname or 'unknown'} → {current.hostname or 'unknown'}")
    if vendor_changed:
        if previous.vendor and current.vendor:
            bits.append(f"vendor {previous.vendor} → {current.vendor}")
        elif current.vendor:
            bits.append(f"vendor became {current.vendor}")
        else:
            bits.append(f"vendor no longer reported ({previous.vendor})")
    if kind_changed:
        bits.append(f"type {previous.kind} → {current.kind}")
    if added:
        bits.append(_port_summary(added, "opened"))
    if removed:
        bits.append(_port_summary(removed, "closed"))

    if added or removed:
        event_type = "device.services_changed"
        title = f"Services changed on {current.name}"
        if added and current.trust != "trusted":
            severity = WARNING
        elif added:
            severity = NOTICE
        else:
            severity = INFO
    elif hostname_changed:
        event_type = "device.hostname_changed"
        title = f"Hostname changed on {current.name}"
        severity = INFO
    elif vendor_changed:
        event_type = "device.vendor_changed"
        title = f"Vendor changed on {current.name}"
        severity = INFO
    else:
        event_type = "device.fingerprint_changed"
        title = f"Device type changed on {current.name}"
        severity = INFO

    return DeviceChange(
        event_type=event_type,
        severity=severity,
        ip=current.ip,
        title=title,
        message=" · ".join(bits),
        details=details,
    )


def compare_snapshots(
    previous: Iterable[SnapshotDevice | Mapping[str, Any]] | None,
    current: Iterable[SnapshotDevice | Mapping[str, Any]],
    *,
    previous_scan_id: int | None = None,
    baseline: bool | None = None,
    partial: bool = False,
    inventory_trust: Mapping[str, str] | None = None,
    is_returning: Callable[[str], bool] | None = None,
) -> ScanDiff:
    """Compare two scan snapshots and return human- and machine-readable changes.

    ``previous`` is the last completed, non-stopped, non-error snapshot.  The
    first completed scan is a baseline: it creates no per-device events.
    """
    current_items = [
        item if isinstance(item, SnapshotDevice) else SnapshotDevice.from_history(item)
        for item in current
    ]
    diff = ScanDiff(
        baseline=baseline if baseline is not None else previous is None,
        partial=partial,
        previous_scan_id=previous_scan_id,
        current_devices=sum(
            1 for item in current_items if not _ignored(item, inventory_trust)
        ),
    )
    if diff.baseline or partial or previous is None:
        return diff

    previous_items = [
        item if isinstance(item, SnapshotDevice) else SnapshotDevice.from_history(item)
        for item in previous
    ]
    previous_by_ip = {item.ip: item for item in previous_items}
    previous_by_mac = {item.mac: item for item in previous_items if item.mac}
    current_by_ip = {item.ip: item for item in current_items}
    current_by_mac = {item.mac: item for item in current_items if item.mac}
    claimed_previous: set[int] = set()
    claimed_current: set[int] = set()

    def claim(previous_item: SnapshotDevice, current_item: SnapshotDevice) -> None:
        claimed_previous.add(id(previous_item))
        claimed_current.add(id(current_item))

    for current_item in current_items:
        if id(current_item) in claimed_current:
            continue
        previous_item = previous_by_ip.get(current_item.ip)
        if previous_item is not None and id(previous_item) not in claimed_previous:
            if (
                previous_item.mac
                and current_item.mac
                and previous_item.mac != current_item.mac
            ):
                claim(previous_item, current_item)
                if not _ignored(current_item, inventory_trust):
                    diff.changes.append(
                        DeviceChange(
                            event_type="device.replaced",
                            severity=CRITICAL,
                            ip=current_item.ip,
                            title=f"Device identity changed at {current_item.ip}",
                            message=(
                                f"MAC changed from {previous_item.mac} "
                                f"to {current_item.mac}"
                            ),
                            details={
                                "before": previous_item.to_dict(),
                                "after": current_item.to_dict(),
                            },
                        )
                    )
                    diff.changed_devices += 1
                    diff.changed_ips.append(current_item.ip)
                continue
            claim(previous_item, current_item)
            change = _changed_fields(previous_item, current_item)
            if change is not None and not _ignored(current_item, inventory_trust):
                diff.changes.append(change)
                diff.changed_devices += 1
                diff.changed_ips.append(current_item.ip)
            continue

        if current_item.mac and current_item.mac in previous_by_mac:
            previous_item = previous_by_mac[current_item.mac]
            if id(previous_item) not in claimed_previous:
                claim(previous_item, current_item)
                if not _ignored(current_item, inventory_trust):
                    diff.changes.append(
                        DeviceChange(
                            event_type="device.ip_changed",
                            severity=NOTICE,
                            ip=current_item.ip,
                            title=f"{current_item.name} changed address",
                            message=f"{previous_item.ip} → {current_item.ip}",
                            details={
                                "before": previous_item.to_dict(),
                                "after": current_item.to_dict(),
                            },
                        )
                    )
                    diff.changed_devices += 1
                    diff.changed_ips.append(current_item.ip)
                continue

        # No previous counterpart: distinguish a genuinely new host from one
        # that was seen before but missed the immediately previous scan.
        if _ignored(current_item, inventory_trust):
            continue
        returned = False
        if is_returning is not None:
            try:
                returned = bool(is_returning(current_item.ip))
            except Exception:  # pragma: no cover - defensive around history I/O
                returned = False
        if returned:
            diff.changes.append(
                DeviceChange(
                    event_type="device.returned",
                    severity=NOTICE,
                    ip=current_item.ip,
                    title=f"Known device returned: {current_item.name}",
                    message=_device_summary(current_item),
                    details={"device": current_item.to_dict()},
                )
            )
            diff.returned_devices += 1
            diff.changed_ips.append(current_item.ip)
        else:
            diff.changes.append(
                DeviceChange(
                    event_type="device.new",
                    severity=WARNING,
                    ip=current_item.ip,
                    title=f"New device: {current_item.name}",
                    message=_device_summary(current_item),
                    details={"device": current_item.to_dict()},
                )
            )
            diff.new_devices += 1
            diff.new_ips.append(current_item.ip)

    for previous_item in previous_items:
        if id(previous_item) in claimed_previous:
            continue
        if previous_item.ip in current_by_ip:
            continue
        if previous_item.mac and previous_item.mac in current_by_mac:
            continue
        trust = (
            inventory_trust.get(previous_item.ip)
            if inventory_trust and previous_item.ip in inventory_trust
            else previous_item.trust
        )
        if trust == "ignored":
            continue
        severity = WARNING if trust == "trusted" else INFO
        diff.changes.append(
            DeviceChange(
                event_type="device.offline",
                severity=severity,
                ip=previous_item.ip,
                title=f"Device offline: {previous_item.name}",
                message=previous_item.ip,
                details={"device": previous_item.to_dict()},
            )
        )
        diff.offline_devices += 1
        diff.offline_ips.append(previous_item.ip)

    return diff
