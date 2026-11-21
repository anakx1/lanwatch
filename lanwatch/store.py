"""Device inventory persistence, scoped per network.

Every network the machine has been scanned on gets its own inventory, so the
same ``192.168.1.0/24`` at home and at the office never mix, and a stale
router from last month's Wi-Fi is not shown next to today's.  A network is
identified by its CIDR plus, when it can be learned, the gateway's MAC.

``Store.devices`` and ``Store.network`` always refer to the *active* network,
which keeps the scan engine and the dashboard code simple.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import tempfile
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import Device, ip_sort_key, normalize_ip

SCHEMA_VERSION = 2
PLACEHOLDER_ID = "default"
MAX_LABEL = 60


def default_state_path() -> Path:
    override = os.environ.get("LANWATCH_STATE")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_STATE_HOME")
    if base:
        return Path(base).expanduser() / "lanwatch" / "devices.json"
    return Path.home() / ".local" / "state" / "lanwatch" / "devices.json"


@dataclass
class NetworkRecord:
    """One network's identity and device inventory."""

    id: str
    cidr: str | None = None
    label: str | None = None
    gateway: str | None = None
    gateway_mac: str | None = None
    info: dict[str, Any] = field(default_factory=dict)
    devices: dict[str, Device] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    archived: bool = False

    @property
    def title(self) -> str:
        return self.label or self.cidr or "Unnamed network"

    def persistable(self) -> bool:
        return bool(self.devices or self.info)

    def summary(self, active: bool = False) -> dict[str, Any]:
        online = sum(1 for device in self.devices.values() if device.online)
        return {
            "id": self.id,
            "cidr": self.cidr,
            "label": self.label,
            "title": self.title,
            "gateway": self.gateway,
            "gateway_mac": self.gateway_mac,
            "interface": self.info.get("interface"),
            "devices": len(self.devices),
            "online": online,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "archived": self.archived,
            "active": active,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "cidr": self.cidr,
            "label": self.label,
            "gateway": self.gateway,
            "gateway_mac": self.gateway_mac,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "archived": self.archived,
            "info": self.info,
            "devices": [self.devices[ip].to_dict() for ip in sorted(self.devices, key=ip_sort_key)],
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> NetworkRecord:
        record = cls(id=str(raw.get("id") or PLACEHOLDER_ID))
        record.cidr = _clean(raw.get("cidr"))
        record.label = _clean(raw.get("label"), MAX_LABEL)
        record.gateway = _clean(raw.get("gateway"))
        record.gateway_mac = _clean(raw.get("gateway_mac"))
        info = raw.get("info")
        if isinstance(info, dict):
            record.info = {str(k): v for k, v in info.items()}
        record.first_seen = _number(raw.get("first_seen"), record.first_seen)
        record.last_seen = _number(raw.get("last_seen"), record.first_seen)
        record.archived = bool(raw.get("archived"))
        for item in raw.get("devices") or []:
            if not isinstance(item, dict):
                continue
            try:
                device = Device.from_dict(item)
            except (ValueError, TypeError):
                continue
            record.devices[device.ip] = device
        return record


def _clean(value: object, limit: int = 128) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()[:limit]
    return text or None


def _number(value: object, default: float) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return default


class Store:
    """Thread-safe, per-network device inventory with an on-disk snapshot."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else default_state_path()
        self.lock = threading.RLock()
        self.networks: dict[str, NetworkRecord] = {}
        self.active_id: str | None = None
        self._detached: dict[str, Device] = {}
        self.load_error: str | None = None
        self.save_error: str | None = None
        self._touched: set[str] = set()
        self.load()

    # -- active network views ---------------------------------------------

    @property
    def active(self) -> NetworkRecord | None:
        return self.networks.get(self.active_id) if self.active_id else None

    @property
    def devices(self) -> dict[str, Device]:
        """Devices of the active network (an empty dict when there is none)."""
        record = self.active
        return record.devices if record is not None else self._detached

    @property
    def network(self) -> dict[str, Any] | None:
        record = self.active
        if record is None or not record.info:
            return None
        return record.info

    def all_devices(self) -> list[Device]:
        with self.lock:
            return [d for record in self.networks.values() for d in record.devices.values()]

    # -- persistence -----------------------------------------------------

    def load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            self.load_error = str(exc)
            return
        if not isinstance(raw, dict):
            self.load_error = "snapshot is not an object"
            return
        with self.lock:
            if isinstance(raw.get("networks"), list):
                self._load_v2(raw)
            else:
                self._load_v1(raw)
        self.load_error = None

    def _load_v2(self, raw: dict[str, Any]) -> None:
        self.networks.clear()
        for item in raw["networks"]:
            if not isinstance(item, dict):
                continue
            record = NetworkRecord.from_dict(item)
            while record.id in self.networks:
                record.id += "+"
            self.networks[record.id] = record
        active = raw.get("active")
        self.active_id = active if isinstance(active, str) and active in self.networks else None

    def _load_v1(self, raw: dict[str, Any]) -> None:
        """Migrate the flat pre-network inventory: group devices by their /24."""
        self.networks.clear()
        legacy_info = raw.get("network") if isinstance(raw.get("network"), dict) else None
        groups: dict[str, NetworkRecord] = {}
        for item in raw.get("devices") or []:
            if not isinstance(item, dict):
                continue
            try:
                device = Device.from_dict(item)
            except (ValueError, TypeError):
                continue
            cidr = str(ipaddress.ip_network(f"{device.ip}/24", strict=False))
            record = groups.get(cidr)
            if record is None:
                record = groups[cidr] = NetworkRecord(id=cidr, cidr=cidr)
            record.devices[device.ip] = device
        for record in groups.values():
            times = [d.last_seen for d in record.devices.values()]
            record.first_seen = min(d.first_seen for d in record.devices.values())
            record.last_seen = max(times)
            gateway = next((d.ip for d in record.devices.values() if d.is_gateway), None)
            record.gateway = gateway
        if legacy_info:
            cidr = str(legacy_info.get("cidr") or "")
            if cidr not in groups and cidr:
                groups[cidr] = NetworkRecord(id=cidr, cidr=cidr)
            if cidr in groups:
                groups[cidr].info = {str(k): v for k, v in legacy_info.items()}
                groups[cidr].gateway = legacy_info.get("gateway") or groups[cidr].gateway
                self.active_id = cidr
        self.networks = groups
        if self.active_id not in self.networks:
            self.active_id = None

    def save(self) -> bool:
        with self.lock:
            records = [r for r in self.networks.values() if r.persistable()]
            active = self.active_id if self.active_id in {r.id for r in records} else None
            payload = {
                "version": SCHEMA_VERSION,
                "saved_at": time.time(),
                "active": active,
                "networks": [record.to_dict() for record in records],
            }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, temp = tempfile.mkstemp(dir=self.path.parent, prefix=".devices-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=1, sort_keys=False)
                    handle.write("\n")
                os.replace(temp, self.path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(temp)
                raise
            self.save_error = None
            return True
        except OSError as exc:
            self.save_error = str(exc)
            return False

    # -- network management ------------------------------------------------

    def _unique_id(self, base: str) -> str:
        if base not in self.networks:
            return base
        number = 2
        while f"{base}#{number}" in self.networks:
            number += 1
        return f"{base}#{number}"

    def _rekey(self, record: NetworkRecord, new_id: str) -> None:
        self.networks.pop(record.id, None)
        record.id = self._unique_id(new_id)
        self.networks[record.id] = record
        self.active_id = record.id

    def _ensure_active(self) -> NetworkRecord:
        record = self.active
        if record is None:
            record = NetworkRecord(id=self._unique_id(PLACEHOLDER_ID))
            self.networks[record.id] = record
            self.active_id = record.id
        return record

    def find(self, cidr: str, gateway_mac: str | None = None) -> NetworkRecord | None:
        """Locate the record for *cidr*, using the gateway MAC to tell twins apart."""
        with self.lock:
            candidates = [r for r in self.networks.values() if r.cidr == cidr]
            if not candidates:
                return None
            if gateway_mac:
                exact = next((r for r in candidates if r.gateway_mac == gateway_mac), None)
                if exact is not None:
                    return exact
                return next((r for r in candidates if not r.gateway_mac), None)
            active = self.active
            if active is not None and active in candidates:
                return active
            return max(candidates, key=lambda r: r.last_seen)

    def activate(self, cidr: str, gateway_mac: str | None = None) -> NetworkRecord:
        """Make the network for *cidr* active, creating it when it is new.

        Same CIDR but a different gateway MAC is a different physical network
        (home vs office both on 192.168.1.0/24) and gets its own inventory.
        """
        cidr = str(ipaddress.ip_network(cidr, strict=False))
        with self.lock:
            record = self.find(cidr, gateway_mac)
            if record is None:
                current = self.active
                if current is not None and current.cidr is None:
                    record = current  # adopt the placeholder created by early upserts
                    record.cidr = cidr
                    self._rekey(record, cidr)
                else:
                    record = NetworkRecord(id=self._unique_id(cidr), cidr=cidr)
                    self.networks[record.id] = record
            if gateway_mac and not record.gateway_mac:
                record.gateway_mac = gateway_mac
            record.archived = False
            record.last_seen = time.time()
            if self.active_id != record.id:
                self._touched.clear()
            self.active_id = record.id
            return record

    def select(self, network_id: str) -> NetworkRecord | None:
        with self.lock:
            record = self.networks.get(network_id)
            if record is None:
                return None
            record.archived = False
            if self.active_id != record.id:
                self._touched.clear()
            self.active_id = record.id
            return record

    def archive(self, network_id: str, archived: bool = True) -> NetworkRecord | None:
        with self.lock:
            record = self.networks.get(network_id)
            if record is None:
                return None
            if archived and record.id == self.active_id:
                raise ValueError("the active network cannot be archived; switch to another first")
            record.archived = archived
            return record

    def rename_network(self, network_id: str, label: str | None) -> NetworkRecord | None:
        with self.lock:
            record = self.networks.get(network_id)
            if record is None:
                return None
            record.label = _clean(label, MAX_LABEL)
            return record

    def delete_network(self, network_id: str) -> bool:
        with self.lock:
            if network_id == self.active_id:
                raise ValueError("the active network cannot be deleted; switch to another first")
            return self.networks.pop(network_id, None) is not None

    def networks_summary(self) -> list[dict[str, Any]]:
        with self.lock:
            rows = [
                record.summary(active=record.id == self.active_id)
                for record in self.networks.values()
                if record.devices or record.info or record.id == self.active_id
            ]
        rows.sort(key=lambda r: (not r["active"], r["archived"], -float(r["last_seen"] or 0)))
        return rows

    def set_network(self, network: dict[str, Any]) -> None:
        cidr = network.get("cidr")
        mac = network.get("gateway_mac")
        with self.lock:
            record = self.active
            if isinstance(cidr, str) and cidr:
                if record is None or record.cidr not in (None, cidr):
                    record = self.activate(cidr, mac if isinstance(mac, str) else None)
                elif record.cidr is None:
                    record.cidr = cidr
                    self._rekey(record, cidr)
            elif record is None:
                record = self._ensure_active()
            assert record is not None
            record.info = dict(network)
            record.last_seen = time.time()
            gateway = network.get("gateway")
            if isinstance(gateway, str) and gateway:
                record.gateway = gateway
            if isinstance(mac, str) and mac and not record.gateway_mac:
                record.gateway_mac = mac

    # -- scan lifecycle --------------------------------------------------

    def begin_scan(self) -> None:
        with self.lock:
            self._touched.clear()

    def upsert(self, partial: Device, touch: bool = True) -> Device:
        """Merge *partial* into the active inventory and return the canonical record."""
        ip = normalize_ip(partial.ip)
        now = time.time()
        with self.lock:
            record = self._ensure_active()
            device = record.devices.get(ip)
            if device is None:
                device = Device(ip=ip, first_seen=now)
                record.devices[ip] = device
            device.merge(partial)
            if touch and ip not in self._touched:
                device.seen_count += 1
                self._touched.add(ip)
            if partial.online:
                device.last_seen = now
                record.last_seen = now
            device.ip = ip
            return device

    def mark_offline(self, seen: Iterable[str], cidr: str | None) -> list[Device]:
        """Mark known devices in *cidr* offline when they were not seen."""
        seen_set = set(seen)
        changed: list[Device] = []
        try:
            network = ipaddress.ip_network(cidr, strict=False) if cidr else None
        except ValueError:
            network = None
        with self.lock:
            for ip, device in self.devices.items():
                if ip in seen_set or not device.online:
                    continue
                if network is not None:
                    try:
                        if ipaddress.ip_address(ip) not in network:
                            continue
                    except ValueError:
                        continue
                device.online = False
                changed.append(device)
        return changed

    # -- editing ---------------------------------------------------------

    def set_user_fields(self, ip: str, label: str | None, notes: str | None) -> Device | None:
        key = normalize_ip(ip)
        with self.lock:
            device = self.devices.get(key)
            if device is None:
                return None
            if label is not None:
                device.label = label.strip()[:MAX_LABEL] or None
            if notes is not None:
                device.notes = notes.strip()[:500]
            return device

    def forget(self, ip: str) -> bool:
        key = normalize_ip(ip)
        with self.lock:
            return self.devices.pop(key, None) is not None

    # -- views -----------------------------------------------------------

    def devices_sorted(self) -> list[Device]:
        with self.lock:
            return [self.devices[ip] for ip in sorted(self.devices, key=ip_sort_key)]

    def counts(self) -> dict[str, int]:
        with self.lock:
            devices = list(self.devices.values())
        return {
            "known": len(devices),
            "online": sum(1 for d in devices if d.online),
            "offline": sum(1 for d in devices if not d.online),
            "services": sum(len(d.ports) for d in devices),
            "labeled": sum(1 for d in devices if d.label),
        }

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            devices = [self.devices[ip].to_dict() for ip in sorted(self.devices, key=ip_sort_key)]
            network = dict(self.network) if self.network else None
            active = self.active
            active_summary = active.summary(active=True) if active is not None else None
        return {
            "devices": devices,
            "network": network,
            "networks": self.networks_summary(),
            "active_network": active_summary,
            "counts": self.counts(),
            "state_path": str(self.path),
            "load_error": self.load_error,
            "save_error": self.save_error,
        }

    def export_json(self) -> dict[str, Any]:
        with self.lock:
            active = self.active
            return {
                "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "network_id": active.id if active is not None else None,
                "network": self.network,
                "devices": [
                    self.devices[ip].to_dict() for ip in sorted(self.devices, key=ip_sort_key)
                ],
            }

    @staticmethod
    def export_csv(devices: Iterable[Device]) -> str:
        import csv
        import io

        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "ip",
                "name",
                "hostname",
                "mac",
                "vendor",
                "online",
                "ports",
                "services",
                "latency_ms",
                "sources",
                "first_seen",
                "last_seen",
                "notes",
            ]
        )
        for device in devices:
            writer.writerow(
                [
                    device.ip,
                    device.display_name,
                    device.hostname or "",
                    device.mac or "",
                    device.vendor or "",
                    "yes" if device.online else "no",
                    " ".join(str(port) for port in sorted(device.ports)),
                    ";".join(device.mdns_services),
                    "" if device.rtt_ms is None else f"{device.rtt_ms:.1f}",
                    " ".join(device.sources),
                    time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(device.first_seen)),
                    time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(device.last_seen)),
                    device.notes.replace("\n", " "),
                ]
            )
        return buffer.getvalue()
