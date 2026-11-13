"""Device inventory persistence and merge bookkeeping."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import tempfile
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .model import Device, ip_sort_key, normalize_ip

SCHEMA_VERSION = 1


def default_state_path() -> Path:
    override = os.environ.get("LANWATCH_STATE")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_STATE_HOME")
    if base:
        return Path(base).expanduser() / "lanwatch" / "devices.json"
    return Path.home() / ".local" / "state" / "lanwatch" / "devices.json"


class Store:
    """Thread-safe device inventory with an on-disk snapshot."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else default_state_path()
        self.lock = threading.RLock()
        self.devices: dict[str, Device] = {}
        self.network: dict[str, Any] | None = None
        self.load_error: str | None = None
        self.save_error: str | None = None
        self._touched: set[str] = set()
        self.load()

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
            network = raw.get("network")
            if isinstance(network, dict):
                self.network = {str(k): v for k, v in network.items()}
            for item in raw.get("devices") or []:
                if not isinstance(item, dict):
                    continue
                try:
                    device = Device.from_dict(item)
                except (ValueError, TypeError):
                    continue
                self.devices[device.ip] = device
        self.load_error = None

    def save(self) -> bool:
        payload = {
            "version": SCHEMA_VERSION,
            "saved_at": time.time(),
            "network": self.network,
            "devices": [self.devices[ip].to_dict() for ip in sorted(self.devices, key=ip_sort_key)],
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

    # -- scan lifecycle --------------------------------------------------

    def begin_scan(self) -> None:
        with self.lock:
            self._touched.clear()

    def upsert(self, partial: Device, touch: bool = True) -> Device:
        """Merge *partial* into the inventory and return the canonical record."""
        ip = normalize_ip(partial.ip)
        now = time.time()
        with self.lock:
            device = self.devices.get(ip)
            if device is None:
                device = Device(ip=ip, first_seen=now)
                self.devices[ip] = device
            device.merge(partial)
            if touch and ip not in self._touched:
                device.seen_count += 1
                self._touched.add(ip)
            if partial.online:
                device.last_seen = now
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
                device.label = label.strip()[:60] or None
            if notes is not None:
                device.notes = notes.strip()[:500]
            return device

    def forget(self, ip: str) -> bool:
        key = normalize_ip(ip)
        with self.lock:
            return self.devices.pop(key, None) is not None

    def set_network(self, network: dict[str, Any]) -> None:
        with self.lock:
            self.network = dict(network)

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
        return {
            "devices": devices,
            "network": network,
            "counts": self.counts(),
            "state_path": str(self.path),
            "load_error": self.load_error,
            "save_error": self.save_error,
        }

    def export_json(self) -> dict[str, Any]:
        with self.lock:
            return {
                "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
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
