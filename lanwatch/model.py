"""Data model for discovered LAN devices.

Collectors never talk to the store directly: they build *partial* devices and
merge them.  A merge only overwrites a field when the incoming value carries
information that ranks at least as highly as what is already known, so a late
reverse-DNS answer cannot clobber a name learned from mDNS.
"""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

# Where a hostname came from, best source wins.
HOSTNAME_RANK = {"mdns": 5, "ssdp": 4, "nbns": 3, "pcb": 3, "rdns": 2}

# Well-known ports shown in the UI next to a device.
PORT_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    515: "lpd",
    548: "afp",
    554: "rtsp",
    631: "ipp",
    812: "sane",
    993: "imaps",
    1883: "mqtt",
    1900: "ssdp",
    3000: "http-alt",
    3306: "mysql",
    3389: "rdp",
    5000: "http-alt",
    5357: "wcf",
    5555: "adb",
    5900: "vnc",
    7000: "airplay",
    8008: "chromecast",
    8009: "cast",
    8080: "http-alt",
    8443: "https-alt",
    8883: "mqtt-tls",
    8888: "http-alt",
    9000: "http-alt",
    9100: "jetdirect",
    9999: "http-alt",
    32400: "plex",
}


def normalize_ip(value: str) -> str:
    """Return a canonical IPv4 address string, raising ValueError if invalid."""
    addr = ipaddress.ip_address(str(value).strip())
    if addr.version != 4:
        raise ValueError("only IPv4 addresses are supported")
    return str(addr)


def _merge_unique(existing: list[str], incoming: Iterable[str]) -> list[str]:
    seen = list(existing)
    lowered = {item.lower() for item in seen}
    for item in incoming:
        text = str(item).strip()
        if text and text.lower() not in lowered:
            seen.append(text)
            lowered.add(text.lower())
    return seen


@dataclass
class Device:
    """A single LAN host, assembled from every collector that saw it."""

    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    hostname_source: str | None = None
    rtt_ms: float | None = None
    ports: list[int] = field(default_factory=list)
    banners: dict[str, str] = field(default_factory=dict)
    mdns_services: list[str] = field(default_factory=list)
    ssdp: dict[str, str] = field(default_factory=dict)
    nbns_name: str | None = None
    sources: list[str] = field(default_factory=list)
    label: str | None = None
    notes: str = ""
    online: bool = False
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    seen_count: int = 0
    is_self: bool = False
    is_gateway: bool = False

    # -- merging ---------------------------------------------------------

    def add_source(self, *sources: str) -> None:
        self.sources = _merge_unique(self.sources, sources)

    def offer_hostname(self, name: str | None, source: str) -> bool:
        """Adopt *name* when *source* is at least as trustworthy as the current one."""
        text = (name or "").strip().strip(".")
        if not text:
            return False
        current = HOSTNAME_RANK.get(self.hostname_source or "", 0)
        incoming = HOSTNAME_RANK.get(source, 1)
        if self.hostname and incoming < current:
            return False
        if not self.hostname or incoming >= current:
            self.hostname = text
            self.hostname_source = source
            return True
        return False

    def merge(self, other: Device) -> None:
        """Fold a partial device into this record."""
        if other.mac and not self.mac:
            self.mac = other.mac
        if other.vendor and not self.vendor:
            self.vendor = other.vendor
        if other.hostname:
            self.offer_hostname(other.hostname, other.hostname_source or "rdns")
        if other.nbns_name and not self.nbns_name:
            self.nbns_name = other.nbns_name
        if other.rtt_ms is not None:
            self.rtt_ms = round(float(other.rtt_ms), 2)
        if other.ports:
            self.ports = sorted(set(self.ports).union(other.ports))
        for port, banner in other.banners.items():
            if banner and str(port) not in self.banners:
                self.banners[str(port)] = banner
        self.mdns_services = _merge_unique(self.mdns_services, other.mdns_services)
        for key, value in other.ssdp.items():
            if value and not self.ssdp.get(key):
                self.ssdp[key] = value
        self.add_source(*other.sources)
        if other.notes and not self.notes:
            self.notes = other.notes
        if other.label and not self.label:
            self.label = other.label
        self.online = self.online or other.online
        self.is_self = self.is_self or other.is_self
        self.is_gateway = self.is_gateway or other.is_gateway
        if other.first_seen:
            self.first_seen = min(self.first_seen, other.first_seen)
        if other.last_seen:
            self.last_seen = max(self.last_seen, other.last_seen)

    # -- presentation ----------------------------------------------------

    @property
    def display_name(self) -> str:
        for candidate in (
            self.label,
            self.hostname,
            self.nbns_name,
            self.ssdp.get("friendlyName"),
            self.vendor,
        ):
            if candidate:
                return str(candidate)
        return "Unknown device"

    def guess_kind(self) -> str:
        """Coarse device category used for the dashboard icon."""
        ports = set(self.ports)
        haystack = " ".join(
            [*self.mdns_services, *self.ssdp.values(), self.vendor or ""]
        ).lower()
        if self.is_self:
            return "self"
        if self.is_gateway:
            return "router"
        if 631 in ports or 9100 in ports or "ipp" in haystack or "printer" in haystack:
            return "printer"
        if "googlecast" in haystack or "chromecast" in haystack:
            return "tv"
        if "airplay" in haystack or 7000 in ports or 8009 in ports:
            return "tv" if ("tv" in haystack or "appletv" in haystack) else "media"
        if "mediarenderer" in haystack or "mediaserver" in haystack:
            return "media"
        if 32400 in ports or 548 in ports or (445 in ports and 22 in ports):
            return "nas"
        if 3389 in ports or (139 in ports and 445 in ports):
            return "computer"
        if {"rtsp", "onvif"} & {part.strip("_") for part in self.mdns_services}:
            return "camera"
        if any(p in ports for p in (554, 9000)):
            return "media"
        if "raspberry" in haystack or "synology" in haystack or "qnap" in haystack:
            return "nas"
        if "espressif" in haystack or 1883 in ports or 8883 in ports:
            return "iot"
        return "device"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "name": self.display_name,
            "label": self.label,
            "notes": self.notes,
            "hostname": self.hostname,
            "hostname_source": self.hostname_source,
            "nbns_name": self.nbns_name,
            "mac": self.mac,
            "vendor": self.vendor,
            "rtt_ms": self.rtt_ms,
            "ports": sorted(self.ports),
            "port_names": [PORT_NAMES.get(p, "") for p in sorted(self.ports)],
            "banners": self.banners,
            "mdns_services": self.mdns_services,
            "ssdp": self.ssdp,
            "sources": self.sources,
            "online": self.online,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "seen_count": self.seen_count,
            "is_self": self.is_self,
            "is_gateway": self.is_gateway,
            "kind": self.guess_kind(),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Device:
        """Rebuild a device from a persisted snapshot, tolerating older files."""
        device = cls(ip=normalize_ip(str(raw.get("ip", ""))))
        device.mac = raw.get("mac") or None
        device.vendor = raw.get("vendor") or None
        device.hostname = raw.get("hostname") or None
        device.hostname_source = raw.get("hostname_source") or ("rdns" if device.hostname else None)
        device.nbns_name = raw.get("nbns_name") or None
        rtt = raw.get("rtt_ms")
        device.rtt_ms = float(rtt) if isinstance(rtt, (int, float)) else None
        ports = raw.get("ports") or []
        device.ports = sorted({int(p) for p in ports if str(p).isdigit() and 0 < int(p) < 65536})
        banners = raw.get("banners") or {}
        if isinstance(banners, dict):
            device.banners = {str(k): str(v) for k, v in banners.items()}
        device.mdns_services = [str(s) for s in raw.get("mdns_services") or []]
        ssdp = raw.get("ssdp") or {}
        if isinstance(ssdp, dict):
            device.ssdp = {str(k): str(v) for k, v in ssdp.items()}
        device.sources = [str(s) for s in raw.get("sources") or []]
        device.label = raw.get("label") or None
        device.notes = str(raw.get("notes") or "")
        device.online = bool(raw.get("online"))
        device.first_seen = float(raw.get("first_seen") or time.time())
        device.last_seen = float(raw.get("last_seen") or device.first_seen)
        device.seen_count = int(raw.get("seen_count") or 0)
        device.is_self = bool(raw.get("is_self"))
        device.is_gateway = bool(raw.get("is_gateway"))
        return device


def ip_sort_key(ip: str) -> tuple[int, int, int, int]:
    try:
        parts = ip.split(".")
        return (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]))
    except (ValueError, IndexError):
        return (999, 999, 999, 999)
