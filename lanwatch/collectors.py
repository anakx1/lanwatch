"""Discovery primitives.

Every collector degrades gracefully: a missing binary, a permission error or a
filtered multicast packet is reported as a status, never raised at the caller.
That matters on Android, where netlink, the ARP table and inbound multicast are
commonly unavailable to ordinary apps.
"""

from __future__ import annotations

import contextlib
import html
import http.client
import ipaddress
import math
import os
import queue
import re
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Callable

from . import dnsparse, oui

DEFAULT_PORTS = [
    21,
    22,
    23,
    53,
    80,
    139,
    443,
    445,
    548,
    554,
    631,
    1883,
    3389,
    5000,
    5357,
    5555,
    5900,
    7000,
    8008,
    8009,
    8080,
    8443,
    8883,
    9100,
    32400,
]

BANNER_PORTS = {21, 22, 23, 25, 110, 143, 993, 995}

MAX_SSDP_DESCRIPTIONS = 24

# Ports that may speak HTTP(S); probed for a page title, Server header and cert.
WEB_PORTS = {80: False, 443: True, 3000: False, 5000: False, 8000: False, 8008: False,
             8080: False, 8443: True, 8888: False, 9000: False}
WEB_READ_BYTES = 16384

_ping_checked: bool | None = None
_ping_lock = threading.Lock()
# ip -> TTL from the last ping reply; the ICMP sweep records it for free.
_ttl_seen: dict[str, int] = {}


def ttl_for(ip: str) -> int | None:
    """TTL seen in the last ping reply from *ip*, if any (OS fingerprinting hint)."""
    return _ttl_seen.get(ip)


# ---------------------------------------------------------------------------
# ICMP
# ---------------------------------------------------------------------------


def ping_available() -> bool:
    """Return True when the system ping binary can reach loopback."""
    global _ping_checked
    if _ping_checked is not None:
        return _ping_checked
    with _ping_lock:
        if _ping_checked is not None:
            return _ping_checked
        usable = bool(shutil.which("ping"))
        if usable:
            cmd = _ping_command("127.0.0.1", 1.0)
            try:
                result = subprocess.run(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4
                )
                usable = result.returncode == 0
            except (OSError, subprocess.SubprocessError):
                usable = False
        _ping_checked = usable
        return usable


def _ping_command(ip: str, timeout: float) -> list[str]:
    if sys.platform == "win32":
        return ["ping", "-n", "1", "-w", str(int(timeout * 1000) + 500), ip]
    if sys.platform == "darwin":
        return ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    return ["ping", "-c", "1", "-W", str(max(1, int(math.ceil(timeout)))), "-n", ip]


def ping_host(ip: str, timeout: float = 1.0) -> float | None:
    """Ping one host and return the round-trip time in milliseconds."""
    started = time.monotonic()
    try:
        result = subprocess.run(
            _ping_command(ip, timeout),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2.5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    output = result.stdout.decode("utf-8", "replace")
    ttl_match = re.search(r"ttl[=:]\s*(\d+)", output, flags=re.IGNORECASE)
    if ttl_match:
        _ttl_seen[ip] = int(ttl_match.group(1))
    match = re.search(r"time[=<]\s*([\d.]+)\s*ms", output)
    if match:
        return float(match.group(1))
    return round((time.monotonic() - started) * 1000, 2)


def ping_sweep(
    hosts: Iterable[str],
    timeout: float = 1.0,
    concurrency: int = 64,
    on_up: Callable[[str, float], None] | None = None,
    cancel: threading.Event | None = None,
    on_result: Callable[[str, float | None], None] | None = None,
) -> dict[str, float]:
    """Ping every host concurrently, invoking *on_up* as results arrive."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    host_list = list(hosts)
    if not host_list:
        return {}
    if not ping_available():
        return {}
    up: dict[str, float] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, len(host_list)))) as pool:
        futures = {pool.submit(ping_host, ip, timeout): ip for ip in host_list}
        for future in as_completed(futures):
            if cancel is not None and cancel.is_set():
                for pending in futures:
                    pending.cancel()
                break
            ip = futures[future]
            try:
                rtt = future.result()
            except Exception:  # pragma: no cover - defensive
                rtt = None
            if rtt is not None:
                up[ip] = rtt
                if on_up is not None:
                    on_up(ip, rtt)
            if on_result is not None:
                on_result(ip, rtt)
    return up


# ---------------------------------------------------------------------------
# Neighbour / ARP cache
# ---------------------------------------------------------------------------


def arp_table() -> tuple[dict[str, str], str]:
    """Return ``(ip -> mac, source description)`` from any readable cache."""
    readers = (
        ("proc", _arp_from_proc),
        ("ip neigh", _arp_from_ip_neigh),
        ("arp", _arp_from_arp),
    )
    notes = []
    for label, reader in readers:
        try:
            table = reader()
        except (OSError, subprocess.SubprocessError):
            continue
        if table:
            return table, label
        notes.append(f"{label}: empty")
    try:
        if not os.path.exists("/proc/net/arp"):
            notes.append("/proc/net/arp missing")
    except OSError:
        pass
    return {}, ", ".join(notes) or "no neighbour cache readable"


def _arp_from_proc() -> dict[str, str]:
    with open("/proc/net/arp", encoding="utf-8", errors="replace") as handle:
        lines = handle.read().splitlines()
    table: dict[str, str] = {}
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        ip, flags, mac = parts[0], parts[2], parts[3]
        if flags == "0x0":
            continue
        normalized = oui.normalize_mac(mac)
        if normalized:
            table[ip] = normalized
    return table


def _arp_from_ip_neigh() -> dict[str, str]:
    result = subprocess.run(
        ["ip", "neigh", "show"], capture_output=True, text=True, timeout=5, check=False
    )
    if result.returncode != 0:
        return {}
    return _parse_ip_neigh(result.stdout)


def _parse_ip_neigh(text: str) -> dict[str, str]:
    table: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or not _is_ipv4(parts[0]):
            continue
        mac = None
        for index, token in enumerate(parts):
            if token == "lladdr" and index + 1 < len(parts):
                mac = oui.normalize_mac(parts[index + 1])
        if mac:
            table[parts[0]] = mac
    return table


def _arp_from_arp() -> dict[str, str]:
    result = subprocess.run(
        ["arp", "-an"], capture_output=True, text=True, timeout=5, check=False
    )
    if result.returncode != 0:
        return {}
    return _parse_arp_output(result.stdout)


def _parse_arp_output(text: str) -> dict[str, str]:
    table: dict[str, str] = {}
    for line in text.splitlines():
        match = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9A-Fa-f:.-]+)", line)
        if not match:
            continue
        normalized = oui.normalize_mac(match.group(2))
        if normalized:
            table[match.group(1)] = normalized
    return table


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------


def probe_port(ip: str, port: int, timeout: float = 0.3) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def scan_ports(
    hosts: Iterable[str],
    ports: Iterable[int] = DEFAULT_PORTS,
    timeout: float = 0.3,
    workers: int = 128,
    cancel: threading.Event | None = None,
) -> dict[str, list[int]]:
    """Connect-scan ports on several hosts; returns ``ip -> open ports``."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    pairs = [(ip, int(port)) for ip in hosts for port in ports]
    if not pairs:
        return {}
    found: dict[str, list[int]] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(pairs)))) as pool:
        futures = {pool.submit(probe_port, ip, port, timeout): (ip, port) for ip, port in pairs}
        for future in as_completed(futures):
            if cancel is not None and cancel.is_set():
                for pending in futures:
                    pending.cancel()
                break
            ip, port = futures[future]
            try:
                if future.result():
                    found.setdefault(ip, []).append(port)
            except Exception:  # pragma: no cover - defensive
                continue
    return {ip: sorted(values) for ip, values in found.items()}


def grab_banner(ip: str, port: int, timeout: float = 0.5) -> str | None:
    if port not in BANNER_PORTS:
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((ip, port)) != 0:
            return None
        data = sock.recv(160)
    except OSError:
        return None
    finally:
        sock.close()
    text = data.decode("utf-8", "replace").strip()
    text = "".join(char for char in text if char.isprintable() or char in "\t ")
    return text[:96] or None


# ---------------------------------------------------------------------------
# NetBIOS name service
# ---------------------------------------------------------------------------


def nbns_query_packet(txid: int = 0x4C57) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0, 1, 0, 0, 0)
    # NetBIOS first-level encoding of "*", padded to 16 characters.
    encoded = b"\x20CK" + b"A" * 30 + b"\x00"
    return header + encoded + struct.pack(">HH", 0x0021, 0x0001)


def nbns_name(ip: str, timeout: float = 0.7) -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(nbns_query_packet(), (ip, 137))
        data, _ = sock.recvfrom(2048)
    except OSError:
        return None
    finally:
        sock.close()
    return parse_nbstat(data)


def parse_nbstat(data: bytes) -> str | None:
    try:
        if len(data) < 12:
            return None
        qdcount, ancount = struct.unpack(">HH", data[4:8])
        offset = 12
        for _ in range(qdcount):
            _, offset = dnsparse.read_name(data, offset)
            offset += 4
        if ancount < 1 or offset + 12 > len(data):
            return None
        _, offset = dnsparse.read_name(data, offset)
        _rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]
        if not rdata:
            return None
        count = rdata[0]
        names: list[str] = []
        for index in range(min(count, 32)):
            entry = rdata[1 + index * 18 : 1 + (index + 1) * 18]
            if len(entry) < 18:
                break
            raw = entry[:15].decode("ascii", "replace").strip("\x00 ")
            flags = struct.unpack(">H", entry[16:18])[0]
            if raw and not (flags & 0x8000):
                names.append(raw)
        return names[0] if names else None
    except (struct.error, ValueError, IndexError):
        return None


# ---------------------------------------------------------------------------
# SSDP / UPnP
# ---------------------------------------------------------------------------


@dataclass
class SsdpResult:
    devices: list[dict[str, str]] = field(default_factory=list)
    sent: int = 0
    received: int = 0
    error: str | None = None


SSDP_REQUEST = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "USER-AGENT: lanwatch/0.1 UPnP/1.1\r\n"
    "\r\n"
)


def ssdp_discover(iface_ip: str, timeout: float = 4.0, cancel: threading.Event | None = None) -> SsdpResult:
    result = SsdpResult()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((iface_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(SSDP_REQUEST.encode("utf-8"), ("239.255.255.250", 1900))
        result.sent = 1
    except OSError as exc:
        result.error = f"send failed: {exc}"
        sock.close()
        return result

    deadline = time.monotonic() + timeout
    seen: set[str] = set()
    try:
        while time.monotonic() < deadline:
            if cancel is not None and cancel.is_set():
                break
            remaining = max(0.05, deadline - time.monotonic())
            sock.settimeout(min(0.4, remaining))
            try:
                data, addr = sock.recvfrom(16384)
            except socket.timeout:
                continue
            except OSError as exc:
                result.error = str(exc)
                break
            result.received += 1
            entry = _parse_ssdp_response(data, addr[0])
            if not entry:
                continue
            key = entry.get("usn") or f"{entry['ip']}|{entry.get('st', '')}"
            if key in seen:
                continue
            seen.add(key)
            result.devices.append(entry)
            if len(result.devices) >= 64:
                break
    finally:
        sock.close()

    _enrich_ssdp(result.devices)
    return result


def _parse_ssdp_response(data: bytes, ip: str) -> dict[str, str] | None:
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines or "200" not in lines[0]:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    entry = {
        "ip": ip,
        "st": headers.get("st", ""),
        "usn": headers.get("usn", ""),
        "server": headers.get("server", ""),
        "location": headers.get("location", ""),
        "friendly": "",
        "manufacturer": "",
        "model": "",
        "device_type": "",
    }
    return entry


def _enrich_ssdp(devices: list[dict[str, str]]) -> None:
    locations = []
    for entry in devices:
        location = entry.get("location", "")
        if location.startswith(("http://", "https://")) and location not in locations:
            locations.append(location)
    if not locations:
        return
    results = run_bounded(_fetch_description, locations[:MAX_SSDP_DESCRIPTIONS], timeout=3.0)
    by_location = dict(results.items())
    for entry in devices:
        values = by_location.get(entry.get("location", ""))
        if not values:
            continue
        entry["friendly"] = values.get("friendlyName", "")
        entry["manufacturer"] = values.get("manufacturer", "")
        entry["model"] = values.get("modelName", "")
        entry["device_type"] = values.get("deviceType", "")
        entry["model_number"] = values.get("modelNumber", "")


def _fetch_description(location: str, timeout: float = 2.0) -> dict[str, str]:
    request = urllib.request.Request(location, headers={"User-Agent": "lanwatch/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - LAN only
        data = response.read(262144)
    values: dict[str, str] = {}
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return values
    wanted = ("friendlyName", "manufacturer", "modelName", "deviceType", "modelNumber")
    for element in root.iter():
        tag = str(element.tag).split("}")[-1]
        if tag in wanted and element.text and not values.get(tag):
            values[tag] = element.text.strip()[:120]
    return values


# ---------------------------------------------------------------------------
# HTTP(S) fingerprint
# ---------------------------------------------------------------------------

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_REALM_RE = re.compile(r'realm="?([^",]+)', re.IGNORECASE)
_OID_CN = b"\x55\x04\x03"
_OID_ORG = b"\x55\x04\x0a"


def _clip(text: str, limit: int = 80) -> str:
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _der_string_after(der: bytes, oid: bytes) -> str | None:
    """Return the last string value that follows *oid* in a DER blob.

    A certificate lists its issuer before its subject, so the last occurrence
    of the common-name OID is the subject (the two are equal when self-signed).
    This is a deliberately tiny reader, not a full X.509 parser.
    """
    index = der.rfind(oid)
    if index < 0:
        return None
    pos = index + len(oid)
    if pos + 2 > len(der):
        return None
    tag, length = der[pos], der[pos + 1]
    if tag not in (0x0C, 0x13, 0x16, 0x14) or length >= 0x80:
        return None
    raw = der[pos + 2 : pos + 2 + length]
    if len(raw) != length:
        return None
    return _clip(raw.decode("utf-8", "replace"), 64) or None


def cert_names(der: bytes) -> dict[str, str]:
    """Extract the subject common name and organisation from a DER certificate."""
    names: dict[str, str] = {}
    common = _der_string_after(der, _OID_CN)
    if common:
        names["cert_cn"] = common
    org = _der_string_after(der, _OID_ORG)
    if org:
        names["cert_org"] = org
    return names


def parse_http_response(headers: dict[str, str], body: bytes, status: int) -> dict[str, str]:
    """Reduce an HTTP response to the few fields worth keeping."""
    info: dict[str, str] = {"status": str(status)}
    server = headers.get("server")
    if server:
        info["server"] = _clip(server)
    powered = headers.get("x-powered-by")
    if powered:
        info["powered_by"] = _clip(powered)
    realm = _REALM_RE.search(headers.get("www-authenticate", ""))
    if realm:
        info["realm"] = _clip(realm.group(1))
    match = _TITLE_RE.search(body)
    if match:
        title = html.unescape(match.group(1).decode("utf-8", "replace"))
        title = _clip(title)
        if title:
            info["title"] = title
    return info


def http_probe(ip: str, port: int, timeout: float = 1.5) -> dict[str, str]:
    """Fetch ``/`` from one web port and describe what answered.

    Self-signed certificates are expected on LAN gear, so verification is off:
    this reads identity hints only and never sends credentials.  Returns an
    empty dict when nothing usable answered.
    """
    use_tls = WEB_PORTS.get(port, False)
    info: dict[str, str] = {}
    connection: http.client.HTTPConnection
    if use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(ip, port, timeout=timeout, context=context)
    else:
        connection = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        connection.request(
            "GET", "/", headers={"User-Agent": "lanwatch/0.1", "Accept": "text/html,*/*;q=0.5"}
        )
        if use_tls and connection.sock is not None:
            sock = connection.sock
            getter = getattr(sock, "getpeercert", None)
            der = getter(binary_form=True) if getter else None
            if der:
                info.update(cert_names(der))
        response = connection.getresponse()
        body = response.read(WEB_READ_BYTES)
        headers = {key.lower(): value for key, value in response.getheaders()}
        info.update(parse_http_response(headers, body, response.status))
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return info if len(info) > 0 and use_tls else {}
    finally:
        connection.close()
    return info


def http_probe_many(
    open_map: dict[str, list[int]],
    timeout: float = 1.5,
    workers: int = 16,
    deadline: float = 10.0,
) -> dict[str, dict[str, dict[str, str]]]:
    """Probe every open web port; returns ``ip -> port -> info``."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from concurrent.futures import TimeoutError as FutureTimeoutError

    tasks = [(ip, port) for ip, ports in open_map.items() for port in ports if port in WEB_PORTS]
    if not tasks:
        return {}
    results: dict[str, dict[str, dict[str, str]]] = {}
    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(tasks))))
    try:
        futures = {pool.submit(http_probe, ip, port, timeout): (ip, port) for ip, port in tasks}
        try:
            for future in as_completed(futures, timeout=deadline):
                ip, port = futures[future]
                try:
                    info = future.result()
                except Exception:
                    info = {}
                if info:
                    results.setdefault(ip, {})[str(port)] = info
        except FutureTimeoutError:
            pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return results


# ---------------------------------------------------------------------------
# mDNS-SD
# ---------------------------------------------------------------------------


@dataclass
class MdnsResult:
    by_ip: dict[str, dict[str, Any]] = field(default_factory=dict)
    service_types: list[str] = field(default_factory=list)
    sent: int = 0
    received: int = 0
    error: str | None = None


def mdns_browse(iface_ip: str, timeout: float = 4.0, cancel: threading.Event | None = None) -> MdnsResult:
    result = MdnsResult()
    sockets = _open_mdns_sockets(iface_ip, result)
    if not sockets:
        return result
    deadline = time.monotonic() + timeout
    try:
        _send_mdns(sockets, "_services._dns-sd._udp.local", result)
        queried: set[str] = set()
        instances: dict[str, dict[str, object]] = {}
        host_records: dict[str, str] = {}
        instance_ip: dict[str, str] = {}
        while time.monotonic() < deadline:
            if cancel is not None and cancel.is_set():
                break
            remaining = max(0.05, deadline - time.monotonic())
            ready, _, _ = select.select(sockets, [], [], min(0.4, remaining))
            if not ready:
                continue
            for sock in ready:
                try:
                    data, addr = sock.recvfrom(9000)
                except OSError:
                    continue
                result.received += 1
                try:
                    message = dnsparse.parse_message(data)
                except (dnsparse.DnsError, ValueError):
                    continue
                _absorb_mdns(
                    message,
                    addr[0],
                    result,
                    instances,
                    host_records,
                    instance_ip,
                )
                for service in result.service_types:
                    if service not in queried and len(queried) < 24:
                        queried.add(service)
                        _send_mdns(sockets, service, result)
    finally:
        for sock in sockets:
            sock.close()
    _resolve_mdns(result, instances, host_records, instance_ip)
    return result


def _open_mdns_sockets(iface_ip: str, result: MdnsResult) -> list[socket.socket]:
    sockets: list[socket.socket] = []
    # A 5353 listener sees multicast answers; it is often taken by Android's
    # mdnsd, so an ephemeral unicast socket is the fallback.
    for port in (5353, 0):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind((iface_ip if port == 0 else "", port))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            if port == 5353:
                membership = socket.inet_aton("224.0.0.251") + socket.inet_aton(iface_ip)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
            sockets.append(sock)
        except OSError as exc:
            if port == 5353:
                continue
            result.error = f"socket: {exc}"
    return sockets


def _send_mdns(sockets: list[socket.socket], name: str, result: MdnsResult) -> None:
    packet = dnsparse.encode_query(name, dnsparse.TYPE_PTR, unicast=True)
    for sock in sockets:
        try:
            sock.sendto(packet, ("224.0.0.251", 5353))
            result.sent += 1
        except OSError:
            continue


def _absorb_mdns(
    message: dnsparse.Message,
    source_ip: str,
    result: MdnsResult,
    instances: dict[str, dict[str, Any]],
    host_records: dict[str, str],
    instance_ip: dict[str, str],
) -> None:
    for record in message.records():
        if record.rtype == dnsparse.TYPE_PTR:
            target = str(record.data)
            if record.name.rstrip(".").lower() == "_services._dns-sd._udp.local":
                service = dnsparse.service_type(target)
                if service and service not in result.service_types:
                    result.service_types.append(service)
            else:
                service = dnsparse.service_type(record.name) or dnsparse.service_type(target)
                if service and service not in result.service_types:
                    result.service_types.append(service)
                entry = instances.setdefault(target, {"services": [], "txt": {}})
                if service:
                    services = entry["services"]
                    assert isinstance(services, list)
                    if service not in services:
                        services.append(service)
                instance_ip.setdefault(target, source_ip)
        elif record.rtype == dnsparse.TYPE_SRV and isinstance(record.data, dict):
            target = str(record.data.get("target", ""))
            entry = instances.setdefault(record.name, {"services": [], "txt": {}})
            entry["target"] = target
            entry["port"] = record.data.get("port")
            host_records.setdefault(target.rstrip(".").lower(), "")
        elif record.rtype == dnsparse.TYPE_TXT:
            entry = instances.setdefault(record.name, {"services": [], "txt": {}})
            values = entry["txt"]
            assert isinstance(values, dict)
            values.update(dnsparse.txt_dict(record))
        elif record.rtype in (dnsparse.TYPE_A, dnsparse.TYPE_AAAA):
            target = record.name.rstrip(".").lower()
            host_records[target] = str(record.data)
        elif record.rtype == dnsparse.TYPE_NSEC and isinstance(record.data, dict):
            pass


def _resolve_mdns(
    result: MdnsResult,
    instances: dict[str, dict[str, Any]],
    host_records: dict[str, str],
    instance_ip: dict[str, str],
) -> None:
    for name, entry in instances.items():
        target = str(entry.get("target") or "").rstrip(".")
        ip = host_records.get(target.lower()) if target else None
        if not ip:
            ip = instance_ip.get(name)
        if not ip:
            continue
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            continue
        bucket = result.by_ip.setdefault(ip, {"hostname": "", "services": [], "txt": {}})
        services = bucket["services"]
        txt = bucket["txt"]
        assert isinstance(services, list) and isinstance(txt, dict)
        for service in entry.get("services", []):
            if service not in services:
                services.append(str(service))
        for key, value in dict(entry.get("txt") or {}).items():
            txt.setdefault(str(key), str(value))
        if target and not bucket["hostname"]:
            bucket["hostname"] = target.split(".")[0]


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------


def reverse_dns(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0].rstrip(".")
    except (OSError, socket.herror):
        return None
    return name or None


def reverse_dns_many(
    hosts: Iterable[str], timeout: float = 2.5, workers: int = 16
) -> dict[str, str]:
    """Resolve many addresses without letting a slow resolver block the scan."""
    return run_bounded(reverse_dns, list(hosts), workers=workers, timeout=timeout)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run_bounded(
    func: Callable[[str], object],
    items: list[str],
    workers: int = 16,
    timeout: float = 3.0,
) -> dict[str, Any]:
    """Run *func* over *items* on daemon threads, giving up after *timeout*."""
    if not items:
        return {}
    work: queue.Queue[str] = queue.Queue()
    for item in items:
        work.put(item)
    results: dict[str, Any] = {}
    lock = threading.Lock()

    def worker() -> None:
        while True:
            try:
                item = work.get_nowait()
            except queue.Empty:
                return
            try:
                value = func(item)
            except Exception:
                value = None
            if value:
                with lock:
                    results[item] = value

    threads = [
        threading.Thread(target=worker, daemon=True)
        for _ in range(max(1, min(workers, len(items))))
    ]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    with lock:
        return dict(results)


def _is_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False
