"""Scan orchestration: turns collectors into one live device inventory."""

from __future__ import annotations

import contextlib
import ipaddress
import os
import platform
import queue
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from . import __version__, collectors, netif, oui
from .model import Device, normalize_ip
from .store import Store

COLLECTOR_ORDER = ("icmp", "arp", "tcp", "mdns", "ssdp", "nbns", "rdns")

DEEP_PORTS = [53, 80, 443, 445, 631, 8080, 9100]


class EventBus:
    """Fan-out of scan events to any number of dashboard clients."""

    def __init__(self) -> None:
        self._subscribers: set[queue.Queue[dict[str, Any]]] = set()
        self._lock = threading.Lock()

    def subscribe(self, maxsize: int = 512) -> queue.Queue[dict[str, Any]]:
        channel: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=maxsize)
        with self._lock:
            self._subscribers.add(channel)
        return channel

    def unsubscribe(self, channel: queue.Queue[dict[str, Any]]) -> None:
        with self._lock:
            self._subscribers.discard(channel)

    def publish(self, event: dict[str, Any]) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for channel in subscribers:
            try:
                channel.put_nowait(event)
            except queue.Full:
                with contextlib.suppress(queue.Empty):
                    channel.get_nowait()
                with contextlib.suppress(queue.Full):
                    channel.put_nowait(event)


@dataclass
class ScanOptions:
    subnet: str | None = None
    ports: list[int] = field(default_factory=lambda: list(collectors.DEFAULT_PORTS))
    ping_timeout: float = 1.0
    concurrency: int = 64
    max_hosts: int = netif.DEFAULT_MAX_HOSTS
    deep: bool = False
    mdns: bool = True
    ssdp: bool = True
    nbns: bool = True
    rdns: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "subnet": self.subnet,
            "ports": list(self.ports),
            "ping_timeout": self.ping_timeout,
            "concurrency": self.concurrency,
            "max_hosts": self.max_hosts,
            "deep": self.deep,
            "mdns": self.mdns,
            "ssdp": self.ssdp,
            "nbns": self.nbns,
            "rdns": self.rdns,
        }

    @classmethod
    def from_payload(
        cls, payload: dict[str, Any] | None, base: ScanOptions | None = None
    ) -> ScanOptions:
        options = cls(**base.to_dict()) if base else cls()
        payload = payload or {}
        if "subnet" in payload:
            text = payload.get("subnet")
            if text is not None and not isinstance(text, str):
                raise ValueError("subnet must be a string")
            options.subnet = (text or "").strip() or None
            if options.subnet and len(options.subnet) > 64:
                raise ValueError("subnet is too long")
        if "ports" in payload:
            options.ports = _parse_ports(payload.get("ports"))
        if "ping_timeout" in payload:
            options.ping_timeout = _clamp_float(payload.get("ping_timeout"), 0.2, 10.0, "ping_timeout")
        if "timeout" in payload:
            options.ping_timeout = _clamp_float(payload.get("timeout"), 0.2, 10.0, "timeout")
        if "concurrency" in payload:
            options.concurrency = _clamp_int(payload.get("concurrency"), 1, 256, "concurrency")
        if "max_hosts" in payload:
            options.max_hosts = _clamp_int(payload.get("max_hosts"), 1, 65536, "max_hosts")
        for name in ("deep", "mdns", "ssdp", "nbns", "rdns"):
            if name in payload:
                value = payload.get(name)
                if not isinstance(value, bool):
                    raise ValueError(f"{name} must be a boolean")
                setattr(options, name, value)
        return options


def _parse_ports(raw: object) -> list[int]:
    if raw is None:
        return list(collectors.DEFAULT_PORTS)
    if isinstance(raw, str):
        tokens = [token for token in re.split(r"[,\s]+", raw.strip()) if token]
        if not tokens:
            return list(collectors.DEFAULT_PORTS)
        values: list[int] = []
        for token in tokens:
            if not token.isdigit():
                raise ValueError(f"invalid port {token!r}")
            values.append(int(token))
    elif isinstance(raw, (list, tuple)):
        if not raw:
            return list(collectors.DEFAULT_PORTS)
        values = []
        for item in raw:
            if isinstance(item, bool) or not isinstance(item, (int, str)):
                raise ValueError("ports must be integers")
            text = str(item).strip()
            if not text.isdigit():
                raise ValueError(f"invalid port {item!r}")
            values.append(int(text))
    else:
        raise ValueError("ports must be a list or comma-separated string")
    unique = sorted({value for value in values if 0 < value < 65536})
    if not unique:
        raise ValueError("no valid ports given")
    if len(unique) > 256:
        raise ValueError("at most 256 ports can be scanned")
    return unique


def _clamp_int(value: object, low: int, high: int, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if not isinstance(value, (int, float, str)):
        raise ValueError(f"{name} must be an integer")
    try:
        number = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not low <= number <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return number


def _clamp_float(value: object, low: float, high: float, name: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a number")
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a number") from exc
    if not low <= number <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return round(number, 2)


class ScanEngine:
    """Owns the inventory, runs scans in a background thread and emits events."""

    def __init__(self, store: Store, options: ScanOptions | None = None) -> None:
        self.store = store
        self.bus = EventBus()
        self.options = options or ScanOptions()
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()
        self._scan_id = 0
        self._interfaces: list[netif.Interface] = []
        self.refresh_interfaces()
        # "Online" means "answered during this process", not "was online when
        # the inventory was written", so a restart starts from a clean slate.
        for device in self.store.devices.values():
            device.online = False
        self.state: dict[str, Any] = {
            "running": False,
            "phase": "idle",
            "message": "ready",
            "started_at": None,
            "finished_at": None,
            "duration_s": None,
            "done": 0,
            "total": 0,
            "hosts_total": 0,
            "found": 0,
            "scan_id": 0,
            "subnet": None,
            "error": None,
            "stopped": False,
        }
        self.collectors_state: dict[str, dict[str, Any]] = {
            name: {"status": "idle", "detail": "not run yet", "count": 0}
            for name in COLLECTOR_ORDER
        }

    # -- housekeeping ----------------------------------------------------

    def refresh_interfaces(self) -> list[dict[str, Any]]:
        try:
            found = netif.detect_interfaces()
        except (OSError, netif.InterfaceError):
            found = []
        usable = [iface for iface in found if netif.usable(iface)]
        with self._lock:
            self._interfaces = usable
        return [iface.to_dict() for iface in usable]

    @property
    def running(self) -> bool:
        with self._lock:
            return bool(self.state["running"])

    @property
    def interfaces(self) -> list[netif.Interface]:
        with self._lock:
            return list(self._interfaces)

    def state_dict(self) -> dict[str, Any]:
        with self._lock:
            return dict(self.state)

    def collectors_dict(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {name: dict(value) for name, value in self.collectors_state.items()}

    def snapshot(self) -> dict[str, Any]:
        data = self.store.snapshot()
        data["state"] = self.state_dict()
        data["options"] = self.options.to_dict()
        data["collectors"] = self.collectors_dict()
        data["interfaces"] = [iface.to_dict() for iface in self._interfaces]
        data["version"] = __version__
        data["host"] = {
            "name": platform.node(),
            "system": platform.system(),
            "android": _is_android(),
            "icmp": collectors.ping_available(),
        }
        return data

    # -- lifecycle -------------------------------------------------------

    def start(self, options: ScanOptions | None = None) -> tuple[bool, str]:
        with self._lock:
            if self.state["running"]:
                return False, "a scan is already running"
            if options is not None:
                self.options = options
            self._scan_id += 1
            scan_id = self._scan_id
            self._cancel.clear()
            self.state = {
                "running": True,
                "phase": "starting",
                "message": "detecting network",
                "started_at": time.time(),
                "finished_at": None,
                "duration_s": None,
                "done": 0,
                "total": 0,
                "hosts_total": 0,
                "found": 0,
                "scan_id": scan_id,
                "subnet": self.options.subnet,
                "error": None,
                "stopped": False,
            }
            self.collectors_state = {
                name: {"status": "pending", "detail": "waiting", "count": 0}
                for name in COLLECTOR_ORDER
            }
            self._thread = threading.Thread(
                target=self._run, args=(self.options, scan_id), name="lanwatch-scan", daemon=True
            )
        self._thread.start()
        return True, ""

    def stop(self) -> bool:
        with self._lock:
            if not self.state["running"]:
                return False
        self._cancel.set()
        return True

    def probe_device(self, ip: str) -> dict[str, Any]:
        """Re-check one device without disturbing the rest of the inventory."""
        address = normalize_ip(ip)
        rtt = collectors.ping_host(address, self.options.ping_timeout)
        open_ports = collectors.scan_ports(
            [address], self.options.ports, timeout=0.25, workers=32
        ).get(address, [])
        online = rtt is not None or bool(open_ports)
        sources = []
        if rtt is not None:
            sources.append("icmp")
        if open_ports:
            sources.append("tcp")
        device = self.store.upsert(
            Device(ip=address, rtt_ms=rtt, ports=open_ports, sources=sources, online=online)
        )
        with self.store.lock:
            device.online = online
            if online:
                device.last_seen = time.time()
        self.store.save()
        snapshot = device.to_dict()
        self._emit("device", device=snapshot)
        return snapshot

    # -- internals -------------------------------------------------------

    def _emit(self, kind: str, **payload: Any) -> None:
        self.bus.publish({"type": kind, "ts": time.time(), **payload})

    def _set_state(self, **values: Any) -> dict[str, Any]:
        with self._lock:
            self.state.update(values)
            return dict(self.state)

    def _phase(self, phase: str, message: str, done: int | None = None, total: int | None = None) -> None:
        values: dict[str, Any] = {"phase": phase, "message": message}
        if done is not None:
            values["done"] = done
        if total is not None:
            values["total"] = total
        state = self._set_state(**values)
        self._emit("progress", state=state)

    def _collector(self, name: str, status: str, detail: str, count: int = 0) -> None:
        entry = {"status": status, "detail": detail, "count": int(count)}
        with self._lock:
            self.collectors_state[name] = entry
        self._emit("collector", name=name, collector=entry)

    def _record(self, partial: Device, seen: set[str]) -> Device:
        device = self.store.upsert(partial)
        seen.add(device.ip)
        self._set_state(found=len(seen))
        self._emit("device", device=device.to_dict())
        return device

    def _run(self, options: ScanOptions, scan_id: int) -> None:
        started = time.monotonic()
        seen: set[str] = set()
        error: str | None = None
        passive: dict[str, Any] = {}
        threads: list[threading.Thread] = []
        try:
            self.store.begin_scan()
            self._phase("starting", "detecting network")
            network, iface, hosts = netif.resolve_target(
                options.subnet, self._interfaces, options.max_hosts
            )
            if not self._interfaces:
                self.refresh_interfaces()
            interface_ip = iface.address if iface else None
            cidr = str(network)
            gateway = str(network.network_address + 1)
            network_info: dict[str, Any] = {
                "cidr": cidr,
                "interface": iface.name if iface else None,
                "address": interface_ip,
                "netmask": iface.netmask if iface else str(network.netmask),
                "broadcast": str(network.broadcast_address),
                "gateway": gateway,
                "host_count": netif.host_capacity(network),
                "scanned_at": time.time(),
                "source": options.subnet or "auto",
            }
            self.store.set_network(network_info)
            self._set_state(subnet=cidr, total=len(hosts), hosts_total=len(hosts))
            self._emit(
                "scan.started",
                scan_id=scan_id,
                state=self.state_dict(),
                options=options.to_dict(),
                network=network_info,
            )
            self._emit("network", network=network_info)

            # Passive collectors run while the sweep does the heavy lifting.
            if options.mdns and interface_ip:
                threads.append(
                    threading.Thread(
                        target=self._task_mdns,
                        args=(interface_ip, passive),
                        name="lanwatch-mdns",
                        daemon=True,
                    )
                )
            if options.ssdp and interface_ip:
                threads.append(
                    threading.Thread(
                        target=self._task_ssdp,
                        args=(interface_ip, passive),
                        name="lanwatch-ssdp",
                        daemon=True,
                    )
                )
            for thread in threads:
                thread.start()

            # 1. Neighbour cache: instant, and the only place MACs come from.
            self._seed_arp(network, seen)

            # 2. ICMP sweep, streaming devices as they answer.
            alive: set[str] = set()
            if collectors.ping_available():
                self._phase("sweep", f"pinging {len(hosts)} addresses", 0, len(hosts))
                counter = {"done": 0}

                def on_up(ip: str, rtt: float) -> None:
                    partial = Device(
                        ip=ip,
                        rtt_ms=rtt,
                        online=True,
                        sources=["icmp"],
                        is_self=(ip == interface_ip),
                    )
                    self._record(partial, seen)
                    alive.add(ip)

                def on_result(ip: str, rtt: float | None) -> None:
                    counter["done"] += 1
                    progress = counter["done"]
                    if progress == len(hosts) or progress % max(1, len(hosts) // 20) == 0:
                        self._phase(
                            "sweep", f"pinging {len(hosts)} addresses", progress, len(hosts)
                        )

                collectors.ping_sweep(
                    hosts,
                    timeout=options.ping_timeout,
                    concurrency=options.concurrency,
                    on_up=on_up,
                    cancel=self._cancel,
                    on_result=on_result,
                )
                self._collector("icmp", "ok", f"{len(alive)} of {len(hosts)} answered", len(alive))
            else:
                self._collector(
                    "icmp",
                    "unavailable",
                    "system ping is not usable; relying on TCP and neighbour data",
                )

            if self._cancel.is_set():
                self._finish(scan_id, seen, started, stopped=True)
                return

            # 3. Optional TCP sweep of hosts that ignored ICMP.  Without a
            # usable ping binary this is the only way to find live hosts.
            if options.deep or not collectors.ping_available():
                silent = [host for host in hosts if host not in alive]
                if silent:
                    self._phase("probe", f"probing {len(silent)} silent hosts", 0, len(silent))
                    found = collectors.scan_ports(
                        silent, DEEP_PORTS, timeout=0.25, workers=128, cancel=self._cancel
                    )
                    for ip, ports in sorted(found.items()):
                        self._record(
                            Device(ip=ip, ports=ports, sources=["tcp"], online=True), seen
                        )
                        alive.add(ip)
                    self._collector(
                        "tcp", "ok", f"{len(found)} silent hosts had open ports", len(found)
                    )

            # 4. Service probe on live hosts.
            if alive:
                self._phase("probe", f"checking {len(alive)} live hosts", 0, len(alive))
                open_map = collectors.scan_ports(
                    sorted(alive),
                    options.ports,
                    timeout=0.25,
                    workers=128,
                    cancel=self._cancel,
                )
                banners = _collect_banners(open_map)
                for ip, ports in sorted(open_map.items()):
                    self._record(
                        Device(
                            ip=ip,
                            ports=ports,
                            banners=banners.get(ip, {}),
                            sources=["tcp"],
                            online=True,
                        ),
                        seen,
                    )
                services = sum(len(ports) for ports in open_map.values())
                self._collector(
                    "tcp",
                    "ok" if services else "empty",
                    f"{services} open services on {len(open_map)} hosts",
                    services,
                )
                self._phase("probe", "service probe complete", len(alive), len(alive))

            # 5. Names: NetBIOS first (ranks above reverse DNS), then PTR.
            if options.nbns and alive:
                self._phase("names", "asking NetBIOS for names")
                names = collectors.run_bounded(
                    collectors.nbns_name, sorted(alive), workers=16, timeout=2.0
                )
                for ip, name in names.items():
                    if ip in seen or ip in alive:
                        self._record(
                            Device(
                                ip=ip,
                                nbns_name=str(name),
                                hostname=str(name),
                                hostname_source="nbns",
                                sources=["nbns"],
                                online=True,
                            ),
                            seen,
                        )
                self._collector(
                    "nbns",
                    "ok" if names else "empty",
                    f"{len(names)} NetBIOS names" if names else "no NetBIOS replies",
                    len(names),
                )
            elif options.nbns:
                self._collector("nbns", "skipped", "no live hosts to ask")

            if options.rdns and alive and not self._cancel.is_set():
                self._phase("names", "resolving reverse DNS")
                ptr_names = collectors.reverse_dns_many(sorted(alive), timeout=3.0)
                for ip, name in ptr_names.items():
                    self._record(
                        Device(ip=ip, hostname=name, hostname_source="rdns", sources=["rdns"]), seen
                    )
                self._collector(
                    "rdns",
                    "ok" if ptr_names else "empty",
                    f"{len(ptr_names)} PTR records" if ptr_names else "no reverse DNS records",
                    len(ptr_names),
                )
            elif options.rdns:
                self._collector("rdns", "skipped", "no live hosts to resolve")

            # 6. Collect passive results.
            for thread in threads:
                thread.join(timeout=max(0.0, 15.0 - (time.monotonic() - started)))
            self._merge_mdns(passive.get("mdns"), network, seen)
            self._merge_ssdp(passive.get("ssdp"), network, seen)

            # 7. Gateway and self marks.
            gateway_ip = netif.guess_gateway(network, alive)
            network_info["gateway"] = gateway_ip
            network_info["hosts_up"] = len(alive)
            self.store.set_network(network_info)
            self._emit("network", network=network_info)
            if gateway_ip in seen:
                with self.store.lock:
                    device = self.store.devices.get(gateway_ip)
                    if device is not None and not device.is_gateway:
                        device.is_gateway = True
                        self._emit("device", device=device.to_dict())
            if interface_ip in seen:
                with self.store.lock:
                    device = self.store.devices.get(interface_ip)
                    if device is not None and not device.is_self:
                        device.is_self = True
                        self._emit("device", device=device.to_dict())

            if self._cancel.is_set():
                self._finish(scan_id, seen, started, stopped=True)
                return

            # 8. Everything in this subnet that stayed silent is now offline.
            for device in self.store.mark_offline(seen, cidr):
                self._emit("device", device=device.to_dict())

            self._finish(scan_id, seen, started)
        except (netif.InterfaceError, netif.SubnetTooLarge, ValueError) as exc:
            error = str(exc)
        except Exception as exc:  # pragma: no cover - last-resort guard
            error = f"{type(exc).__name__}: {exc}"
        finally:
            if error is not None:
                finished = time.time()
                duration = round(time.monotonic() - started, 2)
                with self._lock:
                    finished_here = bool(
                        self.state.get("scan_id") == scan_id and self.state.get("running")
                    )
                    if finished_here:
                        self.state.update(
                            phase="error",
                            message=error,
                            error=error,
                            finished_at=finished,
                            duration_s=duration,
                        )
                        state = dict(self.state, running=False)
                    else:
                        state = dict(self.state)
                # Publish and persist before clearing "running": observers that
                # wait for the scan to stop must not race the final write.
                self._emit("scan.error", error=error, state=state)
                self._emit("scan.finished", state=state, counts=self.store.counts())
                self.store.save()
                if finished_here:
                    self._set_state(running=False)

    def _seed_arp(self, network: ipaddress.IPv4Network, seen: set[str]) -> None:
        table, source = collectors.arp_table()
        inside = {}
        for ip, mac in table.items():
            try:
                if ipaddress.ip_address(ip) in network:
                    inside[ip] = mac
            except ValueError:
                continue
        for ip, mac in sorted(inside.items()):
            self._record(
                Device(
                    ip=ip,
                    mac=mac,
                    vendor=oui.vendor_for(mac),
                    sources=["arp"],
                    online=True,
                ),
                seen,
            )
        if inside:
            self._collector("arp", "ok", f"{len(inside)} entries via {source}", len(inside))
        else:
            self._collector("arp", "empty", source)

    def _task_mdns(self, interface_ip: str, sink: dict[str, Any]) -> None:
        try:
            sink["mdns"] = collectors.mdns_browse(interface_ip, timeout=4.0, cancel=self._cancel)
        except Exception as exc:  # pragma: no cover - defensive
            failure = collectors.MdnsResult(error=f"{type(exc).__name__}: {exc}")
            sink["mdns"] = failure

    def _task_ssdp(self, interface_ip: str, sink: dict[str, Any]) -> None:
        try:
            sink["ssdp"] = collectors.ssdp_discover(
                interface_ip, timeout=3.5, cancel=self._cancel
            )
        except Exception as exc:  # pragma: no cover - defensive
            failure = collectors.SsdpResult(error=f"{type(exc).__name__}: {exc}")
            sink["ssdp"] = failure

    def _merge_mdns(self, result: Any, network: ipaddress.IPv4Network, seen: set[str]) -> None:
        if result is None:
            if self.options.mdns:
                self._collector("mdns", "skipped", "collector did not finish")
            return
        if not isinstance(result, collectors.MdnsResult):
            self._collector("mdns", "error", "unexpected collector result")
            return
        merged = 0
        for ip, info in sorted(result.by_ip.items()):
            try:
                if ipaddress.ip_address(ip) not in network:
                    continue
            except ValueError:
                continue
            raw_txt = info.get("txt")
            txt: dict[str, Any] = raw_txt if isinstance(raw_txt, dict) else {}
            advertisements: dict[str, str] = {}
            for key, label in (("fn", "friendlyName"), ("model", "model"), ("md", "model"), ("am", "model")):
                value = txt.get(key)
                if value and label not in advertisements:
                    advertisements[label] = str(value)
            hostname = str(info.get("hostname") or "") or None
            self._record(
                Device(
                    ip=ip,
                    hostname=hostname,
                    hostname_source="mdns",
                    mdns_services=[str(s) for s in info.get("services") or []],
                    ssdp=advertisements,
                    sources=["mdns"],
                    online=True,
                ),
                seen,
            )
            merged += 1
        if result.error:
            self._collector("mdns", "error", f"error: {result.error}", merged)
        elif result.received == 0:
            self._collector(
                "mdns",
                "empty",
                "no responses — multicast is often filtered on Android; try a desktop",
                merged,
            )
        else:
            detail = f"{result.received} packets, {len(result.service_types)} service types"
            self._collector("mdns", "ok" if merged else "empty", detail, merged)

    def _merge_ssdp(self, result: Any, network: ipaddress.IPv4Network, seen: set[str]) -> None:
        if result is None:
            if self.options.ssdp:
                self._collector("ssdp", "skipped", "collector did not finish")
            return
        if not isinstance(result, collectors.SsdpResult):
            self._collector("ssdp", "error", "unexpected collector result")
            return
        groups: dict[str, list[dict[str, str]]] = {}
        for entry in result.devices:
            try:
                if ipaddress.ip_address(entry["ip"]) in network:
                    groups.setdefault(entry["ip"], []).append(entry)
            except (KeyError, ValueError):
                continue
        for ip, entries in sorted(groups.items()):
            best = next((entry for entry in entries if entry.get("friendly")), entries[0])
            info: dict[str, str] = {}
            for entry in entries:
                for key, field_name in (
                    ("friendly", "friendlyName"),
                    ("manufacturer", "manufacturer"),
                    ("model", "model"),
                    ("device_type", "deviceType"),
                    ("server", "server"),
                ):
                    value = entry.get(key)
                    if value and not info.get(field_name):
                        info[field_name] = value
            self._record(
                Device(
                    ip=ip,
                    hostname=best.get("friendly") or None,
                    hostname_source="ssdp",
                    ssdp=info,
                    sources=["ssdp"],
                    online=True,
                ),
                seen,
            )
        if result.error:
            self._collector("ssdp", "error", f"error: {result.error}", len(groups))
        elif result.received == 0:
            self._collector(
                "ssdp",
                "empty",
                "no replies — multicast is often filtered on Android; try a desktop",
                len(groups),
            )
        else:
            self._collector(
                "ssdp",
                "ok" if groups else "empty",
                f"{result.received} replies, {len(result.devices)} advertisements",
                len(groups),
            )

    def _finish(
        self,
        scan_id: int,
        seen: set[str],
        started: float,
        stopped: bool = False,
    ) -> None:
        duration = round(time.monotonic() - started, 2)
        with self._lock:
            self.state.update(
                phase="stopped" if stopped else "done",
                message="scan stopped" if stopped else "scan complete",
                finished_at=time.time(),
                duration_s=duration,
                found=len(seen),
                stopped=stopped,
                done=self.state.get("hosts_total", 0),
                total=self.state.get("hosts_total", 0),
            )
            state = dict(self.state, running=False)
        # Publish and persist before clearing "running": observers that wait
        # for the scan to stop must not race the final write.
        self.store.save()
        self._emit("scan.finished", state=state, counts=self.store.counts(), stopped=stopped)
        self._set_state(running=False)


def _collect_banners(open_map: dict[str, list[int]]) -> dict[str, dict[str, str]]:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from concurrent.futures import TimeoutError as FutureTimeoutError

    tasks = [
        (ip, port)
        for ip, ports in open_map.items()
        for port in ports
        if port in collectors.BANNER_PORTS
    ]
    if not tasks:
        return {}
    results: dict[str, dict[str, str]] = {}
    with ThreadPoolExecutor(max_workers=min(16, len(tasks))) as pool:
        futures = {
            pool.submit(collectors.grab_banner, ip, port, 0.6): (ip, port) for ip, port in tasks
        }
        try:
            for future in as_completed(futures, timeout=6.0):
                ip, port = futures[future]
                try:
                    banner = future.result()
                except Exception:
                    banner = None
                if banner:
                    results.setdefault(ip, {})[str(port)] = banner
        except FutureTimeoutError:
            pass
    return results


def _is_android() -> bool:
    return "ANDROID_ROOT" in os.environ or os.path.exists("/system/build.prop")
