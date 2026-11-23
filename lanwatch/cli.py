"""Command line interface for lanwatch."""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import sqlite3
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__, collectors, netif, web
from .discovery import ScanEngine, ScanOptions
from .events import SEVERITIES, trust_event
from .history import HistoryStore, default_history_path
from .model import PORT_NAMES, Device, normalize_ip, validate_trust
from .store import Store

COMMANDS = {
    "scan",
    "watch",
    "devices",
    "history",
    "events",
    "web",
    "label",
    "forget",
    "trust",
    "version",
}


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _color_enabled() -> bool:
    return (
        sys.stdout.isatty()
        and os.environ.get("TERM", "") != "dumb"
        and "NO_COLOR" not in os.environ
    )


def _style(text: str, code: str) -> str:
    if not _color_enabled():
        return text
    return f"\033[{code}m{text}\033[0m"


def _truncate(text: str, width: int) -> str:
    text = text.replace("\n", " ")
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "…"


def _ago(timestamp: float) -> str:
    delta = max(0.0, time.time() - timestamp)
    if delta < 60:
        return f"{int(delta)}s"
    if delta < 3600:
        return f"{int(delta // 60)}m"
    if delta < 86400:
        return f"{int(delta // 3600)}h"
    return f"{int(delta // 86400)}d"


def _service_label(port: int) -> str:
    name = PORT_NAMES.get(port)
    return name if name else str(port)


def render_table(devices: list[Device], show_offline: bool = True, verbose: bool = False) -> str:
    rows = [device for device in devices if show_offline or device.online]
    if not rows:
        return (
            "No devices discovered yet.\n"
            "Run a scan, or check that this machine is on the same Wi-Fi/LAN."
        )
    width = max(60, min(shutil.get_terminal_size((100, 24)).columns, 140))
    name_width = max(14, min(32, width - 58))
    ident_width = 0 if width < 104 else 22
    fixed = 1 + 1 + 15 + 1 + name_width + 1 + 8 + 1 + 9
    if ident_width:
        fixed += ident_width + 1
    service_width = max(10, width - fixed)

    header = (
        f"  {'IP':<15} {_truncate('NAME', name_width):<{name_width}} "
        + (f"{'VENDOR / MAC':<{ident_width}} " if ident_width else "")
        + f"{'SERVICES':<{service_width}} {'LATENCY':>8} {'SEEN':>9}"
    )
    lines = [_style(header, "2")]
    for device in rows:
        dot = _style("●" if device.online else "○", "32" if device.online else "2")
        name = device.display_name
        if device.is_gateway:
            name = f"{name} (gateway)"
        elif device.is_self:
            name = f"{name} (this device)"
        ident = device.mac or device.vendor or "—"
        if device.mac and device.vendor:
            ident = f"{device.vendor} · {device.mac}"
        services = ", ".join(_service_label(port) for port in device.ports) or "—"
        latency = f"{device.rtt_ms:.0f} ms" if device.rtt_ms is not None else "—"
        seen = _ago(device.last_seen) if device.online else f"{_ago(device.last_seen)} ago"
        ip_cell = _style(f"{device.ip:<15}", "36")
        seen_cell = _style(f"{seen:>9}", "2")
        line = (
            f"{dot} {ip_cell} {_truncate(name, name_width):<{name_width}} "
            + (f"{_truncate(ident, ident_width):<{ident_width}} " if ident_width else "")
            + f"{_truncate(services, service_width):<{service_width}} "
            f"{latency:>8} {seen_cell}"
        )
        lines.append(line)
        if verbose:
            details = []
            if device.trust != "unknown":
                details.append(f"trust {device.trust}")
            if device.hostname:
                details.append(f"hostname {device.hostname} ({device.hostname_source})")
            if device.mac:
                details.append(f"mac {device.mac}")
            if device.vendor:
                details.append(f"vendor {device.vendor}")
            if device.sources:
                details.append("via " + ",".join(device.sources))
            if device.ssdp:
                details.append(
                    "advertised " + ", ".join(f"{k}={v}" for k, v in device.ssdp.items() if v)
                )
            if device.notes:
                details.append(f"notes {device.notes}")
            if details:
                lines.append("  " + _style("  ".join(details), "2"))
    online = sum(1 for device in rows if device.online)
    lines.append("")
    lines.append(
        _style(f"{online} online · {len(rows) - online} offline · {len(rows)} known", "2")
    )
    return "\n".join(lines)


def _history_time(timestamp: object) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(float(str(timestamp))))
    except (TypeError, ValueError, OSError):
        return "—"


def _duration_text(value: object) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return "—"
    seconds = float(value)
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    rest = int(seconds % 60)
    if minutes < 60:
        return f"{minutes}m {rest}s"
    return f"{minutes // 60}h {minutes % 60}m"


def _history_status(scan: dict[str, Any]) -> str:
    if scan.get("error"):
        return "error"
    if scan.get("stopped"):
        return "stopped"
    return "ok"


def render_history(scans: list[dict[str, Any]]) -> str:
    if not scans:
        return "No scan history yet.\nHistory is recorded after each completed scan."
    header = f"{'WHEN':<16} {'NETWORK':<20} {'FOUND':>5} {'UP':>4} {'DURATION':>9} {'STATUS':<8}"
    lines = [_style(header, "2")]
    colors = {"ok": "32", "stopped": "33", "error": "31"}
    for scan in scans:
        status = _history_status(scan)
        when = _history_time(scan.get("finished_at"))
        network = _truncate(str(scan.get("subnet") or "—"), 20)
        found = int(scan.get("devices_found") or 0)
        up = int(scan.get("hosts_up") or 0)
        duration = _duration_text(scan.get("duration_s"))
        status_cell = _style(f"{status:<8}", colors[status])
        lines.append(f"{when:<16} {network:<20} {found:>5} {up:>4} {duration:>9} {status_cell}")
    return "\n".join(lines)


def render_device_history(ip: str, visits: list[dict[str, Any]]) -> str:
    if not visits:
        return (
            f"No history for {ip}.\n"
            "The address will appear here after a scan finds it."
        )
    header = f"{'WHEN':<16} {'NAME':<24} {'NETWORK':<20} {'LATENCY':>8} {'SERVICES'}"
    lines = [_style(header, "2")]
    for visit in visits:
        when = _history_time(visit.get("finished_at"))
        name = _truncate(str(visit.get("name") or visit.get("hostname") or "—"), 24)
        network = _truncate(str(visit.get("subnet") or "—"), 20)
        latency = visit.get("latency_ms")
        latency_text = f"{float(latency):.0f} ms" if isinstance(latency, (int, float)) else "—"
        ports = visit.get("ports") or []
        services = ", ".join(_service_label(int(port)) for port in ports) or "—"
        lines.append(f"{when:<16} {name:<24} {network:<20} {latency_text:>8} {services}")
    return "\n".join(lines)


def render_events(events: list[dict[str, Any]]) -> str:
    if not events:
        return "No events recorded yet.\nEvents appear after scans discover changes."
    lines = []
    for event in events:
        when = _history_time(event.get("ts"))
        severity = str(event.get("severity") or "info")
        color = {"info": "2", "warning": "33", "critical": "31"}.get(
            severity, "2"
        )
        marker = "*" if not event.get("read") else " "
        title = _truncate(str(event.get("title") or event.get("type") or "event"), 62)
        lines.append(
            f"{marker} {when:<16} {_style(f'{severity:<8}', color)} {title}"
        )
        message = str(event.get("message") or "").strip()
        if message:
            lines.append(f"  {_style(_truncate(message, 96), '2')}")
    return "\n".join(lines)


def _collector_summary(engine: ScanEngine) -> str:
    parts = []
    for name, entry in engine.collectors_dict().items():
        status = entry.get("status")
        count = entry.get("count", 0)
        if status in ("ok", "empty"):
            parts.append(f"{name} {count}")
        elif status in ("pending", "skipped", "idle"):
            continue
        else:
            parts.append(f"{name} {status}")
    return " · ".join(parts)


def _summary(engine: ScanEngine, device_count: int, elapsed: float) -> str:
    network = engine.store.network or {}
    state = engine.state_dict()
    total = state.get("hosts_total") or (network.get("host_count") or 0)
    cidr = network.get("cidr") or "?"
    interface = network.get("interface") or "?"
    address = network.get("address") or "?"
    first = f"{cidr} · {interface} · {address}"
    second = f"{device_count} device{'s' if device_count != 1 else ''} found of {total} addresses in {elapsed:.1f}s"
    summary = f"{_style('network', '2')} {first}\n{_style('result ', '2')} {second}"
    collectors_line = _collector_summary(engine)
    if collectors_line:
        summary += f"\n{_style('sources', '2')} {collectors_line}"
    diff_line = _diff_summary(engine.last_diff)
    if diff_line:
        summary += f"\n{_style('changes', '2')} {diff_line}"
    return summary


def _diff_summary(diff: dict[str, Any] | None) -> str:
    if not diff:
        return ""
    if diff.get("baseline"):
        return "baseline recorded"
    if diff.get("partial"):
        return "scan was stopped; comparison skipped"
    counts = diff.get("counts") or {}
    parts = []
    for key, label in (
        ("new", "new"),
        ("returned", "returned"),
        ("offline", "offline"),
        ("changed", "changed"),
    ):
        count = int(counts.get(key) or 0)
        if count:
            parts.append(f"{count} {label}")
    return " · ".join(parts) if parts else "no changes"


def _build_options(args: argparse.Namespace) -> ScanOptions:
    ports = collectors.DEFAULT_PORTS
    if getattr(args, "ports", None):
        options = ScanOptions.from_payload({"ports": args.ports})
        ports = options.ports
    return ScanOptions(
        subnet=getattr(args, "subnet", None),
        ports=list(ports),
        ping_timeout=getattr(args, "timeout", 1.0),
        concurrency=getattr(args, "concurrency", 64),
        max_hosts=getattr(args, "max_hosts", netif.DEFAULT_MAX_HOSTS),
        deep=getattr(args, "deep", False),
        http=not getattr(args, "no_http", False),
        mdns=not getattr(args, "no_mdns", False),
        ssdp=not getattr(args, "no_ssdp", False),
        nbns=not getattr(args, "no_nbns", False),
        rdns=not getattr(args, "no_rdns", False),
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _run_scan(engine: ScanEngine, show_offline: bool, verbose: bool, quiet: bool) -> int:
    options = engine.options
    if not quiet:
        target = options.subnet or "auto-detect"
        print(_style(f"scanning {target} …", "2"), file=sys.stderr)
    channel = engine.bus.subscribe()
    started, message = engine.start(options)
    if not started:
        print(f"lanwatch: {message}", file=sys.stderr)
        return 1
    last_progress = ""
    start = time.monotonic()
    while True:
        try:
            event = channel.get(timeout=0.25)
        except queue.Empty:
            event = None
        if event is not None:
            if event.get("type") == "scan.finished":
                break
            if event.get("type") == "progress" and not quiet and sys.stderr.isatty():
                state = event.get("state") or {}
                done, total = state.get("done", 0), state.get("total", 0)
                if state.get("phase") in ("sweep", "probe", "names"):
                    text = f"{state.get('phase')} {done}/{total}"
                    if text != last_progress:
                        sys.stderr.write(f"\r\033[2K  {_style(text, '2')}")
                        sys.stderr.flush()
                        last_progress = text
            continue
        if not engine.running:
            break
    if last_progress:
        sys.stderr.write("\r\033[2K")
        sys.stderr.flush()
    engine.bus.unsubscribe(channel)
    elapsed = time.monotonic() - start
    state = engine.state_dict()
    if state.get("error"):
        print(f"lanwatch: {state['error']}", file=sys.stderr)
        return 1
    devices = engine.store.devices_sorted()
    if not quiet:
        print()
        print(render_table(devices, show_offline=show_offline, verbose=verbose))
        print()
        print(_summary(engine, len(devices), elapsed))
    return 0


def _open_store(args: argparse.Namespace) -> Store:
    state = getattr(args, "state", None)
    return Store(Path(state).expanduser() if state else None)


def cmd_scan(args: argparse.Namespace) -> int:
    engine = ScanEngine(_open_store(args), _build_options(args))
    quiet = True if args.json or args.csv else bool(args.quiet)
    code = _run_scan(engine, show_offline=args.all, verbose=args.verbose, quiet=quiet)
    if code != 0:
        return code
    if args.json:
        print(json.dumps(engine.snapshot(), indent=2, default=str))
    if args.csv:
        print(engine.store.export_csv(engine.store.devices_sorted()), end="")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    store = _open_store(args)
    engine = ScanEngine(store, _build_options(args))
    interval = max(5, int(args.interval))
    try:
        while True:
            if sys.stdout.isatty():
                sys.stdout.write("\033[2J\033[H")
                sys.stdout.flush()
            print(_style(f"{time.strftime('%Y-%m-%d %H:%M:%S')}", "2"))
            _run_scan(engine, show_offline=args.all, verbose=args.verbose, quiet=args.quiet)
            print()
            print(_style(f"next scan in {interval}s · Ctrl+C to stop", "2"))
            time.sleep(interval)
    except KeyboardInterrupt:
        print()
        return 0


def cmd_devices(args: argparse.Namespace) -> int:
    store = _open_store(args)
    devices = store.devices_sorted()
    trust = getattr(args, "trust", None)
    if trust:
        level = validate_trust(trust)
        devices = [device for device in devices if device.trust == level]
    if args.json:
        print(json.dumps(store.snapshot(), indent=2, default=str))
        return 0
    if args.csv:
        print(store.export_csv(devices), end="")
        return 0
    print(render_table(devices, show_offline=not args.online, verbose=args.verbose))
    if store.network:
        print()
        print(_style(f"last network {store.network.get('cidr')} · {store.network.get('interface')}", "2"))
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    store = _open_store(args)
    history = HistoryStore(default_history_path(store.path))
    limit = max(1, min(200, int(args.limit)))
    try:
        if args.device:
            address = normalize_ip(args.device)
            visits = history.device_history(address, limit)
            if args.json:
                print(
                    json.dumps(
                        {
                            "ip": address,
                            "visits": visits,
                            "history_path": str(history.path),
                        },
                        indent=2,
                        default=str,
                    )
                )
                return 0
            print(render_device_history(address, visits))
            if visits:
                print()
                print(_style(f"{len(visits)} visit(s) · history {history.path}", "2"))
            return 0

        scans = history.recent(limit)
        if args.json:
            print(
                json.dumps(
                    {"scans": scans, "history_path": str(history.path)},
                    indent=2,
                    default=str,
                )
            )
            return 0
        print(render_history(scans))
        if scans:
            print()
            print(_style(f"{len(scans)} scan(s) · history {history.path}", "2"))
        return 0
    except (OSError, sqlite3.Error) as exc:
        print(f"lanwatch: cannot read scan history: {exc}", file=sys.stderr)
        return 1


def cmd_events(args: argparse.Namespace) -> int:
    store = _open_store(args)
    history = HistoryStore(default_history_path(store.path))
    limit = max(1, min(200, int(args.limit)))
    severities = [item.strip().lower() for item in (args.severity or "").split(",") if item.strip()]
    unknown = [value for value in severities if value not in SEVERITIES]
    if unknown:
        print(f"lanwatch: unknown severity {unknown[0]!r}", file=sys.stderr)
        return 2
    try:
        device = normalize_ip(args.device) if args.device else None
    except ValueError as exc:
        print(f"lanwatch: {exc}", file=sys.stderr)
        return 2
    try:
        events = history.event_log(
            limit,
            severities=severities,
            event_type=args.type,
            device=device,
            unread=args.unread,
        )
        unread = history.unread_count()
    except (OSError, sqlite3.Error) as exc:
        print(f"lanwatch: cannot read event log: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(
            json.dumps(
                {
                    "events": events,
                    "unread": unread,
                    "event_path": str(history.path),
                },
                indent=2,
                default=str,
            )
        )
        return 0
    print(render_events(events))
    print()
    print(_style(f"{len(events)} event(s) · {unread} unread · log {history.path}", "2"))
    return 0


def cmd_trust(args: argparse.Namespace) -> int:
    store = _open_store(args)
    try:
        address = normalize_ip(args.ip)
        level = validate_trust(args.level)
    except ValueError as exc:
        print(f"lanwatch: {exc}", file=sys.stderr)
        return 2
    previous = store.devices.get(address)
    before = previous.trust if previous is not None else None
    try:
        device = store.set_trust(address, level)
    except ValueError as exc:
        print(f"lanwatch: {exc}", file=sys.stderr)
        return 2
    if device is None:
        print(f"lanwatch: no device with IP {address} in the inventory", file=sys.stderr)
        return 1
    store.save()
    if before is not None and before != device.trust:
        history = HistoryStore(default_history_path(store.path))
        event = trust_event(device, before, store.active_id)
        try:
            history.record_event(event)
        except (OSError, sqlite3.Error) as exc:
            print(f"lanwatch: trust saved but event was not recorded: {exc}", file=sys.stderr)
    print(f"{device.ip} is now {device.trust}")
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    store = _open_store(args)
    engine = ScanEngine(store, _build_options(args))
    return web.serve(
        host=args.host,
        port=args.port,
        engine=engine,
        open_browser=not args.no_open,
        auto_scan=args.scan,
    )


def cmd_label(args: argparse.Namespace) -> int:
    store = _open_store(args)
    try:
        device = store.set_user_fields(args.ip, args.name, args.notes)
    except ValueError as exc:
        print(f"lanwatch: {exc}", file=sys.stderr)
        return 2
    if device is None:
        print(f"lanwatch: no device with IP {args.ip} in the inventory", file=sys.stderr)
        return 1
    store.save()
    print(f"labelled {device.ip} as {device.display_name!r}")
    return 0


def cmd_forget(args: argparse.Namespace) -> int:
    store = _open_store(args)
    try:
        removed = store.forget(args.ip)
    except ValueError as exc:
        print(f"lanwatch: {exc}", file=sys.stderr)
        return 2
    store.save()
    print("removed" if removed else "nothing to remove")
    return 0 if removed else 1


def cmd_version(args: argparse.Namespace) -> int:
    print(f"lanwatch {__version__}")
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "subnet",
        nargs="?",
        help="CIDR (192.168.1.0/24), address (192.168.1.0), or interface name (wlan0)",
    )
    parser.add_argument("-p", "--ports", help="comma-separated ports to probe")
    parser.add_argument("--timeout", type=float, default=1.0, help="ping timeout in seconds")
    parser.add_argument("--concurrency", type=int, default=64, help="parallel ping workers")
    parser.add_argument("--max-hosts", type=int, default=netif.DEFAULT_MAX_HOSTS, help="refuse larger subnets")
    parser.add_argument("--deep", action="store_true", help="TCP-probe hosts that ignore ICMP")
    parser.add_argument("--no-mdns", action="store_true", help="skip mDNS-SD discovery")
    parser.add_argument("--no-ssdp", action="store_true", help="skip SSDP/UPnP discovery")
    parser.add_argument("--no-nbns", action="store_true", help="skip NetBIOS name queries")
    parser.add_argument(
        "--no-http", action="store_true", help="skip web-page fingerprinting (titles, headers, certs)"
    )
    parser.add_argument("--no-rdns", action="store_true", help="skip reverse DNS")
    parser.add_argument("--all", action="store_true", help="include offline devices in the table")
    parser.add_argument("--verbose", "-v", action="store_true", help="show names, MACs and notes")
    parser.add_argument("--json", action="store_true", help="print the full snapshot as JSON")
    parser.add_argument("--csv", action="store_true", help="print the inventory as CSV")
    parser.add_argument("--quiet", "-q", action="store_true", help="suppress the table")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--state", help="inventory file (default: XDG state directory)")
    common.add_argument("--version", action="version", version=f"lanwatch {__version__}")

    parser = argparse.ArgumentParser(
        prog="lanwatch",
        description="Discover the devices on your LAN and watch them live.",
        parents=[common],
        epilog=(
            "examples:\n"
            "  lanwatch                      scan the detected LAN\n"
            "  lanwatch 192.168.1.0/24       scan a specific subnet\n"
            "  lanwatch web                  open the live dashboard\n"
            "  lanwatch watch -i 60          rescan every minute\n"
            "  lanwatch devices --all        list the saved inventory\n"
            "  lanwatch history              show recent scans\n"
            "  lanwatch events               show recent network changes\n"
            "  lanwatch trust 192.168.1.5 trusted  approve a device\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    scan = subparsers.add_parser("scan", parents=[common], help="discover devices once")
    _add_scan_options(scan)
    scan.set_defaults(func=cmd_scan)

    watch = subparsers.add_parser("watch", parents=[common], help="scan repeatedly")
    _add_scan_options(watch)
    watch.add_argument("-i", "--interval", type=int, default=30, help="seconds between scans")
    watch.set_defaults(func=cmd_watch)

    devices = subparsers.add_parser("devices", parents=[common], help="list the saved inventory")
    devices.add_argument("--online", action="store_true", help="only show online devices")
    devices.add_argument("--trust", choices=("trusted", "unknown", "ignored"), help="filter by trust")
    devices.add_argument("--json", action="store_true", help="print JSON")
    devices.add_argument("--csv", action="store_true", help="print CSV")
    devices.add_argument("--verbose", "-v", action="store_true", help="show names, MACs and notes")
    devices.set_defaults(func=cmd_devices)

    history_parser = subparsers.add_parser(
        "history", parents=[common], help="show recorded scan history"
    )
    history_parser.add_argument("--limit", type=int, default=20, help="rows to show (default 20)")
    history_parser.add_argument("--device", metavar="IP", help="show history for one device")
    history_parser.add_argument("--json", action="store_true", help="print JSON")
    history_parser.set_defaults(func=cmd_history)

    events_parser = subparsers.add_parser(
        "events", parents=[common], help="show the persistent Event Center log"
    )
    events_parser.add_argument("--limit", type=int, default=30, help="rows to show (default 30)")
    events_parser.add_argument("--severity", help="comma-separated severities")
    events_parser.add_argument("--type", help="filter by event type")
    events_parser.add_argument("--device", metavar="IP", help="filter by device IP")
    events_parser.add_argument("--unread", action="store_true", help="only show unread events")
    events_parser.add_argument("--json", action="store_true", help="print JSON")
    events_parser.set_defaults(func=cmd_events)

    web_parser = subparsers.add_parser("web", parents=[common], help="serve the web dashboard")
    web_parser.add_argument("--host", default="127.0.0.1", help="bind address (default: loopback)")
    web_parser.add_argument("--port", type=int, default=8765, help="listen port")
    web_parser.add_argument("--no-open", action="store_true", help="do not open a browser")
    web_parser.add_argument("--scan", action="store_true", help="start a scan immediately")
    web_parser.add_argument("--subnet", help="default subnet for scans")
    web_parser.add_argument("-p", "--ports", help="default ports to probe")
    web_parser.add_argument("--timeout", type=float, default=1.0, help="ping timeout in seconds")
    web_parser.add_argument("--concurrency", type=int, default=64)
    web_parser.add_argument("--max-hosts", type=int, default=netif.DEFAULT_MAX_HOSTS)
    web_parser.add_argument("--deep", action="store_true")
    web_parser.add_argument("--no-mdns", action="store_true")
    web_parser.add_argument("--no-ssdp", action="store_true")
    web_parser.add_argument("--no-nbns", action="store_true")
    web_parser.add_argument("--no-http", action="store_true")
    web_parser.add_argument("--no-rdns", action="store_true")
    web_parser.set_defaults(func=cmd_web)

    label = subparsers.add_parser("label", parents=[common], help="give a device a friendly name")
    label.add_argument("ip")
    label.add_argument("name", nargs="?")
    label.add_argument("--notes", help="free-form notes")
    label.set_defaults(func=cmd_label)

    forget = subparsers.add_parser("forget", parents=[common], help="remove a device")
    forget.add_argument("ip")
    forget.set_defaults(func=cmd_forget)

    trust = subparsers.add_parser("trust", parents=[common], help="set a device's trust level")
    trust.add_argument("ip")
    trust.add_argument("level", choices=("trusted", "unknown", "ignored"))
    trust.set_defaults(func=cmd_trust)

    version = subparsers.add_parser("version", parents=[common], help="print the version")
    version.set_defaults(func=cmd_version)
    return parser


def _normalize_argv(argv: list[str]) -> list[str]:
    """Make ``lanwatch 10.0.0.0/8`` and bare ``lanwatch`` mean ``scan``."""
    if not argv:
        return ["scan"]
    if argv[0] in ("-h", "--help", "--version"):
        return argv
    value_options = {
        "--state",
        "--ports",
        "-p",
        "--timeout",
        "--concurrency",
        "--max-hosts",
        "--host",
        "--port",
        "--interval",
        "-i",
        "--notes",
        "--limit",
        "--device",
        "--severity",
        "--type",
        "--trust",
    }
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in COMMANDS:
            return argv
        if token in value_options:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    return ["scan", *argv]


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(_normalize_argv(raw))
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    try:
        return int(args.func(args))
    except netif.InterfaceError as exc:
        print(f"lanwatch: {exc}", file=sys.stderr)
        return 1
    except netif.SubnetTooLarge as exc:
        print(f"lanwatch: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"lanwatch: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
