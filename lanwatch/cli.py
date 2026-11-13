"""Command line interface for lanwatch."""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from . import __version__, collectors, netif, web
from .discovery import ScanEngine, ScanOptions
from .model import PORT_NAMES, Device
from .store import Store

COMMANDS = {"scan", "watch", "devices", "web", "label", "forget", "version"}


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
    return summary


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
    devices.add_argument("--json", action="store_true", help="print JSON")
    devices.add_argument("--csv", action="store_true", help="print CSV")
    devices.add_argument("--verbose", "-v", action="store_true", help="show names, MACs and notes")
    devices.set_defaults(func=cmd_devices)

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
