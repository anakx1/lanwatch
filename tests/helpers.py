"""Shared fixtures for the test suite."""

from __future__ import annotations

import contextlib
import ipaddress
import time
from unittest import mock

from lanwatch import collectors, netif


def fake_target() -> tuple[ipaddress.IPv4Network, netif.Interface, list[str]]:
    interface = netif.Interface(
        name="wlan0",
        address="10.0.0.5",
        netmask="255.255.255.0",
        flags=netif.IFF_UP | netif.IFF_BROADCAST,
    )
    return ipaddress.ip_network("10.0.0.0/24"), interface, ["10.0.0.1", "10.0.0.2", "10.0.0.5"]


def _fake_ping_sweep(hosts, timeout, concurrency, on_up, cancel, on_result):
    answers = {"10.0.0.1": 3.0, "10.0.0.5": 0.4}
    for host in hosts:
        rtt = answers.get(host)
        if rtt is not None:
            on_up(host, rtt)
        on_result(host, rtt)
    return dict(answers)


def _fake_scan_ports(hosts, ports, timeout=0.3, workers=128, cancel=None):
    mapping = {"10.0.0.1": [80, 443], "10.0.0.5": [8080]}
    return {host: mapping[host] for host in hosts if host in mapping}


def _fake_mdns(iface_ip, timeout=4.0, cancel=None):
    return collectors.MdnsResult(
        by_ip={
            "10.0.0.2": {
                "hostname": "printer",
                "services": ["_ipp._tcp"],
                "txt": {"model": "Brother HL-2270DW"},
            }
        },
        service_types=["_ipp._tcp"],
        sent=3,
        received=2,
    )


def _fake_ssdp(iface_ip, timeout=3.5, cancel=None):
    return collectors.SsdpResult(
        devices=[
            {
                "ip": "10.0.0.9",
                "st": "urn:schemas-upnp-org:device:MediaRenderer:1",
                "usn": "uuid:test",
                "server": "Linux/5.0 UPnP/1.1",
                "location": "",
                "friendly": "Living Room TV",
                "manufacturer": "Sony",
                "model": "Bravia",
                "device_type": "MediaRenderer",
            }
        ],
        sent=1,
        received=1,
    )


@contextlib.contextmanager
def patched_scan(extra: dict | None = None):
    """Patch every collector so a scan runs offline and deterministically."""
    patches = {
        "lanwatch.discovery.netif.resolve_target": mock.Mock(side_effect=lambda *a, **k: fake_target()),
        "lanwatch.discovery.netif.default_gateway": mock.Mock(return_value=None),
        "lanwatch.discovery.collectors.ping_available": mock.Mock(return_value=True),
        "lanwatch.discovery.collectors.ping_sweep": mock.Mock(side_effect=_fake_ping_sweep),
        "lanwatch.discovery.collectors.arp_table": mock.Mock(
            return_value=(
                {"10.0.0.2": "3c:22:fb:11:22:33", "192.168.9.9": "ac:de:48:00:11:22"},
                "proc",
            )
        ),
        "lanwatch.discovery.collectors.scan_ports": mock.Mock(side_effect=_fake_scan_ports),
        "lanwatch.discovery.collectors.grab_banner": mock.Mock(return_value=None),
        "lanwatch.discovery.collectors.http_probe_many": mock.Mock(
            return_value={
                "10.0.0.1": {"80": {"status": "200", "title": "Acme Router Login", "server": "uhttpd"}}
            }
        ),
        "lanwatch.discovery.collectors.run_bounded": mock.Mock(return_value={"10.0.0.1": "ROUTER"}),
        "lanwatch.discovery.collectors.reverse_dns_many": mock.Mock(
            return_value={"10.0.0.1": "router.lan"}
        ),
        "lanwatch.discovery.collectors.mdns_browse": mock.Mock(side_effect=_fake_mdns),
        "lanwatch.discovery.collectors.ssdp_discover": mock.Mock(side_effect=_fake_ssdp),
    }
    patches.update(extra or {})
    with contextlib.ExitStack() as stack:
        for target, replacement in patches.items():
            stack.enter_context(mock.patch(target, replacement))
        yield


def wait_until(predicate, timeout: float = 10.0, interval: float = 0.02) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False
