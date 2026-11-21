"""Local interface detection without netlink.

Android restricts ``AF_NETLINK`` for ordinary apps, which rules out ``ip addr``
and ``ip route``.  The classic ``SIOCGIF*`` ioctls still work, so that is the
primary path; ``ifconfig`` output is parsed as a fallback for systems where
even the ioctls are unavailable.
"""

from __future__ import annotations

import fcntl
import ipaddress
import re
import socket
import struct
import subprocess
from dataclasses import dataclass

IFF_UP = 0x1
IFF_BROADCAST = 0x2
IFF_LOOPBACK = 0x8
IFF_POINTOPOINT = 0x10

SIOCGIFFLAGS = 0x8913
SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B

DEFAULT_MAX_HOSTS = 1024


class InterfaceError(RuntimeError):
    """Raised when no usable IPv4 interface can be found."""


class SubnetTooLarge(ValueError):
    """Raised when a subnet would require more probes than the limit allows."""


@dataclass(frozen=True)
class Interface:
    name: str
    address: str
    netmask: str
    flags: int = 0

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Interface(f"{self.address}/{self.netmask}").network

    @property
    def cidr(self) -> str:
        return str(self.network)

    @property
    def host_count(self) -> int:
        return host_capacity(self.network)

    @property
    def is_private(self) -> bool:
        return ipaddress.ip_address(self.address).is_private

    @property
    def is_loopback(self) -> bool:
        return bool(self.flags & IFF_LOOPBACK) or self.address.startswith("127.")

    @property
    def is_point_to_point(self) -> bool:
        return bool(self.flags & IFF_POINTOPOINT)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "address": self.address,
            "netmask": self.netmask,
            "cidr": self.cidr,
            "host_count": self.host_count,
            "is_private": self.is_private,
        }


def host_capacity(network: ipaddress.IPv4Network) -> int:
    """Number of probeable host addresses in *network*."""
    if network.prefixlen >= 31:
        return network.num_addresses
    return network.num_addresses - 2


def _ifreq(name: str, request: int, sock: socket.socket) -> bytes:
    packed = struct.pack("256s", name[:15].encode("utf-8", "replace"))
    return fcntl.ioctl(sock.fileno(), request, packed)


def _ioctl_address(sock: socket.socket, name: str) -> str | None:
    try:
        return socket.inet_ntoa(_ifreq(name, SIOCGIFADDR, sock)[20:24])
    except OSError:
        return None


def _ioctl_netmask(sock: socket.socket, name: str) -> str | None:
    try:
        return socket.inet_ntoa(_ifreq(name, SIOCGIFNETMASK, sock)[20:24])
    except OSError:
        return None


def _ioctl_flags(sock: socket.socket, name: str) -> int:
    try:
        return struct.unpack("H", _ifreq(name, SIOCGIFFLAGS, sock)[16:18])[0]
    except OSError:
        return 0


def _names_from_ifconfig() -> list[str]:
    try:
        out = subprocess.run(
            ["ifconfig"], capture_output=True, text=True, timeout=8, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    names = []
    for line in out.splitlines():
        match = re.match(r"^([A-Za-z0-9_.:-]+):\s+flags=", line.strip())
        if match:
            names.append(match.group(1))
    return names


def detect_interfaces() -> list[Interface]:
    """Return every IPv4 interface with an address and netmask."""
    names: list[str] = []
    try:
        names = [name for _, name in socket.if_nameindex()]
    except OSError:
        names = []
    if not names:
        names = _names_from_ifconfig()

    interfaces: list[Interface] = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        sock = None
    try:
        seen = set()
        for name in names:
            if name in seen:
                continue
            seen.add(name)
            if sock is not None:
                address = _ioctl_address(sock, name)
                netmask = _ioctl_netmask(sock, name)
                flags = _ioctl_flags(sock, name)
            else:
                address = netmask = None
                flags = 0
            if not address or not netmask or address == "0.0.0.0":
                continue
            try:
                network = ipaddress.IPv4Interface(f"{address}/{netmask}").network
            except ValueError:
                continue
            if network.prefixlen >= 32:
                continue
            interfaces.append(Interface(name, address, netmask, flags))
    finally:
        if sock is not None:
            sock.close()

    if not interfaces:
        interfaces = parse_ifconfig(_run_ifconfig())
    # Stable order: real broadcast interfaces first, then by name.
    interfaces.sort(key=lambda i: (i.is_loopback, i.is_point_to_point, i.name))
    return interfaces


def _run_ifconfig() -> str:
    try:
        return subprocess.run(
            ["ifconfig"], capture_output=True, text=True, timeout=8, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def parse_ifconfig(text: str) -> list[Interface]:
    """Best-effort parser for ``ifconfig`` output (fallback path)."""
    blocks: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        head = re.match(r"^([A-Za-z0-9_.:-]+):\s+flags=(\d+)", line)
        if head:
            current = {"name": head.group(1), "flags": int(head.group(2))}
            blocks.append(current)
            continue
        if current is None or "inet " not in f" {line} ":
            continue
        tokens = line.split()
        for index, token in enumerate(tokens):
            if token == "inet" and index + 1 < len(tokens):
                current["address"] = tokens[index + 1]
            elif token == "netmask" and index + 1 < len(tokens):
                current["netmask"] = tokens[index + 1].replace("0x", "")
    results: list[Interface] = []
    for block in blocks:
        address = block.get("address")
        netmask = block.get("netmask")
        if not isinstance(address, str) or not isinstance(netmask, str):
            continue
        if netmask.startswith("0x"):
            try:
                netmask = socket.inet_ntoa(struct.pack(">I", int(netmask, 16)))
            except (ValueError, OSError):
                continue
        try:
            if ipaddress.IPv4Interface(f"{address}/{netmask}").network.prefixlen >= 32:
                continue
        except ValueError:
            continue
        flags_value = block.get("flags", 0)
        results.append(
            Interface(
                name=str(block["name"]),
                address=address,
                netmask=netmask,
                flags=flags_value if isinstance(flags_value, int) else 0,
            )
        )
    return results


def choose_interface(interfaces: list[Interface] | None = None) -> Interface:
    """Pick the interface most likely to be the LAN link."""
    candidates = [i for i in (interfaces or detect_interfaces()) if usable(i)]
    if not candidates:
        raise InterfaceError(
            "no usable IPv4 LAN interface found; pass --subnet 192.168.1.0/24"
        )

    def score(iface: Interface) -> tuple[int, int]:
        points = 0
        if iface.is_private:
            points += 4
        if iface.flags & IFF_BROADCAST:
            points += 2
        if re.match(r"^(wlan|eth|en|wlp|br|ap)", iface.name):
            points += 3
        if 2 <= iface.host_count <= 4094:
            points += 2
        if iface.host_count > 65534:
            points -= 4
        return (points, iface.host_count)

    return max(candidates, key=score)


def usable(iface: Interface) -> bool:
    if iface.is_loopback or iface.is_point_to_point:
        return False
    if iface.address.startswith("0.") or iface.netmask == "0.0.0.0":
        return False
    if iface.flags and not (iface.flags & IFF_UP):
        return False
    return host_capacity(iface.network) > 0


def lookup_interface(name: str, interfaces: list[Interface] | None = None) -> Interface | None:
    for iface in interfaces or detect_interfaces():
        if iface.name == name:
            return iface
    return None


def resolve_target(
    spec: str | None,
    interfaces: list[Interface] | None = None,
    max_hosts: int = DEFAULT_MAX_HOSTS,
) -> tuple[ipaddress.IPv4Network, Interface | None, list[str]]:
    """Turn a CLI/web subnet spec into a network, interface and host list.

    ``spec`` may be ``None``/``auto``, an interface name (``wlan0``), a CIDR
    (``192.168.1.0/24``) or a bare address (``192.168.1.0``, assumed /24).
    """
    found = interfaces if interfaces is not None else detect_interfaces()
    iface: Interface | None = None
    text = (spec or "").strip()

    if not text or text.lower() == "auto":
        iface = choose_interface(found)
        network = iface.network
    elif "/" not in text and not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", text):
        iface = lookup_interface(text, found)
        if iface is None:
            raise InterfaceError(f"unknown interface {text!r}")
        network = iface.network
    else:
        if "/" in text:
            try:
                parsed = ipaddress.ip_network(text, strict=False)
            except ValueError as exc:
                raise InterfaceError(f"invalid subnet {text!r}: {exc}") from exc
        else:
            try:
                parsed = ipaddress.ip_network(f"{text}/24", strict=False)
            except ValueError as exc:
                raise InterfaceError(f"invalid address {text!r}: {exc}") from exc
        if parsed.version != 4:
            raise InterfaceError("only IPv4 subnets are supported")
        network = parsed
        for candidate in found:
            if ipaddress.ip_address(candidate.address) in network:
                iface = candidate
                break

    capacity = host_capacity(network)
    if capacity <= 0:
        raise InterfaceError(f"{network} has no probeable host addresses")
    if capacity > max_hosts:
        raise SubnetTooLarge(
            f"{network} has {capacity} hosts, above the {max_hosts} limit; "
            "use a smaller subnet or raise --max-hosts"
        )
    return network, iface, list_hosts(network)


def list_hosts(network: ipaddress.IPv4Network) -> list[str]:
    if network.prefixlen >= 31:
        return [str(address) for address in network]
    return [str(address) for address in network.hosts()]


def guess_gateway(network: ipaddress.IPv4Network, alive: set[str]) -> str:
    """Guess the router address; the routing table is not readable on Android."""
    first = str(network.network_address + 1)
    if first in alive:
        return first
    if alive:
        try:
            return min(alive, key=lambda ip: tuple(int(p) for p in ip.split(".")))
        except ValueError:
            return sorted(alive)[0]
    return first


def local_addresses(interfaces: list[Interface] | None = None) -> list[str]:
    return [iface.address for iface in interfaces or detect_interfaces()]


def primary_address() -> str | None:
    """Best-effort local IPv4 address, used only for labelling."""
    try:
        return choose_interface().address
    except InterfaceError:
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))
            return probe.getsockname()[0]
        finally:
            probe.close()
    except OSError:
        return None


def default_gateway(network: ipaddress.IPv4Network | None = None) -> str | None:
    """Return the default-route gateway, or ``None`` when it cannot be read.

    Android apps usually cannot read the routing table, so callers must keep a
    fallback (see :func:`guess_gateway`).  When *network* is given, a gateway
    outside it is ignored.
    """
    candidates: list[str] = []
    try:
        with open("/proc/net/route", encoding="utf-8", errors="replace") as handle:
            candidates.extend(_gateways_from_proc_route(handle.read()))
    except OSError:
        pass
    if not candidates:
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            candidates.extend(_gateways_from_ip_route(result.stdout))
        except (OSError, subprocess.SubprocessError):
            pass
    for candidate in candidates:
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if network is None or address in network:
            return candidate
    return None


def _gateways_from_proc_route(text: str) -> list[str]:
    found: list[str] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4 or parts[1] != "00000000":
            continue
        try:
            flags = int(parts[3], 16)
            raw = int(parts[2], 16)
        except ValueError:
            continue
        if not flags & 0x2 or raw == 0:  # RTF_GATEWAY
            continue
        found.append(str(ipaddress.ip_address(struct.pack("<I", raw))))
    return found


def _gateways_from_ip_route(text: str) -> list[str]:
    return re.findall(r"^default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})", text, flags=re.MULTILINE)
