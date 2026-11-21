"""Work out what a device *is* from everything the collectors learned.

Android hides MAC addresses from ordinary apps, so most devices arrive without
a vendor.  This module therefore leans on every other signal it can get:
hostnames, mDNS service types, UPnP descriptions, web page titles, ``Server``
headers, TLS certificate names, open ports and the ICMP TTL.

Each signal casts a weighted vote for a device kind.  The winner becomes the
kind, and its margin over the runner-up becomes a confidence score.  Every vote
carries a human-readable reason, so the dashboard can say *why* it thinks a
device is a printer instead of just asserting it.

The module is pure: it reads a ``Device`` and never touches the network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .model import Device

KIND_LABELS = {
    "router": "router",
    "printer": "printer",
    "tv": "TV",
    "media": "media device",
    "nas": "NAS",
    "computer": "computer",
    "camera": "camera",
    "iot": "smart device",
    "phone": "phone or tablet",
    "speaker": "smart speaker",
    "console": "game console",
    "self": "this device",
    "device": "device",
}

MIN_CONFIDENCE = 25
MAX_EVIDENCE = 8

# Titles that say nothing about the device.
_GENERIC_TITLES = {
    "",
    "index",
    "index of /",
    "home",
    "login",
    "log in",
    "sign in",
    "welcome",
    "web interface",
    "web management",
    "web server",
    "default web page",
    "it works!",
    "document",
    "untitled",
    "404 not found",
    "403 forbidden",
    "401 unauthorized",
    "error",
    "object moved",
    "redirect",
    "redirecting...",
    "loading...",
    "please wait",
}

Vote = tuple[str, int, str]


@dataclass
class Identity:
    """The result of fingerprinting one device."""

    kind: str = "device"
    confidence: int = 0
    name: str | None = None
    model: str | None = None
    os: str | None = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "confidence": self.confidence,
            "name": self.name,
            "model": self.model,
            "os": self.os,
            "evidence": list(self.evidence),
        }


# ---------------------------------------------------------------------------
# Rule tables.  Each regex row is (pattern, kind, weight, reason).
# ---------------------------------------------------------------------------

def _compile(rows: list[tuple[str, str, int, str]]) -> list[tuple[re.Pattern[str], str, int, str]]:
    return [(re.compile(pattern, re.IGNORECASE), kind, weight, reason) for pattern, kind, weight, reason in rows]


HOSTNAME_RULES = _compile(
    [
        (r"iphone|ipad|ipod", "phone", 55, "hostname looks like an iPhone/iPad"),
        (
            r"android|galaxy|pixel[-_ ]?\d|oneplus|redmi|xiaomi|poco[-_ ]|oppo|realme|\bsm-[a-z]\d",
            "phone",
            50,
            "hostname looks like an Android phone",
        ),
        (r"macbook|imac|mac-?mini|mac-?pro|\bmbp\b|\bmba\b", "computer", 55, "hostname looks like a Mac"),
        (
            r"desktop-|laptop-|^pc-|-pc$|thinkpad|latitude|inspiron|surface|workstation|ubuntu|fedora|debian",
            "computer",
            45,
            "hostname looks like a PC",
        ),
        (
            r"\besp[-_]?\d|^esp[-_]|espressif|tasmota|shelly|sonoff|\bwled\b|tuya|smartlife|homebridge",
            "iot",
            55,
            "hostname looks like a smart-home device",
        ),
        (r"home-?assistant|hassio|openhab|domoticz", "iot", 50, "hostname looks like a home hub"),
        (r"chromecast|google-?cast|android-?tv|google-?tv|\bshield\b", "tv", 55, "hostname looks like a streaming box"),
        (r"google-?home|nest-?(mini|hub|audio)|\becho\b|alexa|sonos|homepod", "speaker", 55, "hostname looks like a smart speaker"),
        (
            r"roku|fire-?tv|apple-?tv|bravia|webos|tizen|\blg-?tv\b|samsung-?tv|(^|[-_.])tv([-_.]|$)",
            "tv",
            50,
            "hostname looks like a TV",
        ),
        (
            r"printer|laserjet|officejet|deskjet|envy-|ecotank|epson|brother|canon|\bmfc-|\bnpi[0-9a-f]{4}|xerox|lexmark",
            "printer",
            55,
            "hostname looks like a printer",
        ),
        (
            r"(^|[-_.])(ip)?cam(era)?([-_.0-9]|$)|hikvision|dahua|reolink|\bnvr\b|\bdvr\b|doorbell|wyze",
            "camera",
            45,
            "hostname looks like a camera",
        ),
        (
            r"synology|diskstation|qnap|truenas|freenas|unraid|openmediavault|\bomv\b|\bnas\b|plex",
            "nas",
            45,
            "hostname looks like a NAS",
        ),
        (
            r"router|gateway|fritz|openwrt|ubnt|mikrotik|tp-?link|archer|\bdeco\b|orbi|nighthawk|^ap-|access-?point",
            "router",
            40,
            "hostname looks like network gear",
        ),
        (r"playstation|\bps[345]\b|xbox|nintendo", "console", 50, "hostname looks like a game console"),
        (r"raspberry", "computer", 35, "hostname looks like a Raspberry Pi"),
    ]
)

# (substring of lower-cased vendor, kind, weight)
VENDOR_RULES: list[tuple[str, str, int]] = [
    ("espressif", "iot", 60),
    ("tuya", "iot", 55),
    ("shelly", "iot", 55),
    ("allterco", "iot", 55),
    ("sonoff", "iot", 55),
    ("itead", "iot", 55),
    ("philips lighting", "iot", 45),
    ("signify", "iot", 45),
    ("hikvision", "camera", 55),
    ("dahua", "camera", 55),
    ("reolink", "camera", 55),
    ("amcrest", "camera", 55),
    ("foscam", "camera", 55),
    ("uniview", "camera", 55),
    ("vivotek", "camera", 55),
    ("hanwha", "camera", 45),
    ("lorex", "camera", 55),
    ("annke", "camera", 55),
    ("ezviz", "camera", 55),
    ("axis comm", "camera", 55),
    ("wyze", "camera", 45),
    ("arlo", "camera", 45),
    ("ubiquiti", "router", 35),
    ("mikrotik", "router", 40),
    ("netgear", "router", 30),
    ("d-link", "router", 30),
    ("tp-link", "router", 30),
    ("tplink", "router", 30),
    ("tenda", "router", 35),
    ("mercusys", "router", 35),
    ("zyxel", "router", 35),
    ("linksys", "router", 35),
    ("keenetic", "router", 40),
    ("draytek", "router", 40),
    ("avm", "router", 30),
    ("eero", "router", 40),
    ("aruba", "router", 35),
    ("ruckus", "router", 35),
    ("sagemcom", "router", 35),
    ("technicolor", "router", 35),
    ("arris", "router", 30),
    ("ubee", "router", 35),
    ("actiontec", "router", 35),
    ("cisco", "router", 18),
    ("huawei", "router", 15),
    ("zte", "router", 15),
    ("belkin", "router", 15),
    ("brother", "printer", 45),
    ("epson", "printer", 45),
    ("canon", "printer", 35),
    ("xerox", "printer", 50),
    ("lexmark", "printer", 50),
    ("kyocera", "printer", 50),
    ("ricoh", "printer", 45),
    ("konica", "printer", 50),
    ("hewlett", "printer", 20),
    ("hp inc", "printer", 20),
    ("synology", "nas", 55),
    ("qnap", "nas", 55),
    ("asustor", "nas", 55),
    ("terramaster", "nas", 55),
    ("buffalo", "nas", 40),
    ("netapp", "nas", 45),
    ("western digital", "nas", 30),
    ("sonos", "speaker", 60),
    ("bose", "speaker", 45),
    ("harman", "speaker", 35),
    ("jbl", "speaker", 35),
    ("denon", "speaker", 40),
    ("marantz", "speaker", 40),
    ("yamaha", "speaker", 35),
    ("vizio", "tv", 45),
    ("tcl", "tv", 40),
    ("hisense", "tv", 45),
    ("roku", "tv", 50),
    ("lg electronics", "tv", 20),
    ("samsung", "tv", 15),
    ("amazon", "tv", 18),
    ("nintendo", "console", 60),
    ("sony interactive", "console", 60),
    ("microsoft", "console", 12),
    ("apple", "phone", 25),
    ("apple", "computer", 20),
    ("samsung", "phone", 22),
    ("xiaomi", "phone", 25),
    ("oneplus", "phone", 40),
    ("oppo", "phone", 35),
    ("vivo", "phone", 30),
    ("realme", "phone", 35),
    ("motorola", "phone", 30),
    ("google", "tv", 12),
    ("google", "speaker", 12),
    ("google", "phone", 12),
    ("raspberry", "computer", 40),
    ("dell", "computer", 40),
    ("lenovo", "computer", 35),
    ("acer", "computer", 30),
    ("micro-star", "computer", 35),
    ("gigabyte", "computer", 30),
    ("asrock", "computer", 35),
    ("intel", "computer", 30),
    ("hon hai", "computer", 25),
    ("foxconn", "computer", 25),
    ("pegatron", "computer", 25),
    ("azurewave", "computer", 25),
    ("liteon", "computer", 25),
    ("realtek", "computer", 18),
    ("vmware", "computer", 45),
    ("parallels", "computer", 45),
    ("murata", "phone", 15),
]

# (substring of an mDNS service type, kind, weight, reason)
MDNS_RULES: list[tuple[str, str, int, str]] = [
    ("_ipp", "printer", 60, "advertises IPP printing"),
    ("_printer", "printer", 60, "advertises a print service"),
    ("_pdl-datastream", "printer", 60, "advertises a print service"),
    ("_scanner", "printer", 45, "advertises a scanner"),
    ("_googlecast", "tv", 45, "advertises Google Cast"),
    ("_androidtvremote", "tv", 60, "advertises Android TV remote"),
    ("_viziocast", "tv", 60, "advertises Vizio Cast"),
    ("_roku", "tv", 60, "advertises Roku control"),
    ("_amzn-wplay", "tv", 40, "advertises Amazon Fire TV"),
    ("_airplay", "media", 35, "advertises AirPlay"),
    ("_raop", "speaker", 35, "advertises AirPlay audio"),
    ("_spotify-connect", "speaker", 45, "advertises Spotify Connect"),
    ("_sonos", "speaker", 60, "advertises Sonos"),
    ("_hap", "iot", 45, "advertises HomeKit"),
    ("_homekit", "iot", 45, "advertises HomeKit"),
    ("_hue", "iot", 55, "advertises Philips Hue"),
    ("_esphomelib", "iot", 60, "advertises ESPHome"),
    ("_arduino", "iot", 55, "advertises Arduino OTA"),
    ("_matter", "iot", 40, "advertises Matter"),
    ("_meshcop", "iot", 40, "advertises a Thread border router"),
    ("_companion-link", "phone", 25, "advertises Apple companion link"),
    ("_companion-link", "computer", 15, "advertises Apple companion link"),
    ("_smb", "nas", 22, "advertises SMB file sharing"),
    ("_afpovertcp", "nas", 30, "advertises AFP file sharing"),
    ("_adisk", "nas", 35, "advertises a network disk"),
    ("_nfs", "nas", 25, "advertises NFS"),
    ("_plex", "nas", 40, "advertises Plex"),
    ("_daap", "media", 30, "advertises iTunes sharing"),
    ("_workstation", "computer", 30, "advertises a workstation"),
    ("_rfb", "computer", 20, "advertises VNC"),
    ("_nvstream", "computer", 40, "advertises NVIDIA GameStream"),
    ("_rtsp", "camera", 50, "advertises RTSP video"),
    ("_onvif", "camera", 55, "advertises ONVIF"),
]

SSDP_RULES = _compile(
    [
        (r"internetgatewaydevice|wanconnectiondevice|wandevice", "router", 70, "UPnP says it is an internet gateway"),
        (r"printer", "printer", 60, "UPnP says it is a printer"),
        (r"zoneplayer|sonos", "speaker", 70, "UPnP says it is a Sonos speaker"),
        (r"philips hue|hue bridge", "iot", 60, "UPnP says it is a Hue bridge"),
        (r"xbox|playstation", "console", 60, "UPnP says it is a game console"),
        (r"bravia|webos|tizen|smart ?tv|\btv\b|television|dial-multiscreen", "tv", 55, "UPnP description mentions a TV"),
        (r"roku", "tv", 55, "UPnP description mentions Roku"),
        (r"mediarenderer", "media", 45, "UPnP media renderer"),
        (r"mediaserver", "media", 30, "UPnP media server"),
        (r"ip ?cam|camera", "camera", 50, "UPnP description mentions a camera"),
        (r"diskstation|readynas|synology|qnap|\bnas\b", "nas", 55, "UPnP description mentions a NAS"),
    ]
)

WEB_RULES = _compile(
    [
        (
            r"openwrt|luci|dd-wrt|routeros|mikrotik|fritz!?box|unifi|edgeos|pfsense|opnsense|"
            r"\brouter\b|gateway|tp-?link|netgear|d-link|ubiquiti|zyxel|keenetic|tenda|archer",
            "router",
            55,
            "web page looks like router admin",
        ),
        (r"wireless n|wi-?fi|modem|\bdsl\b|\bonu\b|\bgpon\b|\blte\b", "router", 35, "web page mentions Wi-Fi/modem"),
        (
            r"printer|laserjet|officejet|deskjet|ecotank|epson|brother|canon|lexmark|xerox|kyocera|ricoh|konica|\bcups\b",
            "printer",
            60,
            "web page looks like a printer",
        ),
        (
            r"ip ?cam|webcam|hikvision|dahua|reolink|amcrest|foscam|\bnvr\b|\bdvr\b|surveillance|network camera|axis communications",
            "camera",
            55,
            "web page looks like a camera",
        ),
        (
            r"synology|diskstation|qnap|\bnas\b|openmediavault|truenas|freenas|unraid|readynas|my cloud|asustor|terramaster",
            "nas",
            60,
            "web page looks like a NAS",
        ),
        (r"plex|jellyfin|emby|kodi|volumio", "media", 50, "web page looks like a media server"),
        (r"home ?assistant|openhab|domoticz|homebridge", "iot", 50, "web page looks like a home hub"),
        (r"tasmota|shelly|esphome|\bwled\b|sonoff|tuya|zigbee|mqtt", "iot", 55, "web page looks like a smart device"),
        (
            r"webos|tizen|bravia|smart ?tv|roku|android tv|google tv|fire tv|samsung.*\btv\b|lg.*\btv\b",
            "tv",
            50,
            "web page looks like a TV",
        ),
        (r"sonos|\becho\b|\bbose\b|\bheos\b|musiccast", "speaker", 55, "web page looks like a speaker"),
        (r"microsoft-iis|microsoft-httpapi", "computer", 40, "Windows web server"),
        (r"esp32|esp8266|arduino|esp-idf", "iot", 55, "embedded ESP web server"),
        (r"uhttpd", "router", 50, "OpenWrt web server"),
        (r"rompager|goahead|mini_httpd|micro_httpd|boa/|thttpd|mbedthttpd|lwip", "router", 20, "embedded web server"),
        (r"rompager|goahead|mini_httpd|micro_httpd|boa/|thttpd|mbedthttpd|lwip", "iot", 20, "embedded web server"),
    ]
)

# port -> list of (kind, weight, reason)
PORT_RULES: dict[int, list[tuple[str, int, str]]] = {
    9100: [("printer", 50, "JetDirect port 9100 open")],
    631: [("printer", 50, "IPP port 631 open")],
    515: [("printer", 40, "LPD port 515 open")],
    554: [("camera", 35, "RTSP port 554 open")],
    8554: [("camera", 30, "RTSP port 8554 open")],
    37777: [("camera", 55, "Dahua camera port 37777 open")],
    34567: [("camera", 55, "DVR port 34567 open")],
    5555: [
        ("phone", 20, "Android debug bridge (5555) open"),
        ("tv", 20, "Android debug bridge (5555) open"),
    ],
    8008: [("tv", 40, "Chromecast port 8008 open")],
    8009: [("tv", 40, "Cast port 8009 open")],
    7000: [("media", 30, "AirPlay port 7000 open")],
    32400: [("nas", 60, "Plex port 32400 open")],
    548: [("nas", 35, "AFP port 548 open")],
    3389: [("computer", 60, "Remote Desktop port 3389 open")],
    5900: [("computer", 30, "VNC port 5900 open")],
    5357: [("computer", 30, "Windows device discovery port 5357 open")],
    1883: [("iot", 40, "MQTT port 1883 open")],
    8883: [("iot", 40, "MQTT-TLS port 8883 open")],
    53: [("router", 25, "DNS server port 53 open")],
    23: [("router", 20, "Telnet open (typical of embedded gear)"), ("iot", 15, "Telnet open")],
    62078: [("phone", 70, "iOS sync port 62078 open")],
}

_TTL_STEPS = (32, 64, 128, 255)


def initial_ttl(observed: int | None) -> int | None:
    """Round an observed TTL up to the sender's likely initial TTL."""
    if observed is None or observed <= 0:
        return None
    for step in _TTL_STEPS:
        if observed <= step:
            return step
    return None


def os_from_ttl(observed: int | None) -> str | None:
    initial = initial_ttl(observed)
    return {
        64: "Linux / Android / Apple",
        128: "Windows",
        255: "Network equipment",
        32: "Embedded / legacy",
    }.get(initial or 0)


# ---------------------------------------------------------------------------
# Collecting votes
# ---------------------------------------------------------------------------


def _text_blob(values: list[str]) -> str:
    return " ".join(value for value in values if value).lower()


def _regex_votes(
    rules: list[tuple[re.Pattern[str], str, int, str]], text: str
) -> list[Vote]:
    if not text:
        return []
    return [(kind, weight, reason) for pattern, kind, weight, reason in rules if pattern.search(text)]


def _web_text(device: Device) -> str:
    parts: list[str] = []
    for info in device.web.values():
        for key in ("title", "server", "realm", "cert_cn", "cert_org", "powered_by"):
            value = info.get(key)
            if value:
                parts.append(value)
    return _text_blob(parts)


def _collect_votes(device: Device) -> list[Vote]:
    votes: list[Vote] = []

    if device.is_gateway:
        votes.append(("router", 80, "is the network's default gateway"))

    hostnames = [device.hostname or "", device.nbns_name or ""]
    votes += _regex_votes(HOSTNAME_RULES, _text_blob(hostnames))

    vendor = (device.vendor or "").lower()
    if vendor:
        for needle, kind, weight in VENDOR_RULES:
            if needle in vendor:
                votes.append((kind, weight, f"vendor is {device.vendor}"))

    services = [service.lower() for service in device.mdns_services]
    for needle, kind, weight, reason in MDNS_RULES:
        if any(needle in service for service in services):
            votes.append((kind, weight, reason))

    ssdp_text = _text_blob(list(device.ssdp.values()))
    votes += _regex_votes(SSDP_RULES, ssdp_text)

    votes += _regex_votes(WEB_RULES, _web_text(device))

    ports = set(device.ports)
    for port, rules in PORT_RULES.items():
        if port in ports:
            votes += [(kind, weight, reason) for kind, weight, reason in rules]
    if 445 in ports and 22 in ports:
        votes.append(("nas", 40, "SMB and SSH both open"))
    elif 139 in ports and 445 in ports:
        votes.append(("computer", 35, "NetBIOS and SMB open (Windows file sharing)"))
    elif 445 in ports:
        votes.append(("computer", 20, "SMB port 445 open"))

    ttl_os = os_from_ttl(device.ttl)
    if ttl_os == "Windows":
        votes.append(("computer", 20, "TTL 128 suggests Windows"))
    elif ttl_os == "Network equipment":
        votes.append(("router", 35, "TTL 255 suggests network equipment"))

    if device.mac and _is_randomized_mac(device.mac) and not device.vendor:
        votes.append(("phone", 25, "randomized (private) MAC, typical of phones"))

    return votes


def _is_randomized_mac(mac: str) -> bool:
    try:
        first = int(mac.replace("-", ":").split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0x02)


# ---------------------------------------------------------------------------
# Naming helpers
# ---------------------------------------------------------------------------


def clean_title(title: str | None) -> str | None:
    """Return a usable device name from a web page title, or ``None``."""
    if not title:
        return None
    text = re.sub(r"\s+", " ", title).strip(" -|:·")
    if text.lower() in _GENERIC_TITLES or len(text) < 3:
        return None
    if re.fullmatch(r"[\d.\-_/ ]+", text):
        return None
    return text[:48]


def _model_of(device: Device) -> str | None:
    for key in ("model", "modelName", "modelNumber"):
        value = device.ssdp.get(key)
        if value:
            return str(value)[:60]
    return None


def _os_of(device: Device, kind: str) -> str | None:
    server = _text_blob([info.get("server", "") for info in device.web.values()])
    banners = _text_blob(list(device.banners.values()))
    hostnames = _text_blob([device.hostname or "", device.nbns_name or ""])
    vendor = (device.vendor or "").lower()
    if re.search(r"iphone|ipad|ipod", hostnames):
        return "iOS"
    if re.search(r"android|galaxy|pixel|redmi|xiaomi", hostnames) or 5555 in device.ports:
        return "Android"
    if "microsoft" in server or "windows" in banners:
        return "Windows"
    for name in ("ubuntu", "debian", "raspbian", "fedora", "centos", "alpine"):
        if name in banners or name in server:
            return f"Linux ({name.capitalize()})"
    if "openssh" in banners and "linux" not in banners:
        return os_from_ttl(device.ttl)
    if "openwrt" in server:
        return "OpenWrt"
    if "apple" in vendor and kind == "computer":
        return "macOS"
    return os_from_ttl(device.ttl)


def _suggest_name(device: Device, kind: str, confidence: int, model: str | None) -> str | None:
    vendor = _short_vendor(device.vendor)
    if vendor and model and vendor.lower() not in model.lower():
        return f"{vendor} {model}"[:60]
    if model:
        return model
    for info in device.web.values():
        title = clean_title(info.get("title"))
        if title:
            return title
    label = KIND_LABELS.get(kind)
    if kind not in ("device", "self") and confidence >= 40 and label:
        if vendor:
            return f"{vendor} {label}"
        return label[:1].upper() + label[1:]
    return None


def _short_vendor(vendor: str | None) -> str | None:
    if not vendor:
        return None
    text = re.sub(
        r"[,.]?\s*\b(inc|llc|ltd|limited|gmbh|co|corp|corporation|company|technologies|technology|electronics)\b\.?",
        "",
        vendor,
        flags=re.IGNORECASE,
    ).strip(" ,.")
    return text or vendor


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def identify(device: Device) -> Identity:
    """Fingerprint *device* using every signal it carries."""
    if device.is_self:
        return Identity(kind="self", confidence=100, model=None, os=os_from_ttl(device.ttl))

    votes = _collect_votes(device)
    totals: dict[str, int] = {}
    reasons: dict[str, list[tuple[int, str]]] = {}
    for kind, weight, reason in votes:
        totals[kind] = totals.get(kind, 0) + weight
        reasons.setdefault(kind, []).append((weight, reason))

    model = _model_of(device)
    if not totals:
        return Identity(
            kind="device",
            confidence=0,
            name=_suggest_name(device, "device", 0, model),
            model=model,
            os=_os_of(device, "device"),
        )

    ranked = sorted(totals.items(), key=lambda item: (-item[1], item[0]))
    kind, top = ranked[0]
    second = ranked[1][1] if len(ranked) > 1 else 0
    confidence = max(0, min(97, round(top - 0.5 * second)))
    if confidence < MIN_CONFIDENCE:
        kind = "device"

    seen: set[str] = set()
    evidence: list[str] = []
    for _weight, reason in sorted(reasons.get(ranked[0][0], []), key=lambda item: -item[0]):
        if reason not in seen:
            seen.add(reason)
            evidence.append(reason)
    if device.ttl:
        ttl_os = os_from_ttl(device.ttl)
        if ttl_os:
            evidence.append(f"TTL {device.ttl} → {ttl_os}")

    return Identity(
        kind=kind,
        confidence=confidence,
        name=_suggest_name(device, kind, confidence, model),
        model=model,
        os=_os_of(device, kind),
        evidence=evidence[:MAX_EVIDENCE],
    )
