"""MAC address normalisation and vendor lookup.

The embedded table is a small, curated fallback.  When a full IEEE OUI list is
installed (nmap ships one, as does ``ieee-data``), it is parsed lazily and
cached, which gives accurate vendor names for almost every address.
"""

from __future__ import annotations

import re
from pathlib import Path

# Curated subset of the IEEE registry: the vendors that show up on home LANs.
_EMBEDDED_OUI = {
    "000393": "Apple",
    "000A27": "Apple",
    "000A95": "Apple",
    "0017F2": "Apple",
    "001B63": "Apple",
    "001EC2": "Apple",
    "0023DF": "Apple",
    "002500": "Apple",
    "0026BB": "Apple",
    "3C0754": "Apple",
    "3C22FB": "Apple",
    "A483E7": "Apple",
    "F01898": "Apple",
    "8C8590": "Apple",
    "DCA904": "Apple",
    "F45C89": "Apple",
    "0012FB": "Samsung",
    "001599": "Samsung",
    "001632": "Samsung",
    "342387": "Samsung",
    "5C0A5B": "Samsung",
    "8C7712": "Samsung",
    "781FDB": "Samsung",
    "E8508B": "Samsung",
    "C819F7": "Samsung",
    "240AC4": "Espressif",
    "246F28": "Espressif",
    "30AEA4": "Espressif",
    "84F3EB": "Espressif",
    "A4CF12": "Espressif",
    "CC50E3": "Espressif",
    "DC4F22": "Espressif",
    "ECFABC": "Espressif",
    "7C9EBD": "Espressif",
    "B827EB": "Raspberry Pi",
    "DCA632": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    "28CDC1": "Raspberry Pi",
    "2CCF67": "Raspberry Pi",
    "50C7BF": "TP-Link",
    "A42BB0": "TP-Link",
    "C025E9": "TP-Link",
    "B0BE76": "TP-Link",
    "EC086B": "TP-Link",
    "1C3BF3": "TP-Link",
    "9CA2F4": "TP-Link",
    "3C5AB4": "Google",
    "F4F5D8": "Google",
    "A47733": "Google",
    "94EB2C": "Google",
    "1CF29A": "Google",
    "546009": "Google",
    "44650D": "Amazon",
    "74C246": "Amazon",
    "F0272D": "Amazon",
    "6854FD": "Amazon",
    "84D6D0": "Amazon",
    "FC65DE": "Amazon",
    "50DCE7": "Amazon",
    "00E0FC": "Huawei",
    "4846FB": "Huawei",
    "70723C": "Huawei",
    "9C28EF": "Huawei",
    "E0247F": "Huawei",
    "64B473": "Xiaomi",
    "7811DC": "Xiaomi",
    "286C07": "Xiaomi",
    "508F4C": "Xiaomi",
    "F0B429": "Xiaomi",
    "742344": "Xiaomi",
    "8C53C3": "Xiaomi",
    "34CE00": "Xiaomi",
    "000E58": "Sonos",
    "5CAAFD": "Sonos",
    "7828CA": "Sonos",
    "B8E937": "Sonos",
    "949F3E": "Sonos",
    "001788": "Philips Hue",
    "ECB5FA": "Philips Hue",
    "B0A737": "Roku",
    "D83134": "Roku",
    "CC6DA0": "Roku",
    "24A43C": "Ubiquiti",
    "74ACB9": "Ubiquiti",
    "FCECDA": "Ubiquiti",
    "44D9E7": "Ubiquiti",
    "788A20": "Ubiquiti",
    "00146C": "Netgear",
    "204E7F": "Netgear",
    "A040A0": "Netgear",
    "4494FC": "Netgear",
    "001B21": "Intel",
    "3C970E": "Intel",
    "8C1645": "Intel",
    "A0369F": "Intel",
    "3413E8": "Intel",
    "00E04C": "Realtek",
    "001422": "Dell",
    "B82A72": "Dell",
    "F8BC12": "Dell",
    "001F29": "HP",
    "3CD92B": "HP",
    "9CB654": "HP",
    "008077": "Brother",
    "001132": "Synology",
    "9009D0": "Synology",
    "00089B": "QNAP",
    "245EBE": "QNAP",
    "0009BF": "Nintendo",
    "98B6E9": "Nintendo",
    "7CBB8A": "Nintendo",
    "0013A9": "Sony",
    "F8D0AC": "Sony",
    "30F9ED": "Sony",
    "001E75": "LG",
    "A823FE": "LG",
    "C808E9": "LG",
    "18B430": "Nest",
    "2CAA8E": "Wyze",
    "001AA1": "Cisco",
    "000C29": "VMware",
    "005056": "VMware",
    "080027": "VirtualBox",
    "002590": "Super Micro",
    "3C5282": "Xiaomi",
}

_OUI_FILES = (
    "/data/data/com.termux/files/usr/share/nmap/nmap-mac-prefixes",
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/usr/share/ieee-data/oui.txt",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/hwdata/oui.txt",
    "/usr/share/misc/oui.txt",
)

_DB: dict[str, str] = {}
_DB_LOADED = False


def normalize_mac(value: str | None) -> str | None:
    """Return ``aa:bb:cc:dd:ee:ff`` for any common MAC notation."""
    if not value:
        return None
    digits = re.sub(r"[^0-9A-Fa-f]", "", str(value))
    if len(digits) == 12:
        pass
    elif len(digits) == 16 and str(value).count(".") == 2:
        # Cisco style: aabb.ccdd.eeff
        digits = digits[:12]
    else:
        return None
    grouped = [digits[i : i + 2].lower() for i in range(0, 12, 2)]
    mac = ":".join(grouped)
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    return mac


def is_locally_administered(mac: str) -> bool:
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0x02)


def _load_database() -> dict[str, str]:
    global _DB, _DB_LOADED
    if _DB_LOADED:
        return _DB
    _DB_LOADED = True
    database = dict(_EMBEDDED_OUI)
    for raw_path in _OUI_FILES:
        path = Path(raw_path)
        try:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        parsed = _parse_oui_text(text)
        if parsed:
            parsed.update({k: v for k, v in database.items() if k not in parsed})
            database = parsed
            break
    _DB = database
    return database


def _parse_oui_text(text: str) -> dict[str, str]:
    """Parse nmap-mac-prefixes or IEEE ``oui.txt`` formats."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "-" in line and "(hex)" in line:
            # ieee-data: "00-00-0C   (hex)        Cisco Systems, Inc"
            prefix, _, rest = line.partition("(hex)")
            key = re.sub(r"[^0-9A-Fa-f]", "", prefix).upper()
            name = rest.strip()
        else:
            # nmap: "00000C  Cisco Systems, Inc"
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, name = parts[0].upper(), parts[1].strip()
        if len(key) == 6 and re.fullmatch(r"[0-9A-F]{6}", key) and name:
            found.setdefault(key, name[:64])
    return found


def vendor_for(mac: str | None) -> str | None:
    """Look up the vendor for a MAC address, or None when unknown."""
    normalized = normalize_mac(mac)
    if not normalized:
        return None
    if is_locally_administered(normalized):
        return "Locally administered"
    prefix = normalized.replace(":", "").upper()[:6]
    return _load_database().get(prefix)


def database_size() -> int:
    return len(_load_database())
