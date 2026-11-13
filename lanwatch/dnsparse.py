"""A tiny DNS encoder/decoder, sufficient for mDNS-SD queries.

Only the record types that show up in service discovery are decoded into
Python values; everything else is preserved as raw bytes.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_NSEC = 47
TYPE_ANY = 255

TYPE_NAMES = {
    TYPE_A: "A",
    TYPE_PTR: "PTR",
    TYPE_TXT: "TXT",
    TYPE_AAAA: "AAAA",
    TYPE_SRV: "SRV",
    TYPE_NSEC: "NSEC",
    TYPE_ANY: "ANY",
}

MAX_RECORDS = 512
MAX_NAME_DEPTH = 32


class DnsError(ValueError):
    """Malformed DNS message."""


@dataclass
class Record:
    name: str
    rtype: int
    rclass: int
    ttl: int
    data: object

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.rtype, str(self.rtype))

    @property
    def text(self) -> str:
        if isinstance(self.data, str):
            return self.data
        if isinstance(self.data, dict):
            return str(self.data.get("target") or self.data.get("text") or "")
        if isinstance(self.data, list):
            return " ".join(str(item) for item in self.data)
        return ""


@dataclass
class Message:
    id: int
    flags: int
    questions: list[tuple[str, int, int]] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authority: list[Record] = field(default_factory=list)
    additional: list[Record] = field(default_factory=list)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)

    def records(self) -> list[Record]:
        return [*self.answers, *self.authority, *self.additional]


def encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.strip(".").split("."):
        if not label:
            continue
        encoded = label.encode("utf-8")
        if len(encoded) > 63:
            raise DnsError(f"label too long: {label!r}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def encode_query(
    name: str, qtype: int = TYPE_PTR, qclass: int = 1, unicast: bool = False, txid: int = 0
) -> bytes:
    """Build a single-question query.  ``unicast`` sets mDNS's QU bit."""
    if unicast:
        qclass |= 0x8000
    header = struct.pack(">HHHHHH", txid & 0xFFFF, 0, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack(">HH", qtype, qclass)


def _read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > MAX_NAME_DEPTH:
        raise DnsError("name compression loop")
    labels: list[str] = []
    end = offset
    jumped = False
    while True:
        if offset >= len(data):
            raise DnsError("truncated name")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DnsError("truncated pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            jumped = True
            if pointer >= len(data):
                raise DnsError("pointer out of range")
            suffix, _ = _read_name(data, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            break
        if length & 0xC0:
            raise DnsError("bad label length")
        offset += 1
        if offset + length > len(data):
            raise DnsError("truncated label")
        labels.append(data[offset : offset + length].decode("utf-8", "replace"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(label for label in labels if label), end


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Public wrapper around the internal name decompressor."""
    return _read_name(data, offset)


def _decode_rdata(data: bytes, rtype: int, start: int, length: int) -> object:
    end = start + length
    if end > len(data):
        raise DnsError("rdata runs past packet")
    chunk = data[start:end]
    if rtype == TYPE_A and length == 4:
        return socket.inet_ntoa(chunk)
    if rtype == TYPE_AAAA and length == 16:
        return socket.inet_ntop(socket.AF_INET6, chunk)
    if rtype in (TYPE_PTR,):
        value, _ = _read_name(data, start)
        return value
    if rtype == TYPE_SRV and length >= 7:
        priority, weight, port = struct.unpack(">HHH", data[start : start + 6])
        target, _ = _read_name(data, start + 6)
        return {"priority": priority, "weight": weight, "port": port, "target": target}
    if rtype == TYPE_TXT:
        strings: list[str] = []
        pos = start
        while pos < end:
            size = data[pos]
            pos += 1
            if pos + size > end:
                break
            strings.append(data[pos : pos + size].decode("utf-8", "replace"))
            pos += size
        return strings
    if rtype == TYPE_NSEC:
        try:
            next_name, _ = _read_name(data, start)
            return {"next": next_name}
        except DnsError:
            return chunk
    return chunk


def parse_message(data: bytes) -> Message:
    if len(data) < 12:
        raise DnsError("packet shorter than DNS header")
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    total = qdcount + ancount + nscount + arcount
    if total > MAX_RECORDS:
        raise DnsError("too many records")
    offset = 12
    message = Message(id=txid, flags=flags)
    for _ in range(qdcount):
        name, offset = _read_name(data, offset)
        if offset + 4 > len(data):
            raise DnsError("truncated question")
        qtype, qclass = struct.unpack(">HH", data[offset : offset + 4])
        offset += 4
        message.questions.append((name, qtype, qclass & 0x7FFF))

    def read_records(count: int) -> list[Record]:
        nonlocal offset
        records: list[Record] = []
        for _ in range(count):
            name, offset = _read_name(data, offset)
            if offset + 10 > len(data):
                raise DnsError("truncated record header")
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
            offset += 10
            if offset + rdlength > len(data):
                raise DnsError("truncated rdata")
            value = _decode_rdata(data, rtype, offset, rdlength)
            offset += rdlength
            records.append(Record(name, rtype, rclass & 0x7FFF, ttl, value))
        return records

    message.answers = read_records(ancount)
    message.authority = read_records(nscount)
    message.additional = read_records(arcount)
    return message


def txt_dict(record: Record) -> dict[str, str]:
    """Turn a decoded TXT record into a key/value dict."""
    result: dict[str, str] = {}
    if not isinstance(record.data, list):
        return result
    for entry in record.data:
        key, sep, value = entry.partition("=")
        if key:
            result[key] = value if sep else ""
    return result


def service_type(name: str) -> str | None:
    """Extract ``_http._tcp``-style service type from any DNS-SD name."""
    labels = [label for label in name.rstrip(".").split(".") if label]
    for index, label in enumerate(labels):
        if label.startswith("_"):
            if index + 1 < len(labels) and labels[index + 1].startswith("_"):
                return f"{label}.{labels[index + 1]}"
            return label
    return None


def instance_name(name: str) -> str:
    """Strip the service type from an instance name: ``TV._airplay._tcp.local``."""
    service = service_type(name)
    if not service:
        return name.rstrip(".")
    suffix = f".{service}.local"
    text = name.rstrip(".")
    if text.lower().endswith(suffix.lower()):
        return text[: -len(suffix)]
    service_index = text.find(f".{service}.")
    return text[:service_index] if service_index > 0 else text
