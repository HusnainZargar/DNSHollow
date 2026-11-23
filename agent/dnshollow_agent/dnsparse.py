"""Minimal, safe DNS packet parser (IPv4/IPv6, UDP/TCP). Standard library only.

Input starts at the IP header. Every read is bounds-checked: this code parses
hostile network data, so a bad packet must return None, never raise.
"""
import socket
import struct
from typing import NamedTuple, Optional

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX",
          16: "TXT", 28: "AAAA", 33: "SRV", 43: "DS", 46: "RRSIG", 47: "NSEC",
          48: "DNSKEY", 65: "HTTPS", 255: "ANY"}
_CLEAN = {i: ord("?") for i in range(256) if i < 0x21 or i > 0x7E}


class DnsPacket(NamedTuple):
    is_response: bool
    txid: int
    qname: str
    qtype: str
    rcode: int
    ancount: int
    proto: str          # "udp" | "tcp"
    src: str
    dst: str
    sport: int
    dport: int
    dns_len: int        # bytes of the DNS message itself


def _clean_label(raw: bytes) -> str:
    return raw.decode("latin-1").translate(_CLEAN).lower()


def _name(p: bytes, off: int):
    labels, jumps, end, total = [], 0, None, 0
    while True:
        if off >= len(p):
            return None, 0
        length = p[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:                      # compression pointer
            if off + 1 >= len(p):
                return None, 0
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | p[off + 1]
            jumps += 1
            if jumps > 10:
                return None, 0
            continue
        if length & 0xC0:
            return None, 0
        off += 1
        if off + length > len(p):
            return None, 0
        labels.append(_clean_label(p[off:off + length]))
        total += length + 1
        if total > 255:
            return None, 0
        off += length
    return ".".join(labels), (end if end is not None else off)


def parse_dns(p: bytes):
    """-> (txid, is_response, rcode, ancount, qname, qtype) or None."""
    if len(p) < 12:
        return None
    txid, flags, qd, an, _ns, _ar = struct.unpack_from("!HHHHHH", p)
    if qd < 1 or (flags >> 11) & 0xF != 0:             # standard queries only
        return None
    name, off = _name(p, 12)
    if not name or off + 4 > len(p):
        return None
    qtype = struct.unpack_from("!H", p, off)[0]
    return txid, bool(flags & 0x8000), flags & 0xF, an, name, QTYPES.get(qtype, "TYPE%d" % qtype)


def _ip(data: bytes):
    """-> (proto, src, dst, payload_start, payload_end) or None."""
    if len(data) < 20:
        return None
    ver = data[0] >> 4
    if ver == 4:
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl or struct.unpack_from("!H", data, 6)[0] & 0x1FFF:
            return None
        total = struct.unpack_from("!H", data, 2)[0]
        end = min(total, len(data)) if total >= ihl else len(data)
        return (data[9], socket.inet_ntop(socket.AF_INET, data[12:16]),
                socket.inet_ntop(socket.AF_INET, data[16:20]), ihl, end)
    if ver == 6 and len(data) >= 40:
        plen = struct.unpack_from("!H", data, 4)[0]
        end = min(40 + plen, len(data)) if plen else len(data)
        return (data[6], socket.inet_ntop(socket.AF_INET6, data[8:24]),
                socket.inet_ntop(socket.AF_INET6, data[24:40]), 40, end)
    return None


def parse_packet(data: bytes) -> Optional[DnsPacket]:
    try:
        ip = _ip(data)
        if ip is None:
            return None
        proto, src, dst, off, end = ip
        if proto == 17:
            if end < off + 8:
                return None
            sport, dport, ulen = struct.unpack_from("!HHH", data, off)
            payload = data[off + 8:min(end, off + ulen)]
            name = "udp"
        elif proto == 6:
            if end < off + 20:
                return None
            sport, dport = struct.unpack_from("!HH", data, off)
            payload = data[off + (data[off + 12] >> 4) * 4:end]
            if len(payload) < 2:
                return None
            mlen = struct.unpack_from("!H", payload)[0]
            if mlen > len(payload) - 2:                # message split over segments: skipped
                return None
            payload = payload[2:2 + mlen]
            name = "tcp"
        else:
            return None
        if sport != 53 and dport != 53:
            return None
        d = parse_dns(payload)
        if d is None:
            return None
        txid, is_resp, rcode, an, qname, qtype = d
        return DnsPacket(is_resp, txid, qname, qtype, rcode, an, name,
                         src, dst, sport, dport, len(payload))
    except (struct.error, ValueError, IndexError):
        return None


def is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip == "::1" or ip.startswith("::ffff:127.")
