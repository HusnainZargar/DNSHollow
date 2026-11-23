"""Build raw DNS packets for tests (IP header first, like the agent's capture)."""
import socket
import struct


def dns_msg(qname, qtype=1, txid=0x1234, response=False, rcode=0, answers=0, extra=b""):
    flags = (0x8180 if response else 0x0100) | rcode
    head = struct.pack("!HHHHHH", txid, flags, 1, answers, 0, 0)
    q = b"".join(bytes([len(x)]) + x.encode() for x in qname.split(".")) + b"\0"
    return head + q + struct.pack("!HH", qtype, 1) + extra


def udp4(src, dst, sport, dport, payload, ihl_words=5, frag=0):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    opts = b"\x01" * ((ihl_words - 5) * 4)
    ip = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl_words, 0, ihl_words * 4 + len(udp), 0, frag,
                     64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return ip + opts + udp


def tcp4(src, dst, sport, dport, payload):
    body = struct.pack("!H", len(payload)) + payload
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x18, 65535, 0, 0) + body
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return ip + tcp


def udp6(src, dst, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!IHBB16s16s", 0x60000000, len(udp), 17, 64,
                     socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst))
    return ip + udp


def query_pkt(qname, dst="8.8.8.8", src="192.168.1.5", sport=40000, txid=0x1234, qtype=1):
    return udp4(src, dst, sport, 53, dns_msg(qname, qtype, txid))


def response_pkt(qname, src="8.8.8.8", dst="192.168.1.5", dport=40000, txid=0x1234, rcode=0, qtype=1):
    return udp4(src, dst, 53, dport, dns_msg(qname, qtype, txid, response=True, rcode=rcode, answers=1,
                                              extra=b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04"))
