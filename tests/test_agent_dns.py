import random
import struct

from agent.dnshollow_agent.dnsparse import is_loopback, parse_dns, parse_packet
from agent.dnshollow_agent.pairing import Pairer
from tests.helpers import dns_msg, query_pkt, response_pkt, tcp4, udp4, udp6


def test_parse_udp_query():
    p = parse_packet(query_pkt("WWW.Example.COM", dst="1.1.1.1", qtype=16))
    assert (p.is_response, p.qname, p.qtype, p.proto) == (False, "www.example.com", "TXT", "udp")
    assert (p.src, p.dst, p.sport, p.dport, p.txid) == ("192.168.1.5", "1.1.1.1", 40000, 53, 0x1234)
    assert p.dns_len == len(dns_msg("www.example.com", 16))


def test_parse_response_with_rcode_and_size():
    p = parse_packet(response_pkt("nope.example.com", rcode=3))
    assert p.is_response and p.rcode == 3 and p.ancount == 1 and p.dns_len > 30


def test_parse_ipv6_and_tcp():
    p6 = parse_packet(udp6("fe80::1", "2001:db8::53", 40000, 53, dns_msg("a.b.com")))
    assert p6.dst == "2001:db8::53" and p6.qname == "a.b.com"
    pt = parse_packet(tcp4("10.0.0.1", "8.8.8.8", 40000, 53, dns_msg("a.b.com", 10)))
    assert pt.proto == "tcp" and pt.qtype == "NULL"


def test_unknown_qtype_name():
    assert parse_packet(query_pkt("a.com", qtype=999)).qtype == "TYPE999"


def test_non_dns_and_bad_packets_return_none():
    assert parse_packet(udp4("1.1.1.1", "2.2.2.2", 40000, 443, dns_msg("a.com"))) is None
    assert parse_packet(udp4("1.1.1.1", "2.2.2.2", 40000, 53, b"short")) is None
    assert parse_packet(udp4("1.1.1.1", "2.2.2.2", 40000, 53, dns_msg("a.com"), frag=0x00B9)) is None
    assert parse_packet(b"") is None


def test_compression_pointer_and_loop_are_safe():
    # header + pointer pointing at itself (loop) must not hang or raise
    loop = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    assert parse_dns(loop) is None
    # name with a valid forward pointer to a later label
    name = b"\x03abc\xc0\x16"                                  # abc + pointer to offset 22 (the "com" label)
    msg = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + name + b"\x00\x01\x00\x01" + b"\x03com\x00"
    assert parse_dns(msg)[4] == "abc.com"


def test_weird_bytes_in_names_are_cleaned():
    msg = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x04a\x00b\xff\x00\x00\x01\x00\x01"
    assert parse_dns(msg)[4] == "a?b?"


def test_parser_never_raises_on_garbage():
    rng = random.Random(1)
    good = query_pkt("some.long.name.example.com")
    for _ in range(3000):
        n = rng.randrange(0, 120)
        parse_packet(bytes(rng.randrange(256) for _ in range(n)))
        cut = good[:rng.randrange(len(good))]
        parse_packet(cut)
        b = bytearray(good); b[rng.randrange(len(b))] = rng.randrange(256)
        parse_packet(bytes(b))


def test_is_loopback():
    assert is_loopback("127.0.0.53") and is_loopback("::1")
    assert not is_loopback("8.8.8.8") and not is_loopback("192.168.1.1")


# ---------- pairing ----------
def pk(raw):
    return parse_packet(raw)


def test_pairs_query_and_response():
    pr = Pairer()
    assert pr.add_query(100.0, pk(query_pkt("a.example.com"))) == []
    out = pr.add_response(100.05, pk(response_pkt("a.example.com", rcode=3)))
    assert len(out) == 1
    r = out[0]
    assert (r["qname"], r["resolver"], r["proto"], r["rcode"]) == ("a.example.com", "8.8.8.8", "udp", 3)
    assert r["qbytes"] > 0 and r["rbytes"] > r["qbytes"] and r["ts"] == 100.0
    assert pr.pending == {}


def test_unanswered_query_expires_without_response():
    pr = Pairer(timeout=5)
    pr.add_query(100.0, pk(query_pkt("a.example.com")))
    assert pr.flush_expired(103.0) == []
    out = pr.flush_expired(106.0)
    assert out[0]["rcode"] is None and out[0]["rbytes"] is None


def test_response_without_query_is_ignored():
    assert Pairer().add_response(1.0, pk(response_pkt("a.com"))) == []


def test_different_transactions_do_not_mix():
    pr = Pairer()
    pr.add_query(1.0, pk(query_pkt("a.com", txid=1, sport=40001)))
    pr.add_query(1.0, pk(query_pkt("b.com", txid=2, sport=40002)))
    out = pr.add_response(1.1, pk(response_pkt("b.com", txid=2, dport=40002)))
    assert [r["qname"] for r in out] == ["b.com"] and len(pr.pending) == 1


def test_retransmit_closes_old_as_unanswered():
    pr = Pairer()
    pr.add_query(1.0, pk(query_pkt("a.com")))
    out = pr.add_query(2.0, pk(query_pkt("a.com")))
    assert len(out) == 1 and out[0]["rcode"] is None and len(pr.pending) == 1


def test_flood_is_bounded():
    pr = Pairer(max_pending=100)
    for i in range(500):
        pr.add_query(float(i), pk(query_pkt("a%d.com" % i, sport=1000 + i, txid=i)))
    assert len(pr.pending) <= 100
