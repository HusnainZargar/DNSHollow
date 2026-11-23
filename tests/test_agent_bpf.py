"""Run the agent's kernel filter in a small BPF interpreter against crafted packets."""
import struct

import pytest

from agent.dnshollow_agent import bpf
from tests.helpers import dns_msg, tcp4, udp4, udp6


def run(prog, pkt):
    a = x = pc = 0
    while True:
        code, jt, jf, k = prog[pc]
        pc += 1
        if code == bpf.LDB_ABS:
            if k + 1 > len(pkt): return 0
            a = pkt[k]
        elif code == bpf.LDH_ABS:
            if k + 2 > len(pkt): return 0
            a = struct.unpack_from("!H", pkt, k)[0]
        elif code == bpf.LDH_IND:
            if x + k + 2 > len(pkt): return 0
            a = struct.unpack_from("!H", pkt, x + k)[0]
        elif code == bpf.LDXB_MSH:
            if k + 1 > len(pkt): return 0
            x = (pkt[k] & 0xF) * 4
        elif code == bpf.AND_K:
            a &= k
        elif code == bpf.JEQ_K:
            pc += jt if a == k else jf
        elif code == bpf.JSET_K:
            pc += jt if a & k else jf
        elif code == bpf.RET_K:
            return k
        else:
            raise AssertionError("unknown opcode %#x" % code)


PROG = bpf.assemble()
Q = dns_msg("a.example.com")


@pytest.mark.parametrize("pkt", [
    udp4("10.0.0.1", "8.8.8.8", 40000, 53, Q),                 # query
    udp4("8.8.8.8", "10.0.0.1", 53, 40000, Q),                 # response
    udp4("10.0.0.1", "8.8.8.8", 40000, 53, Q, ihl_words=7),    # IPv4 with options
    tcp4("10.0.0.1", "8.8.8.8", 40000, 53, Q),                 # DNS over TCP
    udp6("fe80::1", "2001:4860:4860::8888", 40000, 53, Q),     # IPv6
    udp6("2001:4860:4860::8888", "fe80::1", 53, 40000, Q),
])
def test_dns_is_accepted(pkt):
    assert run(PROG, pkt) == bpf.ACCEPT_BYTES


@pytest.mark.parametrize("pkt", [
    udp4("10.0.0.1", "8.8.8.8", 40000, 443, Q),                # not port 53
    udp4("10.0.0.1", "8.8.8.8", 40000, 5353, Q),
    tcp4("10.0.0.1", "8.8.8.8", 40000, 80, Q),
    udp4("10.0.0.1", "8.8.8.8", 40000, 53, Q, frag=0x00B9),    # later fragment
    udp6("fe80::1", "fe80::2", 40000, 443, Q),
    bytes([0x45]) + bytes(5),                                   # truncated
    b"",                                                        # empty
    b"\x00" * 60,                                               # not IP (version 0)
    bytes([0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1]) + bytes(40),     # ICMP
])
def test_other_traffic_is_dropped(pkt):
    assert run(PROG, pkt) == 0


def test_program_is_small_and_valid():
    assert len(PROG) < 64
    assert all(0 <= jt <= 255 and 0 <= jf <= 255 for _c, jt, jf, _k in PROG)
    assert PROG[-1][0] == bpf.RET_K and PROG[-2][0] == bpf.RET_K
