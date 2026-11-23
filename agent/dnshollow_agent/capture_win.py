"""Windows packet capture. Standard library only, no driver, no Npcap.

How: a raw IPv4 socket bound to each local address with SIO_RCVALL. Windows then hands
this process every IPv4 packet of that interface, with the IP header first, which is the
same shape the Linux agent works with. Needs Administrator (the service runs as SYSTEM).

Differences from Linux (worth knowing):
  * IPv4 only. Windows raw sockets cannot sniff IPv6.
  * No kernel filter: Python gets every packet and drops non-DNS in a few instructions
    (quick_is_dns). That is fine for a workstation; a busy server may notice the CPU.
  * Windows gives no "outgoing / incoming" flag, so direction comes from the source address:
    a packet from one of this machine's own addresses is outgoing.
  * One socket per local address; the address list is rescanned every 30 s so a VPN or a
    new Wi-Fi network is picked up without a restart.
"""
import logging
import select
import socket
import struct
import threading
import time
from typing import Dict, Iterable, Optional, Set

log = logging.getLogger("dnshollow.capture")

SIO_RCVALL = getattr(socket, "SIO_RCVALL", 0x98000001)
RCVALL_ON, RCVALL_OFF = getattr(socket, "RCVALL_ON", 1), getattr(socket, "RCVALL_OFF", 0)
PACKET_HOST, PACKET_OUTGOING = 0, 4          # same numbers the Linux agent uses
RESCAN_SECONDS = 30


def quick_is_dns(data: bytes) -> bool:
    """Cheap pre-filter: IPv4, UDP/TCP, not a fragment, port 53 on either side."""
    if len(data) < 28 or data[0] >> 4 != 4:
        return False
    ihl = (data[0] & 0x0F) * 4
    if data[9] not in (6, 17) or ihl < 20 or len(data) < ihl + 4:
        return False
    if (data[6] & 0x3F) or data[7]:           # More-Fragments flag or a fragment offset
        return False
    sport, dport = struct.unpack_from("!HH", data, ihl)
    return sport == 53 or dport == 53


def local_ipv4_addresses() -> Set[str]:
    """This machine's usable IPv4 addresses (no loopback, no 169.254 auto-addresses)."""
    found: Set[str] = set()
    host = socket.gethostname()
    try:
        found.update(socket.gethostbyname_ex(host)[2])
    except OSError:
        pass
    try:
        found.update(i[4][0] for i in socket.getaddrinfo(host, None, socket.AF_INET))
    except OSError:
        pass
    try:                                       # the address Windows would use to reach the internet
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 53))           # UDP connect sends nothing
        found.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return {a for a in found if not a.startswith(("127.", "169.254.", "0."))}


def _open_one(ip: str) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    try:
        s.bind((ip, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        s.ioctl(SIO_RCVALL, RCVALL_ON)         # type: ignore[attr-defined]  (Windows only)
    except OSError:
        s.close()
        raise
    return s


class WindowsCapture:
    def __init__(self, sink, stop: threading.Event, include_loopback: bool = False,
                 addresses=local_ipv4_addresses, opener=_open_one):
        self.sink, self.stop = sink, stop
        self.addresses, self.opener = addresses, opener
        self.socks: Dict[str, socket.socket] = {}
        self.last_error = ""

    def rescan(self) -> None:
        want = set(self.addresses())
        for ip in sorted(want - set(self.socks)):
            try:
                self.socks[ip] = self.opener(ip)
                log.info("capturing DNS on %s", ip)
            except OSError as e:
                self.last_error = "%s: %s" % (ip, e)
                log.warning("cannot capture on %s: %s", ip, e)
        for ip in sorted(set(self.socks) - want):
            self._close(ip)
            log.info("stopped capturing on %s (address gone)", ip)

    def _close(self, ip: str) -> None:
        s = self.socks.pop(ip, None)
        if s is not None:
            try:
                s.ioctl(SIO_RCVALL, RCVALL_OFF)    # type: ignore[attr-defined]
            except (OSError, AttributeError):
                pass
            s.close()

    def open(self) -> None:
        """Open the sockets. Raises OSError when none could be opened (usually: not Administrator)."""
        self.rescan()
        if not self.socks:
            raise OSError(self.last_error or "no usable IPv4 address found")

    def close(self) -> None:
        for ip in list(self.socks):
            self._close(ip)

    def run(self) -> None:
        """Thread body."""
        last_scan = time.time()
        while not self.stop.is_set():
            if time.time() - last_scan >= RESCAN_SECONDS:
                last_scan = time.time()
                self.rescan()
            socks = list(self.socks.values())
            if not socks:
                time.sleep(1.0)
                continue
            try:
                ready, _w, _x = select.select(socks, [], [], 1.0)
            except (OSError, ValueError):          # a socket closed under us: rebuild the list
                time.sleep(0.2)
                continue
            if ready:
                mine = set(self.socks)
            for s in ready:
                try:
                    data, _addr = s.recvfrom(65535)
                except OSError as e:
                    log.error("capture socket error: %s", e)
                    time.sleep(0.5)
                    continue
                if not quick_is_dns(data):
                    continue
                src = socket.inet_ntoa(data[12:16])
                self.sink.feed(time.time(), PACKET_OUTGOING if src in mine else PACKET_HOST, data)
        self.close()


class _Probe:
    """Sink that only remembers whether it saw a DNS query for one name, leaving this machine."""

    def __init__(self, name: str):
        from .dnsparse import parse_packet
        self.name, self.parse, self.seen_out, self.seen_any = name, parse_packet, False, False

    def feed(self, _ts, pkttype, data) -> None:
        pkt = self.parse(data)
        if pkt and pkt.qname == self.name:
            self.seen_any = True
            if not pkt.is_response and pkttype == PACKET_OUTGOING:
                self.seen_out = True


def self_test(cap: "WindowsCapture", timeout: float = 5.0) -> bool:
    """Look up a random, non-existent name and check that the capture sees the query go out."""
    import os
    name = "dnshollow-%s.invalid" % os.urandom(5).hex()
    probe = _Probe(name)
    cap.sink, stop = probe, threading.Event()
    real_stop, cap.stop = cap.stop, stop
    t = threading.Thread(target=cap.run, daemon=True)
    t.start()
    try:
        threading.Thread(target=lambda: _lookup(name), daemon=True).start()
        end = time.time() + timeout
        while time.time() < end and not probe.seen_out:
            time.sleep(0.1)
    finally:
        stop.set()
        t.join(3)
        cap.stop = real_stop
    return probe.seen_out


def _lookup(name: str) -> None:
    try:
        socket.getaddrinfo(name, None)
    except OSError:
        pass
