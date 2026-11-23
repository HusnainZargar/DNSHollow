"""Real packet capture: one raw socket sees every interface (including VPNs
that appear later). Needs CAP_NET_RAW (root, or the systemd service)."""
import logging
import socket
import threading

from . import bpf

log = logging.getLogger("dnshollow.capture")
ETH_P_ALL = 3


def open_socket():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    try:
        bpf.attach(s)                      # kernel drops all non-DNS packets
    except OSError as e:
        log.warning("kernel filter not attached (%s): filtering in Python (slower)", e)
    s.settimeout(1.0)
    return s


def reader(sock, agent, stop: threading.Event, include_loopback: bool = False) -> None:
    """Thread body: read packets, hand them to the agent queue."""
    import time
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError as e:
            log.error("capture socket error: %s", e)
            time.sleep(1)
            continue
        if not include_loopback and addr[0] == "lo":
            continue
        agent.feed(time.time(), addr[2], data)
