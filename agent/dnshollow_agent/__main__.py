"""python3 -m dnshollow_agent [--config FILE] [--check] [--unblock-all] [--print]"""
import argparse
import logging
import logging.handlers
import platform
import signal
import sys
import threading

from . import __version__, blocker, capture, config
from .agent import Agent
from .client import Client

WINDOWS = sys.platform == "win32"


def _setup_logging(path: str) -> None:
    fmt = "%(asctime)s %(levelname)s %(message)s"
    if path:
        h = logging.handlers.RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        logging.basicConfig(level=logging.INFO, format=fmt, handlers=[h])
    else:
        logging.basicConfig(level=logging.INFO, format=fmt)


def _open_capture(cfg, agent_or_sink, stop):
    """-> (closer, thread target). Linux: one raw AF_PACKET socket. Windows: one raw socket per IPv4 address."""
    if WINDOWS:
        from .capture_win import WindowsCapture
        cap = WindowsCapture(agent_or_sink, stop, cfg.include_loopback)
        cap.open()
        return cap.close, cap.run
    sock = capture.open_socket()
    return sock.close, lambda: capture.reader(sock, agent_or_sink, stop, cfg.include_loopback)


def _check(cfg) -> int:
    ok = True
    try:
        if WINDOWS:
            from .capture_win import WindowsCapture, self_test
            cap = WindowsCapture(None, threading.Event())
            cap.open()
            ips = ", ".join(sorted(cap.socks))
            seen = self_test(cap)
            cap.close()
            print("capture : OK (raw sockets on %s)" % ips)
            if seen:
                print("lookup  : OK (a test DNS query was seen leaving this machine)")
            else:
                ok = False
                print("lookup  : FAILED (no test query seen. DNS over IPv6 / DoH, or a security product, may hide it)")
        else:
            capture.open_socket().close()
            print("capture : OK (raw socket allowed)")
    except OSError as e:
        ok = False
        print("capture : FAILED (%s) - %s" % (e, "run as Administrator" if WINDOWS else "run as root or give CAP_NET_RAW"))
    if cfg.allow_blocking:
        b = blocker.make_blocker()
        good, why = b.available() if b else (False, "not supported on this system")
        print("blocking: %s" % ("OK (%s)" % b.method if good else "NOT AVAILABLE - %s" % why))
    else:
        print("blocking: off (the agent was installed without blocking)")
    status, _ = Client(cfg.server, cfg.api_key, cfg.verify_tls).heartbeat((platform.system() + " " + platform.release())[:64])
    print("manager : %s (HTTP %s) %s" % ("OK" if status == 200 else "FAILED", status, cfg.server))
    return 0 if ok and status == 200 else 1


def main() -> int:
    ap = argparse.ArgumentParser(prog="dnshollow_agent")
    ap.add_argument("--config", default="")
    ap.add_argument("--check", action="store_true", help="test capture permission and manager connection, then exit")
    ap.add_argument("--unblock-all", action="store_true", help="remove every firewall/DNS rule this agent created, then exit")
    ap.add_argument("--version", action="store_true")
    ap.add_argument("--include-loopback", action="store_true", help="also capture 127.0.0.1 (debug only)")
    a = ap.parse_args()
    if a.version:
        print(__version__)
        return 0

    if a.unblock_all:                                  # used by the uninstaller; needs no config
        b = blocker.make_blocker()
        if b is None:
            print("nothing to remove on this system")
            return 0
        b.clear()
        print("DNSHollow blocking rules removed")
        return 0

    try:
        cfg = config.load(a.config)
    except (OSError, ValueError) as e:
        print("Cannot read config: %s" % e, file=sys.stderr)
        return 2
    cfg.include_loopback = cfg.include_loopback or a.include_loopback
    _setup_logging("" if a.check else cfg.log_file)

    if a.check:
        return _check(cfg)

    agent = Agent(cfg)
    try:
        close, target = _open_capture(cfg, agent, agent.stop)
    except OSError as e:
        print("Cannot start packet capture: %s\nThe agent needs %s." % (
            e, "Administrator rights" if WINDOWS else "root or CAP_NET_RAW"), file=sys.stderr)
        return 3

    for name in ("SIGTERM", "SIGINT", "SIGBREAK"):    # SIGBREAK exists on Windows only
        sig = getattr(signal, name, None)
        if sig is not None:
            signal.signal(sig, lambda *_: agent.stop.set())
    t = threading.Thread(target=target, daemon=True)
    t.start()
    agent.run()
    t.join(3)
    close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
