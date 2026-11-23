"""Agent core: packets in -> records -> batches -> manager (24/7, never loses data quietly).

Flow:  capture thread -> queue -> parse -> pair query/response -> filter
       -> buffer -> batch every N seconds -> POST /agent/ingest
       manager down?  batch goes to the disk spool and is retried later.
"""
import logging
import platform
import queue
import threading
import time
import uuid
from collections import Counter
from urllib.parse import urlparse

from . import __version__, blocker as blockmod
from .client import Client
from .config import AgentConfig
from .dnsparse import is_loopback, parse_packet
from .pairing import Pairer
from .spool import Spool

log = logging.getLogger("dnshollow.agent")
PACKET_OUTGOING = 4          # AF_PACKET pkttype for packets this host sent


class Agent:
    def __init__(self, cfg: AgentConfig, client=None, spool=None, blocker=None):
        self.cfg = cfg
        self.client = client or Client(cfg.server, cfg.api_key, cfg.verify_tls)
        self.spool = spool or Spool(cfg.spool_dir, cfg.spool_max_mb * 1024 * 1024)
        self.pairer = Pairer()
        self.q = queue.Queue(maxsize=100000)
        self.stop = threading.Event()
        self.stats = Counter()
        self.buffer = []
        # settings that the manager can change (refreshed by heartbeat)
        self.trusted = []
        self.interval = 10.0
        self.max_batch = 2000
        self.skip_host = (urlparse(cfg.server).hostname or "").lower()
        # blocking (only when the installer enabled it)
        self.blocker = blocker if blocker is not None else (blockmod.make_blocker() if cfg.allow_blocking else None)
        self.blocks_rev = -1
        self.block_applied = []          # domains currently blocked on this machine
        self.block_error = ""
        self.report_soon = False         # tell the manager the new state right after a change
        self.block_synced = False        # first heartbeat always syncs (clears rules left by an older run)
        self.block_ok, self.block_why = (self.blocker.available() if self.blocker else (False, ""))
        # timers / retry state
        self.os_name = ("%s %s" % (platform.system(), platform.release()))[:64]
        self.last_send = self.last_hb = self.last_log = self.last_catchup = 0.0
        self.next_ok = 0.0
        self.fails = 0

    # ---------- input ----------
    def feed(self, ts, pkttype, data) -> None:
        try:
            self.q.put_nowait((ts, pkttype, data))
        except queue.Full:
            self.stats["queue_dropped"] += 1

    def handle(self, ts, pkttype, data) -> None:
        pkt = parse_packet(data)
        if pkt is None:
            return
        self.stats["dns_packets"] += 1
        if not pkt.is_response:
            if pkttype != PACKET_OUTGOING:                   # only queries this host sent
                return
            if not self.cfg.include_loopback and is_loopback(pkt.dst):
                return                                       # local stub: counted once, on the wire
            done = self.pairer.add_query(ts, pkt)
        else:
            if pkttype == PACKET_OUTGOING:
                return
            done = self.pairer.add_response(ts, pkt)
        self._accept(done)

    def _accept(self, records) -> None:
        for r in records:
            name = r["qname"]
            if self._skipped(name):
                self.stats["skipped"] += 1
            else:
                self.buffer.append(r)
                self.stats["records"] += 1

    def _skipped(self, name: str) -> bool:
        for t in self.trusted:
            if name == t or name.endswith("." + t):
                return True
        h = self.skip_host
        return bool(h) and (name == h or name.endswith("." + h))

    # ---------- output ----------
    def _batch(self, records) -> dict:
        return {"batch_id": uuid.uuid4().hex, "os": self.os_name,
                "agent_version": __version__, "queries": records}

    def _failed(self, now: float, status: int) -> None:
        self.fails += 1
        wait = min(300, 5 * 2 ** min(self.fails, 6))
        self.next_ok = now + wait
        if status in (401, 403):
            log.error("manager rejected this agent (HTTP %s). Is it disabled or re-enrolled?", status)
        else:
            log.warning("manager unreachable or busy (status %s), retry in %ss", status, wait)

    def _deliver(self, batch: dict, now: float) -> None:
        n = len(batch["queries"])
        status, body = self.client.ingest(batch)
        if status == 200:
            self.fails = 0
            self.stats["sent"] += n
            self._note_rev(body, now)
        elif status in (400, 422):
            self.stats["poison_dropped"] += n
            log.error("manager refused a batch as invalid (HTTP %s): dropped %s records", status, n)
        elif status == 413 and n > 1:
            half = n // 2
            self._deliver(self._batch(batch["queries"][:half]), now)
            self._deliver(self._batch(batch["queries"][half:]), now)
        else:
            self.spool.save(batch)
            self.stats["spooled"] += n
            self._failed(now, status)

    def _send_due(self, now: float) -> None:
        due = len(self.buffer) >= self.max_batch or (self.buffer and now - self.last_send >= self.interval)
        if not due:
            return
        self.last_send = now
        batch = self._batch(self.buffer[:self.max_batch])
        del self.buffer[:self.max_batch]
        if now < self.next_ok:                               # manager was down: keep it on disk
            self.spool.save(batch)
            self.stats["spooled"] += len(batch["queries"])
        else:
            self._deliver(batch, now)

    def _catch_up(self, now: float) -> None:
        """Resend spooled batches, one every 3 s (stays under the manager's rate limit)."""
        if now < self.next_ok or now - self.last_catchup < 3:
            return
        path = self.spool.oldest()
        if path is None:
            return
        self.last_catchup = now
        batch = self.spool.load(path)
        if batch is None:
            return
        status, body = self.client.ingest(batch)
        if status in (200, 400, 422):
            self.spool.delete(path)
            if status == 200:
                self.fails = 0
                self.stats["resent"] += len(batch["queries"])
                self._note_rev(body, now)
        else:
            self._failed(now, status)

    # ---------- blocking ----------
    def _note_rev(self, body, now: float) -> None:
        """The manager's ingest reply carries its block-list version: if it moved, fetch the list now."""
        if isinstance(body, dict) and body.get("blocks_rev") is not None \
                and body["blocks_rev"] != self.blocks_rev and now - self.last_hb > 5:
            self.last_hb = 0.0

    def _apply_blocks(self, enforce: bool, domains) -> None:
        if self.blocker is None:
            return
        protect = [self.skip_host] + list(self.trusted)
        want = blockmod.safe_domains(domains if enforce else [], protect)
        if self.block_synced and not self.block_error and want == self.block_applied:
            return
        try:
            self.block_applied = self.blocker.sync(want)
            self.block_error, self.block_synced = "", True
            self.report_soon = True
            log.info("blocking %d domain(s): %s", len(want), ", ".join(want[:10]) + (" ..." if len(want) > 10 else ""))
        except blockmod.BlockerError as e:
            self.block_error = str(e)[:300]
            self.report_soon = True
            log.error("blocking failed: %s", self.block_error)

    def block_report(self) -> dict:
        if self.blocker is None:
            return {"capable": False, "enforcing": False, "method": "", "applied": [],
                    "error": "Blocking is not enabled on this agent. Reinstall it with blocking enabled."}
        return {"capable": self.block_ok, "enforcing": bool(self.block_applied) and not self.block_error,
                "method": self.blocker.method, "applied": self.block_applied[:1000],
                "error": self.block_error or ("" if self.block_ok else self.block_why)[:300]}

    def _heartbeat(self, now: float) -> None:
        self.last_hb = now
        status, body = self.client.heartbeat(self.os_name, self.block_report())
        if status == 200 and body:
            cfg = body.get("config", {})
            self.trusted = [t.lower() for t in cfg.get("trusted_domains", [])]
            self.interval = max(1.0, float(cfg.get("batch_interval_seconds", self.interval)))
            self.max_batch = max(1, min(5000, int(cfg.get("max_batch_size", self.max_batch))))
            blk = cfg.get("blocking")
            if isinstance(blk, dict):
                self.blocks_rev = blk.get("rev", self.blocks_rev)
                self._apply_blocks(bool(blk.get("enforce")), blk.get("domains") or [])
        elif status in (401, 403):
            log.error("heartbeat rejected (HTTP %s)", status)
        if self.report_soon:
            self.report_soon, self.last_hb = False, 0.0       # one more heartbeat, with the result

    # ---------- main loop ----------
    def step(self, now=None, wait: float = 0.5) -> None:
        now = time.time() if now is None else now
        try:
            item = self.q.get(timeout=wait)
            for _ in range(5000):
                self.handle(*item)
                item = self.q.get_nowait()
        except queue.Empty:
            pass
        self._accept(self.pairer.flush_expired(now))
        self._send_due(now)
        self._catch_up(now)
        if now - self.last_hb >= 60:
            self._heartbeat(now)
        if now - self.last_log >= 60:
            self.last_log = now
            log.info("stats %s spool_files=%s", dict(self.stats), self.spool.count())

    def run(self) -> None:
        log.info("agent %s started, manager %s", __version__, self.cfg.server)
        self._heartbeat(time.time())
        while not self.stop.is_set():
            self.step()
        self.shutdown()

    def shutdown(self) -> None:
        """Flush everything: send if possible, otherwise keep on disk."""
        self._accept(self.pairer.flush_expired(force=True))
        while True:
            try:
                self.handle(*self.q.get_nowait())
            except queue.Empty:
                break
        self._accept(self.pairer.flush_expired(force=True))
        while self.buffer:
            batch = self._batch(self.buffer[:self.max_batch])
            del self.buffer[:self.max_batch]
            self._deliver(batch, time.time())
        log.info("agent stopped. stats %s", dict(self.stats))
