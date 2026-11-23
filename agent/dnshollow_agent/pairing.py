"""Match each DNS response to its query -> one record per DNS transaction."""
import time
from typing import Dict, List, Optional, Tuple

from .dnsparse import DnsPacket


def _record(ts: float, q: DnsPacket, rbytes: Optional[int], rcode: Optional[int]) -> dict:
    return {"ts": round(ts, 3), "qname": q.qname, "qtype": q.qtype, "resolver": q.dst,
            "proto": q.proto, "qbytes": q.dns_len, "rbytes": rbytes, "rcode": rcode}


class Pairer:
    def __init__(self, timeout: float = 5.0, max_pending: int = 50000):
        self.timeout = timeout
        self.max_pending = max_pending
        self.pending: Dict[Tuple, Tuple[float, DnsPacket]] = {}

    @staticmethod
    def _key(q: DnsPacket, response: bool):
        client, cport, server = (q.dst, q.dport, q.src) if response else (q.src, q.sport, q.dst)
        sport = q.sport if response else q.dport
        return (q.proto, client, cport, server, sport, q.txid)

    def add_query(self, ts: float, q: DnsPacket) -> List[dict]:
        out = []
        key = self._key(q, False)
        old = self.pending.get(key)
        if old:                                    # retransmit: close the old one as unanswered
            out.append(_record(old[0], old[1], None, None))
        self.pending[key] = (ts, q)
        if len(self.pending) > self.max_pending:   # flood protection: flush the oldest
            oldest = min(self.pending, key=lambda k: self.pending[k][0])
            t, p = self.pending.pop(oldest)
            out.append(_record(t, p, None, None))
        return out

    def add_response(self, ts: float, r: DnsPacket) -> List[dict]:
        item = self.pending.pop(self._key(r, True), None)
        if item is None:
            return []                              # started mid-flight: ignore
        return [_record(item[0], item[1], r.dns_len, r.rcode)]

    def flush_expired(self, now: Optional[float] = None, force: bool = False) -> List[dict]:
        now = time.time() if now is None else now
        out = []
        for key in [k for k, (t, _) in self.pending.items() if force or now - t > self.timeout]:
            t, q = self.pending.pop(key)
            out.append(_record(t, q, None, None))
        return out
