"""SQLite storage. Plain sqlite3 (no ORM) to stay lightweight.

WAL mode lets the API write new queries while the engine reads.
One short-lived connection per operation: simple and thread-safe.
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from typing import Optional

from .security import hash_key, new_key

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY, value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    os TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    key_hash TEXT UNIQUE NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    last_seen REAL,
    total_queries INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    host TEXT NOT NULL,
    qname TEXT NOT NULL,
    qtype TEXT NOT NULL,
    parent TEXT NOT NULL,
    resolver TEXT,
    proto TEXT,
    qbytes INTEGER,
    rbytes INTEGER,
    rcode INTEGER
);
CREATE INDEX IF NOT EXISTS idx_q_group ON queries(host, parent, ts);
CREATE INDEX IF NOT EXISTS idx_q_ts ON queries(ts);
CREATE TABLE IF NOT EXISTS batches (
    agent_id INTEGER NOT NULL,
    batch_id TEXT NOT NULL,
    received_at REAL NOT NULL,
    accepted INTEGER NOT NULL,
    dropped INTEGER NOT NULL DEFAULT 0,
    ignored INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, batch_id)
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    pw_hash TEXT NOT NULL,
    must_change INTEGER NOT NULL DEFAULT 1,
    pw_epoch INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    last_login REAL,
    pw_changed_at REAL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE TABLE IF NOT EXISTS enroll_tokens (
    token_hash TEXT PRIMARY KEY,
    agent_id INTEGER NOT NULL,
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile TEXT NOT NULL,
    host TEXT NOT NULL,
    parent TEXT NOT NULL,
    score REAL NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    signals TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'open',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    hits INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_alert_key ON alerts(profile, host, parent);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status, severity);
CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',           -- agent name; '' = every agent
    source TEXT NOT NULL,                    -- 'manual' | 'auto'
    reason TEXT NOT NULL DEFAULT '',
    alert_id INTEGER,
    score REAL,
    created_at REAL NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    expires_at REAL,                         -- NULL = until removed
    active INTEGER NOT NULL DEFAULT 1,
    removed_at REAL,
    removed_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_blocks_active ON blocks(active, parent);
"""

ALERT_STATUSES = ("open", "ack", "false_positive", "expired")

# columns added after the first release: older databases are upgraded on start
NEW_AGENT_COLUMNS = (("block_state", "TEXT"),)      # what the agent reports about enforcing blocks
NEW_QUERY_COLUMNS = (("resolver", "TEXT"), ("proto", "TEXT"), ("qbytes", "INTEGER"),
                     ("rbytes", "INTEGER"), ("rcode", "INTEGER"))


class Database:
    def __init__(self, path: str):
        self.path = path
        with self.conn() as c:
            c.executescript(SCHEMA)
            have = {r["name"] for r in c.execute("PRAGMA table_info(queries)")}
            for col, typ in NEW_QUERY_COLUMNS:
                if col not in have:
                    c.execute("ALTER TABLE queries ADD COLUMN %s %s" % (col, typ))
            have = {r["name"] for r in c.execute("PRAGMA table_info(agents)")}
            for col, typ in NEW_AGENT_COLUMNS:
                if col not in have:
                    c.execute("ALTER TABLE agents ADD COLUMN %s %s" % (col, typ))
            have = {r["name"] for r in c.execute("PRAGMA table_info(batches)")}
            for col in ("dropped", "ignored"):
                if col not in have:
                    c.execute("ALTER TABLE batches ADD COLUMN %s INTEGER NOT NULL DEFAULT 0" % col)

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path, timeout=15)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    # ---------- meta / settings ----------

    def get_meta(self, key: str) -> Optional[str]:
        with self.conn() as c:
            r = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return r["value"] if r else None

    def set_meta(self, key: str, value: str) -> None:
        with self.conn() as c:
            c.execute("INSERT INTO meta(key,value) VALUES(?,?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def load_settings(self) -> Optional[dict]:
        with self.conn() as c:
            r = c.execute("SELECT value FROM settings WHERE key='config'").fetchone()
        return json.loads(r["value"]) if r else None

    def save_settings(self, cfg: dict) -> None:
        with self.conn() as c:
            c.execute("INSERT INTO settings(key,value,updated_at) VALUES('config',?,?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                      (json.dumps(cfg), time.time()))

    def delete_settings(self) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM settings WHERE key='config'")

    # ---------- agents ----------

    def create_agent(self, name: str, os_name: str = "") -> tuple[int, str]:
        """Returns (agent_id, plaintext_key). Raises sqlite3.IntegrityError
        if the name already exists."""
        key = new_key("dh_agent")
        with self.conn() as c:
            cur = c.execute(
                "INSERT INTO agents(name,os,key_hash,created_at) VALUES(?,?,?,?)",
                (name, os_name, hash_key(key), time.time()))
            return cur.lastrowid, key

    def get_agent_by_key(self, key: str):
        with self.conn() as c:
            return c.execute("SELECT * FROM agents WHERE key_hash=?", (hash_key(key),)).fetchone()

    def get_agent(self, agent_id: int):
        with self.conn() as c:
            return c.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()

    def list_agents(self):
        with self.conn() as c:
            return c.execute("SELECT * FROM agents ORDER BY name").fetchall()

    def set_agent_enabled(self, agent_id: int, enabled: bool) -> bool:
        with self.conn() as c:
            return c.execute("UPDATE agents SET enabled=? WHERE id=?",
                             (int(enabled), agent_id)).rowcount > 0

    def rotate_agent_key(self, agent_id: int) -> Optional[str]:
        key = new_key("dh_agent")
        with self.conn() as c:
            n = c.execute("UPDATE agents SET key_hash=? WHERE id=?",
                          (hash_key(key), agent_id)).rowcount
        return key if n else None

    def touch_agent(self, agent_id: int, os_name: str = "", version: str = "",
                    now: Optional[float] = None) -> None:
        with self.conn() as c:
            c.execute("UPDATE agents SET last_seen=?, "
                      "os=CASE WHEN ?!='' THEN ? ELSE os END, "
                      "version=CASE WHEN ?!='' THEN ? ELSE version END WHERE id=?",
                      (now or time.time(), os_name, os_name, version, version, agent_id))

    # ---------- enrollment tokens (one-time, short-lived) ----------

    def create_enroll_token(self, agent_id: int, ttl: float = 900.0) -> str:
        token = new_key("dh_enroll")
        now = time.time()
        with self.conn() as c:
            c.execute("DELETE FROM enroll_tokens WHERE expires_at<? OR used=1", (now,))
            c.execute("INSERT INTO enroll_tokens(token_hash,agent_id,expires_at) VALUES(?,?,?)",
                      (hash_key(token), agent_id, now + ttl))
        return token

    def consume_enroll_token(self, token: str, now: Optional[float] = None) -> Optional[int]:
        """Atomic: a token works exactly once. Returns the agent id, or None."""
        now = time.time() if now is None else now
        h = hash_key(token)
        with self.conn() as c:
            n = c.execute("UPDATE enroll_tokens SET used=1 WHERE token_hash=? AND used=0 "
                          "AND expires_at>?", (h, now)).rowcount
            if n != 1:
                return None
            return c.execute("SELECT agent_id FROM enroll_tokens WHERE token_hash=?", (h,)).fetchone()[0]

    # ---------- ingest ----------

    def insert_batch(self, agent_id: int, host: str, batch_id: str,
                     rows: list[tuple], now: float, dropped: int = 0,
                     ignored: int = 0) -> tuple[int, bool]:
        """rows: (ts, qname, qtype, parent[, resolver, proto, qbytes, rbytes, rcode]).
        One transaction, bulk insert. Returns (accepted, duplicate).
        A repeated batch_id is ignored."""
        with self.conn() as c:
            if c.execute("SELECT 1 FROM batches WHERE agent_id=? AND batch_id=?",
                         (agent_id, batch_id)).fetchone():
                return 0, True
            c.executemany(
                "INSERT INTO queries(ts,host,qname,qtype,parent,resolver,proto,qbytes,rbytes,rcode) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                [(r[0], host, r[1], r[2], r[3]) + tuple(r[4:9]) + (None,) * (9 - len(r))
                 for r in rows])
            c.execute("INSERT INTO batches(agent_id,batch_id,received_at,accepted,dropped,ignored) "
                      "VALUES(?,?,?,?,?,?)", (agent_id, batch_id, now, len(rows), dropped, ignored))
            c.execute("UPDATE agents SET last_seen=?, total_queries=total_queries+? WHERE id=?",
                      (now, len(rows), agent_id))
        return len(rows), False

    # ---------- engine reads ----------

    def candidate_groups(self, since: float, until: float, min_queries: int):
        """(host, parent, count) groups with enough queries. Done in SQL so
        the engine only loads rows for groups worth scoring."""
        with self.conn() as c:
            rows = c.execute(
                "SELECT host, parent, COUNT(*) AS n FROM queries "
                "WHERE ts>=? AND ts<=? GROUP BY host, parent HAVING n>=?",
                (since, until, min_queries)).fetchall()
        return [(r["host"], r["parent"], r["n"]) for r in rows]

    def fetch_group(self, host: str, parent: str, since: float, until: float):
        with self.conn() as c:
            rows = c.execute(
                "SELECT ts, qname, qtype FROM queries "
                "WHERE host=? AND parent=? AND ts>=? AND ts<=? ORDER BY ts",
                (host, parent, since, until)).fetchall()
        return [(r["ts"], r["qname"], r["qtype"]) for r in rows]

    def purge(self, cutoff: float) -> int:
        with self.conn() as c:
            n = c.execute("DELETE FROM queries WHERE ts<?", (cutoff,)).rowcount
            c.execute("DELETE FROM batches WHERE received_at<?", (cutoff,))
        return n

    # ---------- alerts ----------

    def upsert_alert(self, profile: str, host: str, parent: str, score: float,
                     severity: str, summary: str, signals: list, now: float):
        """Create or refresh the alert for (profile, host, parent).
        Returns (alert_id, "created"|"updated"|"suppressed")."""
        sig = json.dumps(signals)
        with self.conn() as c:
            row = c.execute(
                "SELECT id, status FROM alerts WHERE profile=? AND host=? AND parent=? "
                "AND status IN ('open','ack','false_positive') ORDER BY id DESC LIMIT 1",
                (profile, host, parent)).fetchone()
            if row:
                if row["status"] == "false_positive":
                    return row["id"], "suppressed"
                c.execute("UPDATE alerts SET score=?, severity=?, summary=?, signals=?, "
                          "last_seen=?, hits=hits+1 WHERE id=?",
                          (score, severity, summary, sig, now, row["id"]))
                return row["id"], "updated"
            cur = c.execute(
                "INSERT INTO alerts(profile,host,parent,score,severity,summary,signals,"
                "first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?)",
                (profile, host, parent, score, severity, summary, sig, now, now))
            return cur.lastrowid, "created"

    def expire_alerts(self, profile: str, cutoff: float) -> int:
        """Open alerts that stopped firing become 'expired'."""
        with self.conn() as c:
            return c.execute("UPDATE alerts SET status='expired' "
                             "WHERE profile=? AND status='open' AND last_seen<?",
                             (profile, cutoff)).rowcount

    def get_alert(self, alert_id: int):
        with self.conn() as c:
            return c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()

    def list_alerts(self, *, status=None, severity=None, profile=None, host=None,
                    parent=None, limit=50, offset=0):
        where, args = [], []
        for col, val in (("status", status), ("severity", severity), ("profile", profile),
                         ("host", host), ("parent", parent)):
            if val:
                where.append(f"{col}=?")
                args.append(val)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self.conn() as c:
            total = c.execute(f"SELECT COUNT(*) FROM alerts {clause}", args).fetchone()[0]
            rows = c.execute(
                f"SELECT * FROM alerts {clause} ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?",
                args + [limit, offset]).fetchall()
        return rows, total

    def set_alert_status(self, alert_id: int, status: str) -> bool:
        with self.conn() as c:
            return c.execute("UPDATE alerts SET status=? WHERE id=?",
                             (status, alert_id)).rowcount > 0

    def close_alerts_for_parent(self, parent: str, status: str = "false_positive") -> int:
        with self.conn() as c:
            return c.execute("UPDATE alerts SET status=? WHERE parent=? "
                             "AND status IN ('open','ack')", (status, parent)).rowcount

    def campaigns(self, min_hosts: int):
        """Parent domains with active alerts from several hosts."""
        with self.conn() as c:
            rows = c.execute(
                "SELECT parent, COUNT(DISTINCT host) AS hosts, MAX(score) AS max_score, "
                "GROUP_CONCAT(DISTINCT host) AS host_list, MAX(last_seen) AS last_seen "
                "FROM alerts WHERE status IN ('open','ack') GROUP BY parent "
                "HAVING hosts>=? ORDER BY hosts DESC, max_score DESC", (min_hosts,)).fetchall()
        return rows


    # ---------- blocks ----------

    @staticmethod
    def _bump_rev(c) -> None:
        """Agents compare this number to know that the block list changed."""
        c.execute("INSERT INTO meta(key,value) VALUES('blocks_rev','1') "
                  "ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+1")

    def blocks_rev(self) -> int:
        try:
            return int(self.get_meta("blocks_rev") or 0)
        except ValueError:
            return 0

    def add_block(self, parent: str, host: str, source: str, reason: str = "", *,
                  alert_id: Optional[int] = None, score: Optional[float] = None,
                  created_by: str = "", expires_at: Optional[float] = None,
                  now: Optional[float] = None) -> tuple[int, bool]:
        """Block `parent` on one agent (host) or on all ('').
        Returns (block_id, created). An equal or wider active block is reused."""
        now = time.time() if now is None else now
        with self.conn() as c:
            hosts = ("",) if host == "" else ("", host)      # a global block already covers one host
            row = c.execute(
                "SELECT id FROM blocks WHERE active=1 AND parent=? AND host IN (%s) "
                "AND (expires_at IS NULL OR expires_at>?) ORDER BY id DESC LIMIT 1" % ",".join("?" * len(hosts)),
                (parent,) + hosts + (now,)).fetchone()
            if row:
                return row["id"], False
            cur = c.execute(
                "INSERT INTO blocks(parent,host,source,reason,alert_id,score,created_at,created_by,expires_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (parent, host, source, reason[:200], alert_id, score, now, created_by[:64], expires_at))
            self._bump_rev(c)
            return cur.lastrowid, True

    def get_block(self, block_id: int):
        with self.conn() as c:
            return c.execute("SELECT * FROM blocks WHERE id=?", (block_id,)).fetchone()

    def list_blocks(self, *, active: bool = True, limit: int = 100, now: Optional[float] = None):
        now = time.time() if now is None else now
        cond = ("active=1 AND (expires_at IS NULL OR expires_at>?)" if active
                else "NOT (active=1 AND (expires_at IS NULL OR expires_at>?))")
        with self.conn() as c:
            return c.execute("SELECT * FROM blocks WHERE " + cond +
                             " ORDER BY id DESC LIMIT ?", (now, limit)).fetchall()

    def remove_block(self, block_id: int, by: str, now: Optional[float] = None) -> bool:
        with self.conn() as c:
            n = c.execute("UPDATE blocks SET active=0, removed_at=?, removed_by=? WHERE id=? AND active=1",
                          (time.time() if now is None else now, by[:64], block_id)).rowcount
            if n:
                self._bump_rev(c)
            return n > 0

    def remove_blocks_for_parent(self, parent: str, by: str, host: Optional[str] = None) -> int:
        """Remove every active block of a domain (or only the ones that apply to `host`)."""
        sql, args = "UPDATE blocks SET active=0, removed_at=?, removed_by=? WHERE active=1 AND parent=?", \
                    [time.time(), by[:64], parent]
        if host is not None:
            sql += " AND host IN ('', ?)"
            args.append(host)
        with self.conn() as c:
            n = c.execute(sql, args).rowcount
            if n:
                self._bump_rev(c)
            return n

    def expire_blocks(self, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        with self.conn() as c:
            n = c.execute("UPDATE blocks SET active=0, removed_at=?, removed_by='expired' "
                          "WHERE active=1 AND expires_at IS NOT NULL AND expires_at<=?", (now, now)).rowcount
            if n:
                self._bump_rev(c)
            return n

    def blocks_for_agent(self, name: str, now: Optional[float] = None) -> list[str]:
        """Domains this agent has to block (its own + the ones for everyone)."""
        now = time.time() if now is None else now
        with self.conn() as c:
            return [r[0] for r in c.execute(
                "SELECT DISTINCT parent FROM blocks WHERE active=1 AND host IN ('', ?) "
                "AND (expires_at IS NULL OR expires_at>?) ORDER BY parent", (name, now))]

    def blocks_by_parent(self, now: Optional[float] = None) -> dict:
        """parent -> [active block rows as dicts] (the alert views mark what is blocked)."""
        out: dict = {}
        for r in self.list_blocks(active=True, limit=2000, now=now):
            out.setdefault(r["parent"], []).append(dict(r))
        return out

    def set_agent_block_state(self, agent_id: int, state: dict) -> None:
        with self.conn() as c:
            c.execute("UPDATE agents SET block_state=? WHERE id=?", (json.dumps(state), agent_id))

    # ---------- users ----------

    def count_users(self) -> int:
        with self.conn() as c:
            return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def create_user(self, username: str, pw_hash: str, must_change: bool = True) -> int:
        with self.conn() as c:
            return c.execute("INSERT INTO users(username,pw_hash,must_change,created_at) VALUES(?,?,?,?)",
                             (username, pw_hash, int(must_change), time.time())).lastrowid

    def get_user_by_name(self, username: str):
        with self.conn() as c:
            return c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

    def get_user(self, user_id: int):
        with self.conn() as c:
            return c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

    def set_password(self, user_id: int, pw_hash: str, must_change: bool) -> int:
        """Changes the password and ends every other login (epoch + 1). Returns the new epoch."""
        with self.conn() as c:
            c.execute("UPDATE users SET pw_hash=?, must_change=?, pw_epoch=pw_epoch+1, pw_changed_at=? "
                      "WHERE id=?", (pw_hash, int(must_change), time.time(), user_id))
            return c.execute("SELECT pw_epoch FROM users WHERE id=?", (user_id,)).fetchone()[0]

    def touch_login(self, user_id: int, now: float) -> None:
        with self.conn() as c:
            c.execute("UPDATE users SET last_login=? WHERE id=?", (now, user_id))

    # ---------- audit trail ----------

    def audit(self, actor: str, action: str, detail: str = "", ip: str = "") -> None:
        with self.conn() as c:
            c.execute("INSERT INTO audit_log(ts,actor,action,detail,ip) VALUES(?,?,?,?,?)",
                      (time.time(), actor, action, detail[:500], ip))

    def list_audit(self, limit: int = 100, before_id: Optional[int] = None):
        with self.conn() as c:
            return c.execute("SELECT * FROM audit_log WHERE (? IS NULL OR id<?) ORDER BY id DESC LIMIT ?",
                             (before_id, before_id, limit)).fetchall()

    # ---------- logs (what the agents sent) ----------

    def list_queries(self, *, since: float, host=None, text=None, qtype=None, rcode=None,
                     before_id=None, limit: int = 100):
        where, args = ["ts>=?"], [since]
        if host:
            where.append("host=?"); args.append(host)
        if text:
            esc = text.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where.append("qname LIKE ? ESCAPE '\\'"); args.append("%" + esc + "%")
        if qtype:
            where.append("qtype=?"); args.append(qtype.upper())
        if rcode is not None:
            where.append("rcode=?"); args.append(rcode)
        if before_id:
            where.append("id<?"); args.append(before_id)
        with self.conn() as c:
            return c.execute("SELECT * FROM queries WHERE " + " AND ".join(where) +
                             " ORDER BY id DESC LIMIT ?", args + [limit]).fetchall()

    def list_batches(self, limit: int = 100, before_rowid: Optional[int] = None, agent_id=None):
        where, args = [], []
        if before_rowid:
            where.append("b.rowid<?"); args.append(before_rowid)
        if agent_id:
            where.append("b.agent_id=?"); args.append(agent_id)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self.conn() as c:
            return c.execute(
                "SELECT b.rowid AS id, a.name AS agent, b.batch_id, b.received_at, b.accepted, "
                "b.dropped, b.ignored FROM batches b LEFT JOIN agents a ON a.id=b.agent_id " + clause +
                " ORDER BY b.rowid DESC LIMIT ?", args + [limit]).fetchall()

    # ---------- details views ----------

    def group_summary(self, host: str, parent: str, since: float, until: float) -> dict:
        with self.conn() as c:
            one = c.execute(
                "SELECT COUNT(*) n, MIN(ts) first, MAX(ts) last, COUNT(DISTINCT qname) names, "
                "SUM(qbytes) qb, SUM(rbytes) rb FROM queries WHERE host=? AND parent=? AND ts>=? AND ts<=?",
                (host, parent, since, until)).fetchone()

            def top(col):
                return [{"value": r[0], "count": r[1]} for r in c.execute(
                    "SELECT %s, COUNT(*) FROM queries WHERE host=? AND parent=? AND ts>=? AND ts<=? "
                    "GROUP BY %s ORDER BY COUNT(*) DESC LIMIT 6" % (col, col), (host, parent, since, until))]
            return {"queries": one["n"], "first": one["first"], "last": one["last"],
                    "unique_names": one["names"], "bytes_out": one["qb"] or 0, "bytes_in": one["rb"] or 0,
                    "qtypes": top("qtype"), "resolvers": top("resolver"), "rcodes": top("rcode")}

    def group_timeline(self, host: str, parent: str, since: float, until: float, buckets: int = 30):
        size = max((until - since) / buckets, 1e-6)
        counts = [0] * buckets
        with self.conn() as c:
            for r in c.execute("SELECT CAST((ts-?)/? AS INTEGER) b, COUNT(*) FROM queries "
                               "WHERE host=? AND parent=? AND ts>=? AND ts<=? GROUP BY b",
                               (since, size, host, parent, since, until)):
                counts[max(0, min(buckets - 1, r[0]))] += r[1]
        return {"start": since, "step": size, "counts": counts}

    def group_samples(self, host: str, parent: str, since: float, until: float, limit: int = 25):
        with self.conn() as c:
            return c.execute("SELECT ts,qname,qtype,resolver,rcode,qbytes,rbytes FROM queries "
                             "WHERE host=? AND parent=? AND ts>=? AND ts<=? ORDER BY id DESC LIMIT ?",
                             (host, parent, since, until, limit)).fetchall()

    def top_domains(self, host: str, since: float, limit: int = 8):
        with self.conn() as c:
            return [{"parent": r[0], "count": r[1]} for r in c.execute(
                "SELECT parent, COUNT(*) FROM queries WHERE host=? AND ts>=? GROUP BY parent "
                "ORDER BY COUNT(*) DESC LIMIT ?", (host, since, limit))]

    # ---------- stats ----------

    def stats(self, now: float, online_window: float) -> dict:
        with self.conn() as c:
            sev = {r["severity"]: r["n"] for r in c.execute(
                "SELECT severity, COUNT(*) n FROM alerts WHERE status='open' GROUP BY severity")}
            total_agents = c.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
            online = c.execute("SELECT COUNT(*) FROM agents WHERE enabled=1 AND last_seen>=?",
                               (now - online_window,)).fetchone()[0]
            q1h = c.execute("SELECT COUNT(*) FROM queries WHERE ts>=?", (now - 3600,)).fetchone()[0]
            nblocks = c.execute("SELECT COUNT(*) FROM blocks WHERE active=1 AND (expires_at IS NULL OR expires_at>?)",
                                (now,)).fetchone()[0]
        return {
            "blocks_active": nblocks,
            "alerts_open": {k: sev.get(k, 0) for k in ("high", "medium", "low")},
            "agents": {"total": total_agents, "online": online},
            "queries_last_hour": q1h,
        }
