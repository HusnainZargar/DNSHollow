"""Auth, sessions, rate limiting, audit helper."""
import hmac
import logging
import time
from collections import defaultdict, deque
from typing import Optional

from fastapi import Header, HTTPException, Request

from ..security import hash_key

log = logging.getLogger("dnshollow")
SESSION_COOKIE = "dh_session"
SESSION_TTL = 12 * 3600          # a dashboard login lasts 12 hours


# ---------- who is calling? ----------

def session_user(request: Request):
    """The logged-in dashboard user (a DB row) or None.
    A login stops working when the password changes (pw_epoch) or it expires."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    s = request.app.state.sessions.get(hash_key(token))
    if not s or s["exp"] < time.time():
        return None
    user = request.app.state.db.get_user(s["uid"])
    if user is None or user["pw_epoch"] != s["epoch"]:
        return None
    return user


def require_session_user(request: Request):
    """Any logged-in user, even one who still has to change the temporary password."""
    user = session_user(request)
    if user is None:
        raise HTTPException(401, "Please sign in.")
    request.state.actor = user["username"]
    return user


def require_admin(request: Request, x_admin_key: Optional[str] = Header(default=None)):
    """Admin access = X-Admin-Key header (scripts, curl) OR a dashboard login.
    A user who has not changed the temporary password yet is blocked here."""
    if x_admin_key:
        if hmac.compare_digest(hash_key(x_admin_key), request.app.state.admin_hash):
            request.state.actor = "api-key"
            return None
        raise HTTPException(401, "Missing or invalid admin key (X-Admin-Key).")
    user = session_user(request)
    if user is None:
        raise HTTPException(401, "Please sign in.")
    if user["must_change"]:
        raise HTTPException(403, {"code": "password_change_required",
                                  "message": "Change the temporary password first."})
    request.state.actor = user["username"]
    return user


def require_agent(request: Request, x_api_key: Optional[str] = Header(default=None)):
    if not x_api_key:
        raise HTTPException(401, "Missing agent key (X-API-Key).")
    agent = request.app.state.db.get_agent_by_key(x_api_key)
    if agent is None:
        raise HTTPException(401, "Invalid agent key.")
    if not agent["enabled"]:
        raise HTTPException(403, "Agent is disabled.")
    return agent


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def audit(request: Request, action: str, detail: str = "", actor: Optional[str] = None) -> None:
    """Write one line to the audit trail. Never breaks the request."""
    try:
        request.app.state.db.audit(actor or getattr(request.state, "actor", "?"),
                                   action, detail, client_ip(request))
    except Exception:
        log.exception("audit write failed")


# ---------- rate limiting ----------

class RateLimiter:
    """Max N batches per 60 s per agent (in memory)."""

    def __init__(self):
        self._hits: dict[int, deque] = defaultdict(deque)

    def allow(self, agent_id: int, limit: int, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        q = self._hits[agent_id]
        while q and q[0] < now - 60:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True


class FailLimiter:
    """Blocks an IP after N failures in 60 s (in memory)."""

    def __init__(self, limit: int = 5):
        self.limit = limit
        self._fails: dict[str, deque] = defaultdict(deque)

    def _clean(self, ip: str, now: float) -> deque:
        q = self._fails[ip]
        while q and q[0] < now - 60:
            q.popleft()
        return q

    def blocked(self, ip: str, now: Optional[float] = None) -> bool:
        return len(self._clean(ip, time.time() if now is None else now)) >= self.limit

    def fail(self, ip: str, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        self._clean(ip, now).append(now)


def record_engine(app, name: str, ok: bool = True, error: Optional[str] = None) -> None:
    """Remember when each engine profile last ran (shown on the dashboard)."""
    app.state.engine[name] = {"last_run": time.time(), "ok": ok, "error": error}
