"""Blocking rules shared by the API (manual block) and the engine (auto-block).

A block always targets a registered domain ("evil.com"), never a bare TLD or a
public suffix, so one typo cannot cut off all DNS. Subdomains are included.
"""
from __future__ import annotations

import ipaddress
import re
import time
from typing import Optional

from .domain import _extract, is_trusted, normalize, split_domain

_NAME = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$")


class BlockError(ValueError):
    """A block request that is refused. The message is shown to the user."""


def clean_block_domain(text: str, trusted_domains) -> str:
    """Return the domain to block, or raise BlockError with a plain explanation."""
    name = normalize(text or "")
    if not name or len(name) > 253 or not _NAME.match(name):
        raise BlockError("Enter a domain name like evil-dns.xyz (letters, numbers, dots and dashes).")
    try:
        ipaddress.ip_address(name)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        raise BlockError("Enter a domain name, not an IP address.")
    ext = _extract(name)
    if ext.suffix and not ext.domain:
        raise BlockError("%s is a public suffix. Blocking it would cut off many sites." % name)
    parent = split_domain(name).parent
    if parent != name:
        raise BlockError("Enter the main domain (%s). Its subdomains are blocked too." % parent)
    if is_trusted(parent, trusted_domains):
        raise BlockError("%s is on your trusted list. Remove it from Trusted domains first." % parent)
    return parent


def expiry(hours: Optional[float], now: float) -> Optional[float]:
    return now + float(hours) * 3600 if hours else None


def auto_block(db, settings: dict, *, host: str, parent: str, score: float,
               alert_id: int, now: Optional[float] = None) -> Optional[int]:
    """Called by the engine after an alert is written. Returns the new block id, or None.

    Blocks only when: blocking and auto-block are both on, the score reached the
    threshold, the domain is not trusted, and the alert is still 'open' (an alert
    someone acknowledged or marked as not a threat is never auto-blocked again)."""
    cfg = settings["blocking"]
    if not (cfg["enabled"] and cfg["auto_block"]) or score < cfg["auto_min_score"]:
        return None
    if is_trusted(parent, settings["trusted_domains"]):
        return None
    alert = db.get_alert(alert_id)
    if alert is None or alert["status"] != "open":
        return None
    now = time.time() if now is None else now
    scope_host = host if cfg["auto_scope"] == "host" else ""
    block_id, created = db.add_block(
        parent, scope_host, "auto", "Score %g reached the auto-block level (%g)" % (score, cfg["auto_min_score"]),
        alert_id=alert_id, score=score, created_by="auto-block",
        expires_at=expiry(cfg["auto_expire_hours"], now), now=now)
    if not created:
        return None
    db.audit("auto-block", "auto_block", "%s on %s (score %g)" % (parent, scope_host or "all computers", score))
    return block_id
