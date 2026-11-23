"""Endpoints used by agents (auth: X-API-Key).

All agents use the SAME endpoints. The key says which agent is calling.
"""
import sqlite3
import time

from fastapi import APIRouter, Depends, HTTPException, Request

from ..engine.domain import is_trusted, normalize, split_domain
from .deps import require_agent
from .schemas import HeartbeatIn, IngestIn

router = APIRouter(prefix="/api/v1/agent", tags=["agent"])


def _agent_config(settings: dict, db=None, agent_name: str = "") -> dict:
    cfg = {
        "batch_interval_seconds": settings["agent"]["batch_interval_seconds"],
        "max_batch_size": settings["agent"]["max_batch_size"],
        "trusted_domains": settings["trusted_domains"],   # agent may skip these
    }
    if db is not None:
        on = bool(settings["blocking"]["enabled"])
        cfg["blocking"] = {"enforce": on, "rev": db.blocks_rev(),
                           "domains": db.blocks_for_agent(agent_name) if on else []}
    return cfg


@router.get("/config")
def config(request: Request, agent=Depends(require_agent)):
    return _agent_config(request.app.state.store.get(), request.app.state.db, agent["name"])


@router.post("/heartbeat")
def heartbeat(body: HeartbeatIn, request: Request, agent=Depends(require_agent)):
    db = request.app.state.db
    now = time.time()
    db.touch_agent(agent["id"], body.os, body.agent_version, now)
    if body.blocking is not None:
        state = body.blocking.model_dump()
        state["at"] = now
        db.set_agent_block_state(agent["id"], state)
    return {"ok": True, "server_time": now,
            "config": _agent_config(request.app.state.store.get(), db, agent["name"])}


@router.post("/ingest")
def ingest(body: IngestIn, request: Request, agent=Depends(require_agent)):
    app = request.app
    settings = app.state.store.get()
    limits = settings["agent"]

    if not app.state.limiter.allow(agent["id"], limits["max_batches_per_minute"]):
        raise HTTPException(429, "Too many batches. Send fewer, larger batches.",
                            headers={"Retry-After": "10"})
    if len(body.queries) > limits["max_batch_size"]:
        raise HTTPException(413, f"Batch too large (max {limits['max_batch_size']} queries).")

    now = time.time()
    oldest = now - settings["retention_days"] * 86400
    trusted = settings["trusted_domains"]

    rows, dropped, ignored = [], 0, 0
    for q in body.queries:
        name = normalize(q.qname)
        if not name or len(name) > 253 or not (oldest <= q.ts <= now + 300):
            dropped += 1
            continue
        parent = split_domain(name).parent
        if not parent:
            dropped += 1
            continue
        if is_trusted(parent, trusted):      # trusted = skipped, never stored
            ignored += 1
            continue
        proto = (q.proto or "").lower()
        rows.append((
            q.ts, name, (q.qtype or "A").upper()[:16], parent,
            (q.resolver or "")[:64] or None,
            proto if proto in ("udp", "tcp") else None,
            q.qbytes if q.qbytes is not None and 0 <= q.qbytes <= 70000 else None,
            q.rbytes if q.rbytes is not None and 0 <= q.rbytes <= 70000 else None,
            q.rcode if q.rcode is not None and 0 <= q.rcode <= 15 else None))

    try:
        accepted, duplicate = app.state.db.insert_batch(
            agent["id"], agent["name"], body.batch_id, rows, now, dropped, ignored)
    except sqlite3.IntegrityError:           # same batch sent twice at once
        accepted, duplicate = 0, True

    if body.os or body.agent_version:
        app.state.db.touch_agent(agent["id"], body.os, body.agent_version, now)

    return {"accepted": accepted, "dropped": dropped, "ignored_trusted": ignored,
            "duplicate": duplicate, "blocks_rev": app.state.db.blocks_rev()}
