"""Block DNS for a domain (auth: dashboard login or X-Admin-Key).

A block is a (domain, computer) pair, or (domain, every computer). Agents that were
installed with blocking enabled read their list from the heartbeat and drop DNS for
those domains. Auto-block (engine/blocking.py) creates the same kind of block.
"""
import json
import time

from fastapi import APIRouter, Depends, HTTPException, Request

from ..engine.blocking import BlockError, clean_block_domain, expiry
from .deps import audit, require_admin
from .schemas import AlertBlock, BlockCreate

router = APIRouter(prefix="/api/v1", tags=["blocking"], dependencies=[Depends(require_admin)])


def block_dict(row) -> dict:
    d = dict(row)
    d["scope"] = "host" if d["host"] else "all"
    return d


def _need_enabled(settings: dict) -> None:
    if not settings["blocking"]["enabled"]:
        raise HTTPException(409, "Blocking is switched off. Turn it on in Settings > Blocking first.")


def _enforcement(request: Request) -> list[dict]:
    """What each agent says about enforcing (shown next to the block list)."""
    out = []
    for a in request.app.state.db.list_agents():
        st = json.loads(a["block_state"]) if a["block_state"] else None
        out.append({"name": a["name"], "enabled": bool(a["enabled"]), "state": st})
    return out


@router.get("/blocks")
def list_blocks(request: Request):
    db = request.app.state.db
    settings = request.app.state.store.get()
    return {
        "enabled": settings["blocking"]["enabled"],
        "auto": {k: settings["blocking"][k] for k in ("auto_block", "auto_min_score", "auto_scope", "auto_expire_hours")},
        "active": [block_dict(r) for r in db.list_blocks(active=True, limit=500)],
        "history": [block_dict(r) for r in db.list_blocks(active=False, limit=30)],
        "agents": _enforcement(request),
    }


def _make(request: Request, parent: str, scope: str, host, hours, reason: str, alert=None):
    app = request.app
    settings = app.state.store.get()
    _need_enabled(settings)
    try:
        parent = clean_block_domain(parent, settings["trusted_domains"])
    except BlockError as e:
        raise HTTPException(422, str(e))
    if scope == "host":
        names = {a["name"] for a in app.state.db.list_agents()}
        if not host or host not in names:
            raise HTTPException(422, "Choose which computer to block it on.")
    else:
        host = ""
    now = time.time()
    actor = getattr(request.state, "actor", "?")
    block_id, created = app.state.db.add_block(
        parent, host, "manual", reason, alert_id=alert["id"] if alert else None,
        score=alert["score"] if alert else None, created_by=actor, expires_at=expiry(hours, now), now=now)
    if created:
        audit(request, "block_added", "%s on %s" % (parent, host or "all computers"))
    return {"id": block_id, "created": created, "parent": parent, "host": host}


@router.post("/blocks", status_code=201)
def add_block(body: BlockCreate, request: Request):
    return _make(request, body.parent, body.scope, body.host, body.hours, body.reason)


@router.post("/alerts/{alert_id}/block", status_code=201)
def block_from_alert(alert_id: int, body: AlertBlock, request: Request):
    """One click on an alert: block its domain on that computer (or on all computers)."""
    row = request.app.state.db.get_alert(alert_id)
    if row is None:
        raise HTTPException(404, "Alert not found.")
    return _make(request, row["parent"], body.scope, row["host"], body.hours,
                 "Blocked from alert %s" % alert_id, alert=row)


@router.delete("/blocks/{block_id}")
def remove_block(block_id: int, request: Request):
    db = request.app.state.db
    row = db.get_block(block_id)
    if row is None or not row["active"]:
        raise HTTPException(404, "Block not found (it may already be removed).")
    actor = getattr(request.state, "actor", "?")
    db.remove_block(block_id, actor)
    # An open alert for this domain would just be auto-blocked again within a minute.
    # Mark it "looking into it" so unblocking by hand sticks.
    calmed = 0
    for a in db.list_alerts(parent=row["parent"], status="open", limit=200)[0]:
        if not row["host"] or a["host"] == row["host"]:
            db.set_alert_status(a["id"], "ack")
            calmed += 1
    audit(request, "block_removed", "%s on %s" % (row["parent"], row["host"] or "all computers"))
    return {"id": block_id, "removed": True, "alerts_acknowledged": calmed}
