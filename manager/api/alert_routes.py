"""Read/manage alerts, campaigns, stats (auth: X-Admin-Key).
The dashboard will call these."""
import json
import time
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .admin_routes import _online_window
from .deps import audit, require_admin
from .schemas import AlertPatch

router = APIRouter(prefix="/api/v1", tags=["alerts"], dependencies=[Depends(require_admin)])


def alert_dict(row, blocks_by_parent=None) -> dict:
    d = dict(row)
    d["signals"] = json.loads(d["signals"])
    if blocks_by_parent is not None:                  # active blocks that cover this alert's domain + computer
        d["blocks"] = [{"id": b["id"], "scope": "host" if b["host"] else "all", "source": b["source"],
                        "expires_at": b["expires_at"]}
                       for b in blocks_by_parent.get(d["parent"], []) if b["host"] in ("", d["host"])]
    return d


@router.get("/alerts")
def list_alerts(
    request: Request,
    status: Optional[Literal["open", "ack", "false_positive", "expired"]] = None,
    severity: Optional[Literal["low", "medium", "high"]] = None,
    profile: Optional[str] = None,
    host: Optional[str] = None,
    parent: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    rows, total = request.app.state.db.list_alerts(
        status=status, severity=severity, profile=profile, host=host,
        parent=parent, limit=limit, offset=offset)
    bp = request.app.state.db.blocks_by_parent()
    return {"total": total, "items": [alert_dict(r, bp) for r in rows]}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, request: Request):
    row = request.app.state.db.get_alert(alert_id)
    if row is None:
        raise HTTPException(404, "Alert not found.")
    return alert_dict(row, request.app.state.db.blocks_by_parent())


@router.patch("/alerts/{alert_id}")
def patch_alert(alert_id: int, body: AlertPatch, request: Request):
    if not request.app.state.db.set_alert_status(alert_id, body.status):
        raise HTTPException(404, "Alert not found.")
    audit(request, "alert_" + body.status, "alert %s" % alert_id)
    lifted = 0
    if body.status == "false_positive":               # "not a threat" also lifts the block it caused
        row = request.app.state.db.get_alert(alert_id)
        lifted = request.app.state.db.remove_blocks_for_parent(
            row["parent"], getattr(request.state, "actor", "?"), host=row["host"])
        if lifted:
            audit(request, "block_removed", "%s (marked not a threat)" % row["parent"])
    return {"id": alert_id, "status": body.status, "blocks_removed": lifted}


@router.get("/alerts/{alert_id}/details")
def alert_details(alert_id: int, request: Request):
    """The detailed view: numbers, a timeline and sample queries behind one alert."""
    app = request.app
    row = app.state.db.get_alert(alert_id)
    if row is None:
        raise HTTPException(404, "Alert not found.")
    prof = app.state.store.get()["profiles"].get(row["profile"], {})
    window = float(prof.get("window_seconds", 300))
    until = row["last_seen"]
    since = until - window
    db = app.state.db
    others = [r["host"] for r in db.list_alerts(parent=row["parent"], status="open", limit=50)[0]
              if r["host"] != row["host"]]
    return {
        "alert": alert_dict(row),
        "window": {"since": since, "until": until, "seconds": window},
        "summary": db.group_summary(row["host"], row["parent"], since, until),
        "timeline": db.group_timeline(row["host"], row["parent"], since, until),
        "samples": [dict(r) for r in db.group_samples(row["host"], row["parent"], since, until)],
        "other_hosts": sorted(set(others)),
    }


@router.post("/alerts/{alert_id}/trust-domain")
def trust_domain(alert_id: int, request: Request):
    """One click: add the alert's domain to the trusted list and close its alerts."""
    app = request.app
    row = app.state.db.get_alert(alert_id)
    if row is None:
        raise HTTPException(404, "Alert not found.")
    parent = row["parent"]
    trusted = app.state.store.get()["trusted_domains"]
    if parent not in trusted:
        app.state.store.patch({"trusted_domains": trusted + [parent]})
    closed = app.state.db.close_alerts_for_parent(parent)
    unblocked = app.state.db.remove_blocks_for_parent(parent, getattr(request.state, "actor", "?"))
    audit(request, "domain_trusted", parent)
    return {"trusted": parent, "alerts_closed": closed, "blocks_removed": unblocked}


@router.get("/campaigns")
def campaigns(request: Request):
    """Domains with active alerts from several hosts."""
    min_hosts = request.app.state.store.get()["campaign_min_hosts"]
    rows = request.app.state.db.campaigns(min_hosts)
    return [{"parent": r["parent"], "hosts": r["hosts"], "host_list": r["host_list"].split(","),
             "max_score": r["max_score"], "last_seen": r["last_seen"]} for r in rows]


@router.get("/stats")
def stats(request: Request):
    settings = request.app.state.store.get()
    out = request.app.state.db.stats(time.time(), _online_window(settings))
    out["engine"] = {
        "scheduler": request.app.state.scheduler_on,
        "profiles": {n: {"enabled": p["enabled"], "run_every": p["run_every_seconds"],
                         **request.app.state.engine.get(n, {"last_run": None, "ok": None, "error": None})}
                     for n, p in settings["profiles"].items()},
    }
    return out
