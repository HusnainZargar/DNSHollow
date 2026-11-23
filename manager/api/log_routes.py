"""Logs: what the agents sent, how batches arrived, and who did what."""
import time
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request

from .deps import require_admin

router = APIRouter(prefix="/api/v1/logs", tags=["logs"], dependencies=[Depends(require_admin)])


@router.get("/queries")
def query_log(
    request: Request,
    agent: Optional[str] = None,
    q: Optional[str] = Query(None, max_length=100, description="part of the domain name"),
    qtype: Optional[str] = Query(None, max_length=16),
    rcode: Optional[int] = Query(None, ge=0, le=15),
    minutes: int = Query(60, ge=1, le=60 * 24 * 30),
    before_id: Optional[int] = Query(None, ge=1, description="paging: only rows older than this id"),
    limit: int = Query(100, ge=1, le=500),
):
    rows = request.app.state.db.list_queries(
        since=time.time() - minutes * 60, host=agent, text=q, qtype=qtype, rcode=rcode,
        before_id=before_id, limit=limit)
    items = [dict(r) for r in rows]
    return {"items": items, "next_before_id": items[-1]["id"] if len(items) == limit else None}


@router.get("/batches")
def batch_log(request: Request, before_id: Optional[int] = Query(None, ge=1),
              limit: int = Query(100, ge=1, le=500)):
    items = [dict(r) for r in request.app.state.db.list_batches(limit=limit, before_rowid=before_id)]
    return {"items": items, "next_before_id": items[-1]["id"] if len(items) == limit else None}


@router.get("/audit")
def audit_log(request: Request, before_id: Optional[int] = Query(None, ge=1),
              limit: int = Query(100, ge=1, le=500)):
    items = [dict(r) for r in request.app.state.db.list_audit(limit, before_id)]
    return {"items": items, "next_before_id": items[-1]["id"] if len(items) == limit else None}
