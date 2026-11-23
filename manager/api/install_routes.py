"""Public endpoints used by the agent installer (no admin key needed):
   GET  /install/linux.sh                  the Linux installer script
   GET  /install/windows.ps1               the Windows installer script (PowerShell)
   GET  /api/v1/agent/bundle.tar.gz        the agent code
   POST /api/v1/agent/enroll               one-time token -> API key
"""
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import FileResponse

from .agent_routes import _agent_config
from .deps import audit
from .schemas import EnrollIn

router = APIRouter(tags=["install"])
DIST = Path(__file__).resolve().parent.parent / "dist"
INSTALLER = DIST / "install-linux.sh"
INSTALLER_WIN = DIST / "install-windows.ps1"


@router.get("/install/linux.sh", include_in_schema=False)
def installer():
    return FileResponse(INSTALLER, media_type="text/x-shellscript",
                        headers={"Cache-Control": "no-store"})


@router.get("/install/windows.ps1", include_in_schema=False)
def installer_windows():
    return FileResponse(INSTALLER_WIN, media_type="text/plain; charset=utf-8",
                        headers={"Cache-Control": "no-store"})


@router.get("/api/v1/agent/bundle.tar.gz")
def bundle(request: Request):
    try:
        blob, sha = request.app.state.bundle.get()
    except FileNotFoundError:
        raise HTTPException(503, "Agent code is missing on the manager.")
    return Response(blob, media_type="application/gzip", headers={"X-SHA256": sha})


@router.post("/api/v1/agent/enroll")
def enroll(body: EnrollIn, request: Request):
    app = request.app
    ip = request.client.host if request.client else "unknown"
    if app.state.enroll_limiter.blocked(ip):
        raise HTTPException(429, "Too many failed attempts. Wait a minute.")
    agent_id = app.state.db.consume_enroll_token(body.token)
    if agent_id is None:
        app.state.enroll_limiter.fail(ip)
        raise HTTPException(401, "Install token is invalid, expired, or already used.")
    agent = app.state.db.get_agent(agent_id)
    if agent is None or not agent["enabled"]:
        raise HTTPException(403, "Agent is disabled.")
    key = app.state.db.rotate_agent_key(agent_id)
    app.state.db.touch_agent(agent_id, body.os, "")
    audit(request, "agent_enrolled", agent["name"], actor="agent:" + agent["name"])
    return {"api_key": key, "name": agent["name"],
            "config": _agent_config(app.state.store.get(), app.state.db, agent["name"])}
