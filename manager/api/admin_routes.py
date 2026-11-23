"""Admin endpoints (auth: X-Admin-Key): agents, settings, manual engine run."""
import json
import sqlite3
import time

from fastapi import APIRouter, Depends, HTTPException, Request

from ..engine.runner import run_profile
from ..engine.settings import DEFAULTS, PRESETS
from ..settings_store import SettingsError
from .deps import audit, record_engine, require_admin
from .schemas import AgentCreate, AgentPatch, SettingsBody

router = APIRouter(prefix="/api/v1/admin", tags=["admin"], dependencies=[Depends(require_admin)])


def _online_window(settings: dict) -> float:
    return max(60.0, 6 * settings["agent"]["batch_interval_seconds"])


def agent_dict(row, online_window: float, now: float) -> dict:
    last = row["last_seen"]
    return {
        "id": row["id"], "name": row["name"], "os": row["os"], "version": row["version"],
        "enabled": bool(row["enabled"]), "created_at": row["created_at"],
        "last_seen": last, "total_queries": row["total_queries"],
        "online": bool(row["enabled"] and last and now - last <= online_window),
        "blocking": json.loads(row["block_state"]) if row["block_state"] else None,
    }


# ---------- agents ----------

@router.post("/agents", status_code=201)
def create_agent(body: AgentCreate, request: Request):
    try:
        agent_id, key = request.app.state.db.create_agent(body.name, body.os)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "An agent with this name already exists.")
    audit(request, "agent_created", body.name)
    return {"id": agent_id, "name": body.name,
            "api_key": key, "note": "Save this key now. It is shown only once."}


@router.get("/agents")
def list_agents(request: Request):
    now = time.time()
    win = _online_window(request.app.state.store.get())
    return [agent_dict(r, win, now) for r in request.app.state.db.list_agents()]


@router.patch("/agents/{agent_id}")
def patch_agent(agent_id: int, body: AgentPatch, request: Request):
    if not request.app.state.db.set_agent_enabled(agent_id, body.enabled):
        raise HTTPException(404, "Agent not found.")
    audit(request, "agent_enabled" if body.enabled else "agent_disabled", "agent id %s" % agent_id)
    return {"id": agent_id, "enabled": body.enabled}


ENROLL_TTL = 900     # install command is valid for 15 minutes


@router.post("/agents/{agent_id}/enroll-token")
def enroll_token(agent_id: int, request: Request):
    """One-time token for the install command. The installer swaps it for the
    real API key, so the key never appears in the dashboard or a shell history."""
    app = request.app
    row = app.state.db.get_agent(agent_id)
    if row is None:
        raise HTTPException(404, "Agent not found.")
    try:
        _blob, sha = app.state.bundle.get()
    except FileNotFoundError:
        raise HTTPException(503, "Agent code is missing on the manager (agent/ folder).")
    token = app.state.db.create_enroll_token(agent_id, ENROLL_TTL)
    audit(request, "install_command_created", row["name"])
    return {"token": token, "expires_in": ENROLL_TTL, "sha256": sha, "agent": row["name"]}


@router.post("/agents/{agent_id}/rotate-key")
def rotate_key(agent_id: int, request: Request):
    key = request.app.state.db.rotate_agent_key(agent_id)
    if key is None:
        raise HTTPException(404, "Agent not found.")
    audit(request, "agent_key_rotated", "agent id %s" % agent_id)
    return {"id": agent_id, "api_key": key, "note": "Old key no longer works."}


@router.get("/agents/{agent_id}/details")
def agent_details(agent_id: int, request: Request):
    """The list shows short facts; this adds recent activity and top domains."""
    app = request.app
    row = app.state.db.get_agent(agent_id)
    if row is None:
        raise HTTPException(404, "Agent not found.")
    now = time.time()
    base = agent_dict(row, _online_window(app.state.store.get()), now)
    return {"agent": base,
            "recent_batches": [dict(r) for r in app.state.db.list_batches(limit=10, agent_id=agent_id)],
            "top_domains_last_hour": app.state.db.top_domains(row["name"], now - 3600)}


# ---------- settings ----------

@router.get("/settings")
def get_settings(request: Request):
    return request.app.state.store.get()


@router.get("/settings/defaults")
def get_defaults():
    return DEFAULTS


@router.put("/settings")
def put_settings(body: SettingsBody, request: Request):
    """Replace the whole config (missing keys = defaults)."""
    try:
        out = request.app.state.store.replace(body.config)
    except SettingsError as e:
        raise HTTPException(422, {"errors": e.errors})
    audit(request, "settings_replaced")
    return out


@router.patch("/settings")
def patch_settings(body: SettingsBody, request: Request):
    """Change only the keys sent. Used by the dashboard for small edits."""
    try:
        out = request.app.state.store.patch(body.config)
    except SettingsError as e:
        raise HTTPException(422, {"errors": e.errors})
    audit(request, "settings_changed", ", ".join(sorted(body.config))[:200])
    return out


@router.post("/settings/reset")
def reset_settings(request: Request):
    out = request.app.state.store.reset()
    audit(request, "settings_reset")
    return out


@router.get("/settings/presets")
def list_presets():
    return [{"name": k, "title": v["title"], "description": v["description"], "config": v["config"]}
            for k, v in PRESETS.items()]


@router.post("/settings/preset/{name}")
def apply_preset(name: str, request: Request):
    """One click: Relaxed / Balanced / Strict."""
    if name not in PRESETS:
        raise HTTPException(404, "Unknown preset.")
    try:
        out = request.app.state.store.patch(PRESETS[name]["config"])
    except SettingsError as e:
        raise HTTPException(422, {"errors": e.errors})
    audit(request, "preset_applied", name)
    return out


# ---------- engine ----------

@router.post("/run/{profile}")
def run_now(profile: str, request: Request):
    """Run a profile immediately (same code the scheduler runs)."""
    settings = request.app.state.store.get()
    if profile not in settings["profiles"]:
        raise HTTPException(404, f"Unknown profile '{profile}'.")
    try:
        result = run_profile(request.app.state.db, settings, profile)
    except Exception as e:
        record_engine(request.app, profile, ok=False, error=str(e))
        raise
    record_engine(request.app, profile)
    return result
