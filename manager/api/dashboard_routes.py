"""The dashboard page plus login, logout and password change."""
import os
import secrets
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from ..security import burn_time, check_new_password, hash_key, hash_password, verify_password
from .deps import (SESSION_COOKIE, SESSION_TTL, audit, client_ip, require_session_user,
                   session_user)

DASH_DIR = Path(__file__).resolve().parent.parent / "dashboard"
router = APIRouter()

# No inline scripts allowed. Inline style attributes are (progress bars, charts).
CSP = ("default-src 'self'; style-src 'self' 'unsafe-inline'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=200)


class PasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=1, max_length=200)


def credentials_path(db_path) -> Path:
    """Where the temporary login is written (next to the database)."""
    return Path(db_path).resolve().parent / "initial-credentials.txt"


def credentials_file(app) -> Path:
    return credentials_path(app.state.db.path)


def _open_session(request: Request, response: Response, user) -> None:
    app = request.app
    now = time.time()
    sessions = app.state.sessions
    for k in [k for k, v in sessions.items() if v["exp"] < now]:      # forget expired logins
        del sessions[k]
    token = secrets.token_urlsafe(32)
    sessions[hash_key(token)] = {"uid": user["id"], "epoch": user["pw_epoch"], "exp": now + SESSION_TTL}
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True,
                        samesite="strict", secure=request.url.scheme == "https")


@router.get("/", include_in_schema=False)
def index():
    return FileResponse(DASH_DIR / "index.html", media_type="text/html", headers={
        "Cache-Control": "no-store", "Content-Security-Policy": CSP,
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer"})


@router.post("/api/v1/session", tags=["account"])
def login(body: LoginIn, request: Request, response: Response):
    app, ip = request.app, client_ip(request)
    if app.state.login_limiter.blocked(ip):
        raise HTTPException(429, "Too many failed sign-ins. Wait a minute and try again.")
    user = app.state.db.get_user_by_name(body.username.strip())
    ok = verify_password(body.password, user["pw_hash"]) if user else (burn_time(body.password) or False)
    if not ok:
        app.state.login_limiter.fail(ip)
        audit(request, "login_failed", "username=%s" % body.username.strip()[:64], actor="-")
        raise HTTPException(401, "Wrong username or password.")
    app.state.db.touch_login(user["id"], time.time())
    _open_session(request, response, user)
    audit(request, "login", actor=user["username"])
    return {"ok": True, "username": user["username"], "must_change": bool(user["must_change"])}


@router.get("/api/v1/session", tags=["account"])
def whoami(user=Depends(require_session_user)):
    return {"ok": True, "username": user["username"], "must_change": bool(user["must_change"]),
            "last_login": user["last_login"]}


@router.delete("/api/v1/session", tags=["account"])
def logout(request: Request, response: Response):
    user = session_user(request)
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        request.app.state.sessions.pop(hash_key(token), None)
    if user:
        audit(request, "logout", actor=user["username"])
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@router.post("/api/v1/account/password", tags=["account"])
def change_password(body: PasswordIn, request: Request, response: Response,
                    user=Depends(require_session_user)):
    app, ip = request.app, client_ip(request)
    if app.state.login_limiter.blocked(ip):
        raise HTTPException(429, "Too many failed attempts. Wait a minute.")
    if not verify_password(body.current_password, user["pw_hash"]):
        app.state.login_limiter.fail(ip)
        audit(request, "password_change_failed", "wrong current password")
        raise HTTPException(400, {"errors": ["The current password is not correct."]})
    problems = check_new_password(body.new_password, user["username"], body.current_password)
    if problems:
        raise HTTPException(422, {"errors": problems})

    epoch = app.state.db.set_password(user["id"], hash_password(body.new_password), must_change=False)
    token = request.cookies.get(SESSION_COOKIE)             # keep THIS login, end all others
    if token:
        s = app.state.sessions.get(hash_key(token))
        if s:
            s["epoch"] = epoch
    try:
        credentials_file(app).unlink()                      # the temporary password is gone for good
    except FileNotFoundError:
        pass
    audit(request, "password_changed")
    return {"ok": True}
