"""DNSHollow manager API.

Run (single worker, because the scheduler lives inside the app):
    uvicorn manager.api.main:create_app --factory --host 0.0.0.0 --port 8000

Admin key: set DNSHOLLOW_ADMIN_KEY, or the app generates one on first start
and prints it once.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from ..bundle import BundleCache
from ..db import Database
from ..engine.runner import purge_old, run_profile
from ..security import hash_key, hash_password, make_temp_password, new_key
from ..settings_store import SettingsStore
from .admin_routes import router as admin_router
from .agent_routes import router as agent_router
from .alert_routes import router as alert_router
from .block_routes import router as block_router
from .dashboard_routes import DASH_DIR, credentials_path, router as dashboard_router
from .deps import FailLimiter, RateLimiter, record_engine
from .install_routes import router as install_router
from .log_routes import router as log_router

log = logging.getLogger("dnshollow")


def bootstrap_admin_key(db: Database, provided: Optional[str]) -> Optional[str]:
    """Make sure an admin key exists. Returns the plaintext only when it was
    just generated (so it can be shown once)."""
    if provided:
        db.set_meta("admin_key_hash", hash_key(provided))
        return None
    if db.get_meta("admin_key_hash"):
        return None
    key = new_key("dh_admin")
    db.set_meta("admin_key_hash", hash_key(key))
    return key


def bootstrap_admin_user(db: Database, provided: Optional[str]):
    """First start only: create the user 'admin' with a temporary password.
    Returns (password, was_random) or None when users already exist."""
    if db.count_users() > 0:
        return None
    random_pw = not provided
    pw = provided or make_temp_password()
    db.create_user("admin", hash_password(pw), must_change=True)
    db.audit("system", "first_user_created", "admin (temporary password)")
    return pw, random_pw


async def _profile_loop(app: FastAPI, name: str) -> None:
    """Runs one detection profile forever (24/7). Errors never stop the loop."""
    while True:
        every = 60
        try:
            settings = app.state.store.get()
            every = max(5, settings["profiles"][name]["run_every_seconds"])
            await asyncio.to_thread(run_profile, app.state.db, settings, name)
            record_engine(app, name)
        except Exception as e:
            log.exception("engine run failed (%s)", name)
            record_engine(app, name, ok=False, error=str(e))
        await asyncio.sleep(every)


async def _purge_loop(app: FastAPI) -> None:
    while True:
        try:
            await asyncio.to_thread(purge_old, app.state.db, app.state.store.get())
        except Exception:
            log.exception("purge failed")
        await asyncio.sleep(3600)


def create_app(db_path: Optional[str] = None, *, scheduler: bool = True,
               admin_key: Optional[str] = None, docs: Optional[bool] = None,
               initial_password: Optional[str] = None) -> FastAPI:
    db = Database(db_path or os.environ.get("DNSHOLLOW_DB", "dnshollow.db"))
    store = SettingsStore(db)
    # optional key for scripts (X-Admin-Key header). The dashboard uses user logins.
    bootstrap_admin_key(db, admin_key or os.environ.get("DNSHOLLOW_ADMIN_KEY"))
    first = bootstrap_admin_user(db, initial_password or os.environ.get("DNSHOLLOW_INITIAL_PASSWORD"))
    if first:
        pw, random_pw = first
        print("\n" + "=" * 64)
        print("  FIRST LOGIN (temporary, you must change it after signing in)")
        print("  Username : admin")
        print("  Password : %s" % (pw if random_pw else "(the one you set in DNSHOLLOW_INITIAL_PASSWORD)"))
        print("=" * 64 + "\n", flush=True)
        if random_pw:
            try:
                f = credentials_path(db.path)
                f.write_text("username: admin\ntemporary password: %s\n"
                             "(this file is deleted when you change the password)\n" % pw)
                f.chmod(0o600)
            except OSError:
                pass

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        tasks = []
        if scheduler:
            tasks = [asyncio.create_task(_profile_loop(app, "fast")),
                     asyncio.create_task(_profile_loop(app, "slow")),
                     asyncio.create_task(_purge_loop(app))]
        yield
        for t in tasks:
            t.cancel()

    # /docs, /redoc and /openapi.json are on by default for the lab.
    # Set DNSHOLLOW_DOCS=0 to switch them off in real deployments.
    docs_on = docs if docs is not None else os.environ.get("DNSHOLLOW_DOCS", "1") != "0"
    app = FastAPI(title="DNSHollow", version="0.5.0", lifespan=lifespan,
                  docs_url="/docs" if docs_on else None,
                  redoc_url="/redoc" if docs_on else None,
                  openapi_url="/openapi.json" if docs_on else None)
    app.state.db = db
    app.state.store = store
    app.state.limiter = RateLimiter()
    app.state.login_limiter = FailLimiter()
    app.state.enroll_limiter = FailLimiter(limit=10)
    app.state.bundle = BundleCache()
    app.state.engine = {}            # profile -> last run info (dashboard shows it)
    app.state.scheduler_on = scheduler
    app.state.sessions = {}          # hashed session token -> {uid, epoch, exp}
    app.state.admin_hash = db.get_meta("admin_key_hash")

    app.include_router(agent_router)
    app.include_router(admin_router)
    app.include_router(alert_router)
    app.include_router(block_router)
    app.include_router(install_router)
    app.include_router(log_router)
    app.include_router(dashboard_router)
    app.mount("/static", StaticFiles(directory=str(DASH_DIR / "static")), name="static")

    @app.get("/api/v1/health", tags=["health"])
    def health():
        return {"status": "ok", "time": time.time()}

    return app
