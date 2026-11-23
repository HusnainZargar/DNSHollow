#!/usr/bin/env bash
# Browser-like smoke test of the dashboard (needs node 18+ and internet for `npm install jsdom`).
#   bash tests/ui/run.sh
# Starts a throw-away manager, seeds fake + hostile data, then drives the real dashboard code
# through login, password change, every page, and checks that hostile domain names stay plain text.
set -euo pipefail
cd "$(dirname "$0")/../.."
WORK="$(mktemp -d)"; trap 'kill "$PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT
cp tests/ui/ui_test.js "$WORK/"; ( cd "$WORK" && npm init -y >/dev/null 2>&1 && npm install jsdom >/dev/null 2>&1 )
PY="${PYTHON:-$( [ -x venv/bin/python ] && echo venv/bin/python || echo python3 )}"
DNSHOLLOW_DB="$WORK/ui.db" DNSHOLLOW_INITIAL_PASSWORD=Temp-pass-1 DNSHOLLOW_ADMIN_KEY=k DNSHOLLOW_PW_ITERATIONS=1000 \
  "$PY" -m uvicorn manager.api.main:create_app --factory --port 8790 >"$WORK/server.log" 2>&1 & PID=$!
for _ in $(seq 1 40); do curl -fs localhost:8790/api/v1/health >/dev/null 2>&1 && break; sleep 0.5; done
"$PY" tests/ui/seed.py >/dev/null
( cd "$WORK" && node ui_test.js )
