#!/usr/bin/env bash
# DNSHollow manager: one command to set up and run.
#   ./run.sh                          start in the foreground
#   ./run.sh --port 9000              use another port
#   sudo ./run.sh --install-service   run 24/7 as a service (starts at boot)
#   ./run.sh --reset-password         forgot the password? get a new temporary one
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"; PORT=8000; HOST=0.0.0.0; SERVICE=0; RESET=0

while [ $# -gt 0 ]; do
  case "$1" in
    --port) [ $# -ge 2 ] || { echo "--port needs a value"; exit 1; }; PORT="$2"; shift 2 ;;
    --host) [ $# -ge 2 ] || { echo "--host needs a value"; exit 1; }; HOST="$2"; shift 2 ;;
    --install-service) SERVICE=1; shift ;;
    --reset-password) RESET=1; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
if [ ! -d venv ]; then echo "==> Creating virtual environment"; python3 -m venv venv; fi
if [ ! -f venv/.deps-ok ] || [ requirements.txt -nt venv/.deps-ok ]; then
  echo "==> Installing dependencies"
  venv/bin/pip install -q --upgrade pip
  venv/bin/pip install -q -r requirements.txt
  touch venv/.deps-ok
fi

mkdir -p data
if [ ! -f data/admin.key ]; then
  ( umask 077; venv/bin/python -c "import secrets; print('dh_admin_' + secrets.token_urlsafe(24))" > data/admin.key )
fi
export DNSHOLLOW_DB="$ROOT/data/dnshollow.db"
export DNSHOLLOW_ADMIN_KEY="$(cat data/admin.key)"
IP="$( (hostname -I 2>/dev/null || true) | awk '{print $1}')"; IP="${IP:-localhost}"

banner() {
  echo
  echo "  DNSHollow is ready"
  echo "  Dashboard : http://$IP:$PORT"
  if [ ! -f data/dnshollow.db ]; then
    echo "  First start: the temporary login is printed below, right after the server starts."
  elif [ -f data/initial-credentials.txt ]; then
    echo "  First time? Sign in with the temporary login below (also in data/initial-credentials.txt):"
    sed 's/^/    /' data/initial-credentials.txt | head -2
  else
    echo "  Sign in with your username and password.  Forgot it?  bash run.sh --reset-password"
  fi
  echo
}

if [ "$RESET" -eq 1 ]; then
  exec venv/bin/python -m manager.cli reset-password --db "$DNSHOLLOW_DB"
fi

if [ "$SERVICE" -eq 1 ]; then
  [ "$(id -u)" -eq 0 ] || { echo "Use sudo for --install-service"; exit 1; }
  RUN_USER="${SUDO_USER:-root}"
  chown -R "$RUN_USER" "$ROOT/data" "$ROOT/venv"
  cat > /etc/systemd/system/dnshollow-manager.service <<UNIT
[Unit]
Description=DNSHollow manager
After=network-online.target
Wants=network-online.target

[Service]
User=$RUN_USER
WorkingDirectory=$ROOT
ExecStart=$ROOT/run.sh --host $HOST --port $PORT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now dnshollow-manager
  banner
  echo "  Running as a service. Logs: journalctl -u dnshollow-manager -f"
  exit 0
fi

banner
# ONE worker on purpose: the 24/7 detection engine runs inside this process.
exec venv/bin/uvicorn manager.api.main:create_app --factory --host "$HOST" --port "$PORT"
