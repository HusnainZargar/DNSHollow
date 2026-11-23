#!/usr/bin/env bash
# DNSHollow Linux agent installer (served by the manager at /install/linux.sh).
#
#   Install : curl -fsSL http://MANAGER:8000/install/linux.sh | sudo bash -s -- \
#               --server http://MANAGER:8000 --token TOKEN --sha256 HASH
#   Remove  : curl -fsSL http://MANAGER:8000/install/linux.sh | sudo bash -s -- --uninstall
#
# Options: --insecure (self-signed HTTPS)   --no-service (install files only)
#          --enable-blocking (let the manager block DNS on this machine: adds CAP_NET_ADMIN to the
#                             service, which is what changing firewall rules needs)
set -euo pipefail

APP_DIR=/opt/dnshollow-agent
CONF_DIR=/etc/dnshollow
CONF="$CONF_DIR/agent.json"
STATE_DIR=/var/lib/dnshollow
SERVICE=dnshollow-agent
SVC_USER=dnshollow
UNIT="/etc/systemd/system/${SERVICE}.service"

SERVER=""; TOKEN=""; SHA=""; INSECURE=0; UNINSTALL=0; NO_SERVICE=0; BLOCKING=0

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --server)     [ $# -ge 2 ] || die "--server needs a value"; SERVER="${2%/}"; shift 2 ;;
    --token)      [ $# -ge 2 ] || die "--token needs a value";  TOKEN="$2"; shift 2 ;;
    --sha256)     [ $# -ge 2 ] || die "--sha256 needs a value"; SHA="$2"; shift 2 ;;
    --insecure)   INSECURE=1; shift ;;
    --no-service) NO_SERVICE=1; shift ;;
    --enable-blocking) BLOCKING=1; shift ;;
    --uninstall)  UNINSTALL=1; shift ;;
    *) die "Unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "Run as root (put 'sudo' before 'bash')."

# ---------------- uninstall ----------------
if [ "$UNINSTALL" -eq 1 ]; then
  say "Removing the DNSHollow agent"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$SERVICE" 2>/dev/null || true
  fi
  rm -f "$UNIT"
  if [ -d "$APP_DIR/dnshollow_agent" ] && command -v python3 >/dev/null 2>&1; then
    # take our DNS block rules out of the firewall (chain DNSHOLLOW)
    PYTHONPATH="$APP_DIR" python3 -m dnshollow_agent --unblock-all || warn "Could not remove the DNS block rules. Check: iptables -S DNSHOLLOW"
  fi
  if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload 2>/dev/null || true; fi
  rm -rf "$APP_DIR" "$CONF_DIR" "$STATE_DIR"
  if id "$SVC_USER" >/dev/null 2>&1; then userdel "$SVC_USER" 2>/dev/null || true; fi
  say "Done. (Delete the agent in the dashboard too if you no longer need it.)"
  exit 0
fi

# ---------------- checks ----------------
[ -n "$SERVER" ] || die "--server is required (the manager address, e.g. http://192.168.1.10:8000)"
if [ -z "$TOKEN" ] && [ ! -f "$CONF" ]; then die "--token is required for a first install (copy the command from the dashboard)"; fi
command -v python3 >/dev/null 2>&1 || die "python3 is required"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || die "Python 3.8 or newer is required"
if [ "$NO_SERVICE" -eq 0 ] && { ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; }; then
  die "systemd was not found. Re-run with --no-service to install the files only."
fi

fetch() {  # fetch URL OUTFILE
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    if [ "$INSECURE" -eq 1 ]; then curl -fsSLk -o "$out" "$url"; else curl -fsSL -o "$out" "$url"; fi
  elif command -v wget >/dev/null 2>&1; then
    if [ "$INSECURE" -eq 1 ]; then wget -q --no-check-certificate -O "$out" "$url"; else wget -q -O "$out" "$url"; fi
  else
    die "curl or wget is required"
  fi
}
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else die "sha256sum is required"; fi
}

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# ---------------- download + verify ----------------
say "Downloading the agent from $SERVER"
fetch "$SERVER/api/v1/agent/bundle.tar.gz" "$TMP/agent.tar.gz" || die "Cannot download the agent. Is $SERVER reachable from this machine?"
if [ -n "$SHA" ]; then
  GOT="$(sha256_of "$TMP/agent.tar.gz")"
  [ "$GOT" = "$SHA" ] || die "Checksum mismatch! Expected $SHA but got $GOT. The download was changed. Nothing was installed."
  say "Checksum OK"
else
  warn "No --sha256 given: the download was not verified."
fi

# ---------------- install ----------------
if ! id "$SVC_USER" >/dev/null 2>&1; then
  say "Creating the unprivileged user '$SVC_USER'"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
    || useradd --system --no-create-home --shell /sbin/nologin "$SVC_USER"
fi

if [ "$NO_SERVICE" -eq 0 ] && systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
  say "Stopping the running agent (upgrade)"
  systemctl stop "$SERVICE"
fi

say "Installing to $APP_DIR"
mkdir -p "$APP_DIR"
rm -rf "$APP_DIR/dnshollow_agent"
tar -xzf "$TMP/agent.tar.gz" --no-same-owner -C "$APP_DIR"
chown -R root:root "$APP_DIR"; chmod -R go-w "$APP_DIR"

mkdir -p "$STATE_DIR"; chown "$SVC_USER":"$SVC_USER" "$STATE_DIR"; chmod 700 "$STATE_DIR"
mkdir -p "$CONF_DIR"

if [ -n "$TOKEN" ]; then
  say "Registering this machine with the manager"
  DH_SERVER="$SERVER" DH_TOKEN="$TOKEN" DH_INSECURE="$INSECURE" DH_BLOCK="$BLOCKING" DH_OUT="$CONF" python3 - <<'PY'
import json, os, platform, ssl, sys, urllib.error, urllib.request
server = os.environ["DH_SERVER"]
insecure = os.environ["DH_INSECURE"] == "1"
body = json.dumps({"token": os.environ["DH_TOKEN"],
                   "os": ("%s %s" % (platform.system(), platform.release()))[:64]}).encode()
req = urllib.request.Request(server + "/api/v1/agent/enroll", data=body,
                             headers={"Content-Type": "application/json"})
ctx = ssl._create_unverified_context() if insecure else None
try:
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        d = json.loads(r.read())
except urllib.error.HTTPError as e:
    try:
        msg = json.loads(e.read()).get("detail")
    except Exception:
        msg = e.reason
    sys.exit("Registration failed: %s" % msg)
except Exception as e:
    sys.exit("Cannot reach the manager at %s: %s" % (server, e))
cfg = {"server": server, "api_key": d["api_key"], "name": d["name"], "verify_tls": not insecure,
       "allow_blocking": os.environ["DH_BLOCK"] == "1"}
fd = os.open(os.environ["DH_OUT"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(cfg, f, indent=2)
print("    registered as '%s'" % d["name"])
PY
fi
if [ -z "$TOKEN" ] && [ "$BLOCKING" -eq 1 ]; then      # upgrade: switch blocking on in the existing config
  DH_OUT="$CONF" python3 -c 'import json,os; p=os.environ["DH_OUT"]; d=json.load(open(p)); d["allow_blocking"]=True; json.dump(d, open(p,"w"), indent=2)'
fi
chown "root:$SVC_USER" "$CONF"; chmod 640 "$CONF"

PYBIN="$(command -v python3)"
say "Checking capture permission and the manager connection"
PYTHONPATH="$APP_DIR" "$PYBIN" -m dnshollow_agent --config "$CONF" --check \
  || die "The self-check failed (see above). Nothing is running yet."

if [ "$NO_SERVICE" -eq 1 ]; then
  say "Installed (no service). Start it with:"
  echo "    sudo PYTHONPATH=$APP_DIR $PYBIN -m dnshollow_agent --config $CONF"
  exit 0
fi

if [ "$BLOCKING" -eq 1 ] || grep -q '"allow_blocking": true' "$CONF" 2>/dev/null; then
  CAPS="CAP_NET_RAW CAP_NET_ADMIN"                       # NET_ADMIN = change firewall rules (blocking)
  FAMILIES="AF_INET AF_INET6 AF_PACKET AF_UNIX AF_NETLINK"
  XT_ENV="Environment=XTABLES_LOCKFILE=$STATE_DIR/xtables.lock"
  say "Blocking is enabled: the service also gets CAP_NET_ADMIN"
else
  CAPS="CAP_NET_RAW"; FAMILIES="AF_INET AF_INET6 AF_PACKET AF_UNIX"; XT_ENV=""
fi
say "Creating the systemd service (starts at boot, restarts on crash)"
cat > "$UNIT" <<UNITEOF
[Unit]
Description=DNSHollow DNS monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Environment=PYTHONPATH=$APP_DIR
Environment=PYTHONUNBUFFERED=1
$XT_ENV
ExecStart=$PYBIN -m dnshollow_agent --config $CONF
Restart=always
RestartSec=5
# only the privileges it needs: reading raw packets (+ firewall changes when blocking is enabled)
AmbientCapabilities=$CAPS
CapabilityBoundingSet=$CAPS
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$STATE_DIR
RestrictAddressFamilies=$FAMILIES

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable --now "$SERVICE"
sleep 3
if systemctl is-active --quiet "$SERVICE"; then
  say "The agent is running and will start at every boot."
  echo "    Status : systemctl status $SERVICE"
  echo "    Logs   : journalctl -u $SERVICE -f"
  echo "    Remove : curl -fsSL $SERVER/install/linux.sh | sudo bash -s -- --uninstall"
else
  journalctl -u "$SERVICE" -n 20 --no-pager 2>/dev/null || true
  die "The service did not start. See the log lines above."
fi
