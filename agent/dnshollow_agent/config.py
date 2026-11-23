import json
import os
from dataclasses import dataclass

WINDOWS = os.name == "nt"
_PD = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "DNSHollow")
DEFAULT_PATH = os.path.join(_PD, "agent.json") if WINDOWS else "/etc/dnshollow/agent.json"
DEFAULT_SPOOL = os.path.join(_PD, "spool") if WINDOWS else "/var/lib/dnshollow"


@dataclass
class AgentConfig:
    server: str
    api_key: str
    name: str = ""
    verify_tls: bool = True
    spool_dir: str = DEFAULT_SPOOL
    spool_max_mb: int = 50
    include_loopback: bool = False
    allow_blocking: bool = False       # set by the installer (--enable-blocking); the manager decides WHAT to block
    log_file: str = ""                 # empty = log to the console / journal


def load(path: str = "") -> AgentConfig:
    path = path or os.environ.get("DNSHOLLOW_AGENT_CONFIG", DEFAULT_PATH)
    with open(path, encoding="utf-8-sig") as f:       # utf-8-sig: a Windows editor may add a BOM
        d = json.load(f)
    if not d.get("server") or not d.get("api_key"):
        raise ValueError("config needs 'server' and 'api_key'")
    return AgentConfig(
        server=d["server"].rstrip("/"), api_key=d["api_key"], name=d.get("name", ""),
        verify_tls=bool(d.get("verify_tls", True)),
        spool_dir=d.get("spool_dir", DEFAULT_SPOOL),
        spool_max_mb=int(d.get("spool_max_mb", 50)),
        include_loopback=bool(d.get("include_loopback", False)),
        allow_blocking=bool(d.get("allow_blocking", False)),
        log_file=d.get("log_file", ""))
