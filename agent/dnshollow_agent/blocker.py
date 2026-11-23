"""Block DNS for chosen domains on this machine. Standard library only.

The manager sends a list of domains. The agent makes the machine drop DNS for them
(the domain and every subdomain). Nothing is blocked unless the manager asks, and the
agent only touches rules it created itself.

Linux    iptables / ip6tables: our own chain DNSHOLLOW (jumped to from OUTPUT) drops port-53
         packets that contain the domain's name. Needs CAP_NET_ADMIN (or root).
Windows  NRPT (Name Resolution Policy Table): a DNS Client rule sends the domain to a dead
         resolver (127.0.0.1) so the name never resolves. Needs Administrator (the service
         runs as SYSTEM). Rules are tagged with the comment "DNSHollow".

Known limits (also shown in the README): software that talks straight to its own DNS server
and bypasses the system resolver is not stopped by the Windows method; DNS over HTTPS/TLS is
not visible to either method; Windows Group Policy NRPT rules take priority over local ones.
"""
import logging
import re
import shutil
import subprocess
import sys
from typing import Callable, List, Optional, Sequence, Tuple

log = logging.getLogger("dnshollow.blocker")

CHAIN = "DNSHOLLOW"
NRPT_COMMENT = "DNSHollow"
MAX_DOMAINS = 500
MAX_NAME = 120                      # iptables string match: patterns are limited to 128 bytes
_DOMAIN = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$")


class BlockerError(Exception):
    """Blocking failed. The message is reported to the manager and shown in the dashboard."""


def safe_domains(domains: Sequence[str], protect: Sequence[str] = ()) -> List[str]:
    """Keep only well-formed registered-style names, sorted and de-duplicated.

    Refuses anything that would cut the agent off from its manager or from a trusted
    domain: the manager's own name and trusted names are never blocked, and neither is
    a parent domain that contains them."""
    keep = set()
    prot = [p.lower().rstrip(".") for p in protect if p]
    for d in domains:
        d = str(d).strip().lower().rstrip(".")
        if not d or len(d) > MAX_NAME or not _DOMAIN.match(d):
            continue
        if any(p == d or p.endswith("." + d) or d.endswith("." + p) for p in prot):
            continue
        keep.add(d)
    return sorted(keep)[:MAX_DOMAINS]


def run_cmd(cmd: List[str], stdin: Optional[str] = None, timeout: float = 60.0) -> Tuple[int, str, str]:
    """-> (return code, stdout, stderr). Never raises for a missing program: returns 127."""
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "%s not found" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "%s timed out" % cmd[0]
    except OSError as e:
        return 126, "", str(e)


# ---------------------------------------------------------------- Linux

def wire_pattern(domain: str) -> bytes:
    """The domain as it appears inside a DNS packet: length-prefixed labels + the root byte."""
    out = b""
    for label in domain.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def hex_pattern(domain: str) -> str:
    """iptables --hex-string argument, e.g. '|04 65 76 69 6c 03 63 6f 6d 00|'."""
    return "|" + " ".join("%02x" % b for b in wire_pattern(domain)) + "|"


def restore_text(domains: Sequence[str], icase: bool = True) -> str:
    flag = " --icase" if icase else ""
    lines = ["*filter", "-F " + CHAIN]
    for d in domains:
        for proto in ("udp", "tcp"):
            lines.append('-A %s -p %s --dport 53 -m string --algo bm%s --hex-string "%s" -j DROP'
                         % (CHAIN, proto, flag, hex_pattern(d)))
    lines.append("COMMIT")
    return "\n".join(lines) + "\n"


class LinuxBlocker:
    method = "iptables"

    def __init__(self, run: Callable = run_cmd, which: Callable = shutil.which):
        self.run, self.which = run, which

    def _tools(self) -> List[str]:
        tools = []
        if self.which("iptables") and self.which("iptables-restore"):
            tools.append("iptables")
        if tools and self.which("ip6tables") and self.which("ip6tables-restore"):
            tools.append("ip6tables")         # IPv6 is best effort; IPv4 is required
        return tools

    def available(self) -> Tuple[bool, str]:
        if not self._tools():
            return False, "iptables and iptables-restore are not installed on this machine."
        rc, _o, err = self.run(["iptables", "-w", "-L", "OUTPUT", "-n"])
        if rc != 0:
            return False, "Not allowed to change firewall rules (%s). Reinstall the agent with blocking enabled." % (
                err.strip().splitlines()[0] if err.strip() else "iptables failed")
        return True, ""

    def _ensure_chain(self, tool: str) -> None:
        if self.run([tool, "-w", "-L", CHAIN, "-n"])[0] != 0:
            rc, _o, err = self.run([tool, "-w", "-N", CHAIN])
            if rc != 0:
                raise BlockerError("%s: cannot create chain: %s" % (tool, err.strip()[:200]))
        if self.run([tool, "-w", "-C", "OUTPUT", "-j", CHAIN])[0] != 0:
            rc, _o, err = self.run([tool, "-w", "-I", "OUTPUT", "1", "-j", CHAIN])
            if rc != 0:
                raise BlockerError("%s: cannot add the jump rule: %s" % (tool, err.strip()[:200]))

    def sync(self, domains: Sequence[str]) -> List[str]:
        tools = self._tools()
        if not tools:
            raise BlockerError("iptables is not installed on this machine.")
        for tool in tools:
            try:
                self._ensure_chain(tool)
                rc, _o, err = self.run([tool + "-restore", "--noflush"], restore_text(domains, True))
                if rc != 0 and "icase" in err.lower():          # very old kernels: case-sensitive match
                    rc, _o, err = self.run([tool + "-restore", "--noflush"], restore_text(domains, False))
                if rc != 0:
                    raise BlockerError("%s-restore failed: %s" % (tool, err.strip()[:200]))
            except BlockerError:
                if tool == "iptables":
                    raise
                log.warning("IPv6 blocking not applied (ip6tables failed)")
        return list(domains)

    def clear(self) -> None:
        """Remove everything this agent ever added to the firewall."""
        for tool in self._tools():
            for _ in range(20):                                   # bounded: remove duplicate jump rules
                if self.run([tool, "-w", "-D", "OUTPUT", "-j", CHAIN])[0] != 0:
                    break
            self.run([tool, "-w", "-F", CHAIN])
            self.run([tool, "-w", "-X", CHAIN])


# ---------------------------------------------------------------- Windows

def nrpt_namespaces(domains: Sequence[str]) -> List[str]:
    """'.evil.com' covers the subdomains, 'evil.com' covers the domain itself."""
    out = []
    for d in domains:
        out += ["." + d, d]
    return out


# A fixed script: the domain list is NOT pasted into it, it arrives on stdin, one name per line.
# (No quoting problems, and no command-line length limit however many domains there are.)
NRPT_SCRIPT = f"""$ErrorActionPreference = 'Stop'
try {{
  $raw = [Console]::In.ReadToEnd()
  $domains = @()
  if ($raw) {{ $domains = @($raw -split '\r?\n' | ForEach-Object {{ $_.Trim() }} | Where-Object {{ $_ }}) }}
  $want = @()
  foreach ($d in $domains) {{ $want += ('.' + $d); $want += [string]$d }}
  $mine = @(Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{NRPT_COMMENT}' }})
  foreach ($r in $mine) {{
    $ns = @($r.Namespace)
    if (-not ($ns | Where-Object {{ $want -contains $_ }})) {{ Remove-DnsClientNrptRule -Name $r.Name -Force }}
  }}
  $have = @(Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{NRPT_COMMENT}' }} | ForEach-Object {{ @($_.Namespace) }})
  foreach ($n in $want) {{
    if ($have -notcontains $n) {{ Add-DnsClientNrptRule -Namespace $n -NameServers '127.0.0.1' -Comment '{NRPT_COMMENT}' | Out-Null }}
  }}
  Clear-DnsClientCache
  Write-Output 'DNSHOLLOW_OK'
}} catch {{
  Write-Output ('DNSHOLLOW_ERR ' + $_.Exception.Message)
  exit 1
}}
"""


def encoded(script: str) -> str:
    import base64
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


class WindowsBlocker:
    method = "windows-nrpt"

    def __init__(self, run: Callable = run_cmd, which: Callable = shutil.which,
                 is_admin: Optional[Callable[[], bool]] = None, powershell: str = "powershell.exe"):
        self.run, self.which, self.powershell = run, which, powershell
        self._is_admin = is_admin or _windows_admin

    def available(self) -> Tuple[bool, str]:
        if not self.which(self.powershell):
            return False, "PowerShell was not found."
        if not self._is_admin():
            return False, "The agent must run as Administrator (or SYSTEM) to block DNS."
        return True, ""

    def _ps(self, domains: Sequence[str]) -> None:
        cmd = [self.powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-EncodedCommand", encoded(NRPT_SCRIPT)]
        rc, out, err = self.run(cmd, "\n".join(domains), 90.0)
        lines = (out or "").strip().splitlines()
        last = lines[-1].strip() if lines else ""
        if rc != 0 or last != "DNSHOLLOW_OK":
            msg = last[len("DNSHOLLOW_ERR "):] if last.startswith("DNSHOLLOW_ERR") else (err or out or "PowerShell failed")
            raise BlockerError("Windows DNS rule change failed: %s" % msg.strip()[:250])

    def sync(self, domains: Sequence[str]) -> List[str]:
        self._ps(domains)
        return list(domains)

    def clear(self) -> None:
        try:
            self._ps([])
        except BlockerError as e:
            log.warning("%s", e)


def _windows_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())      # type: ignore[attr-defined]
    except Exception:
        return False


def make_blocker():
    """The blocker for this operating system, or None when there is none."""
    if sys.platform.startswith("linux"):
        return LinuxBlocker()
    if sys.platform == "win32":
        return WindowsBlocker()
    return None
