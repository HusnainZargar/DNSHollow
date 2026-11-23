# DNSHollow

A centralized, multi-signal DNS tunneling detection system.
Lightweight **Linux and Windows** agents capture real DNS traffic and send metadata to one manager.
The manager can also **block** a domain on the machines (by hand, or automatically above a score you choose).
The manager scores every (host, domain) pair with 7 signals, 24/7, and shows explainable alerts in a web dashboard.

```
Linux / Windows agent ──(JSON over HTTP)──▶ Manager (API + engine + SQLite + dashboard)
 raw capture, all interfaces            fast profile  (5 min window)  → noisy tunnels
 pairs query + response                 slow profile  (24 h window)   → stealthy tunnels
 spools to disk if manager is down      alerts + evidence + campaigns
```

## Quick start

**1. Manager** (any Linux machine with Python 3.8+)

```bash
bash run.sh                          # sets everything up and starts it
sudo bash run.sh --install-service   # optional: run 24/7, start at boot
```

**2. Sign in.** The first start prints a **temporary login** (username `admin`) in the terminal and saves it in
`data/initial-credentials.txt`. Open the dashboard, sign in, and you are asked to choose your own password
before anything else.

> **First time here?** Use the temporary login printed in the terminal where the manager started (also saved in
> `data/initial-credentials.txt`). You will be asked to choose your own password.
>
> **Forgot your password?** On the manager machine run `sudo bash run.sh --reset-password`. It prints a new temporary
> password, and you choose your own at the next sign-in. (This help is only here, it is not shown in the dashboard.)

**3. Add an agent**: **Agents** page → type a name → copy the install command →
run it as root on the Linux machine you want to monitor. It downloads the agent from the manager,
checks its SHA-256, registers with a one-time token, runs a self-check and installs a systemd service
(runs as a normal user with only `CAP_NET_RAW`, restarts on crash, starts at boot).
Use the manager's **LAN address** in the command (not `localhost`).
Remove an agent: `curl -fsSL http://MANAGER:8000/install/linux.sh | sudo bash -s -- --uninstall`

**3b. Windows agent**: on the **Agents** page pick the **Windows** tab and copy the PowerShell command. Run it in an
**Administrator PowerShell**. Needs **Python 3.8+ installed for all users** (`winget install -e --id Python.Python.3.12 --scope machine`).
It downloads the agent, checks its SHA-256, registers with the one-time token, runs a self-check (including a real test DNS
lookup) and creates a Scheduled Task that runs as SYSTEM at boot and restarts on a crash. Log: `C:\ProgramData\DNSHollow\agent.log`.
Remove: same command with `-Uninstall` instead of `-Server/-Token/-Sha256` (keep `-Server`).

**4. Watch**: Overview → Alerts. The engine already runs by itself, 24/7. **Check now** only forces an immediate run.

## Blocking DNS

| Where | What |
|---|---|
| **Alert → "Block on this computer / all computers"** | one click, from the alert panel |
| **Blocks page** | block any domain by hand (one computer or all, for 1 h / 24 h / 7 d / until removed), see what is blocked, unblock |
| **Settings → Blocking** | master switch, **auto-block** on/off, score level (default 90), scope (one computer / all), duration (default 24 h) |

How it works: the manager keeps the block list. Agents installed **with blocking enabled** (the install command has it ticked by default;
`--enable-blocking` on Linux, `-EnableBlocking` on Windows) fetch their list on the heartbeat (and within seconds when it changes) and make the
machine drop DNS for the domain **and all its subdomains**. The dashboard shows per agent whether it is enforcing or why it cannot.

| OS | Method | Needs |
|---|---|---|
| Linux | own iptables chain `DNSHOLLOW` (jumped to from `OUTPUT`); drops port-53 packets that contain the domain name. IPv4 + IPv6 | `CAP_NET_ADMIN` (added to the service by `--enable-blocking`), `iptables` + `iptables-restore` |
| Windows | NRPT rules (comment `DNSHollow`) send the domain to a dead resolver (127.0.0.1) so it never resolves | Administrator / SYSTEM |

Safety rules: only registered domains can be blocked (never `com` or `co.uk`, never an IP), trusted domains and the manager's own address are
never blocked, auto-block only acts on alerts nobody has reviewed, and **Not a threat**, **Trust this domain** and **Unblock** lift blocks
(Unblock also marks the open alert "looking into it" so auto-block does not re-block it). Timed blocks expire by themselves. Rules stay in
place if the manager is unreachable; the uninstallers remove them (`python -m dnshollow_agent --unblock-all` does it by hand).

Limits: software that talks straight to its own DNS server bypasses the **Windows** method (NRPT only governs the system resolver); a
Windows Group Policy NRPT overrides local rules; DNS over HTTPS/TLS is invisible to both methods; Linux matching can miss names split over
several TCP segments. Dropped queries never reach the agent's capture, so a blocked tunnel simply goes quiet and its alert expires.

## Testing with fake traffic

`tools/fake_dns_traffic.py` sends made-up DNS queries to the manager (no real tunnel needed), at different danger levels:

```bash
# the admin key is the DNSHOLLOW_ADMIN_KEY the manager was started with
python3 tools/fake_dns_traffic.py all  --server http://127.0.0.1:8000 --admin-key YOUR_KEY
python3 tools/fake_dns_traffic.py high --server http://127.0.0.1:8000 --admin-key YOUR_KEY --loop 120   # keep it alive
```

| Level | What it imitates | You should see |
|---|---|---|
| `benign` | normal browsing | nothing |
| `low` | busy hash-named CDN, A records | Low alert (~45) |
| `medium` | TXT-heavy, fairly regular | Medium alert (~69) |
| `high` | noisy tunnel (iodine / dnscat2) | High alert (~85) |
| `critical` | everything wrong at once | High, score 100 (passes the default auto-block level 90) |
| `slow` | stealth beacon, 1 query / ~22 min | alert from the slow profile (up to 5 min) |
| `campaign` | one bad domain from 3 computers | 3 High alerts + a Campaign card |
| `all` | all of the above, spread over 3 fake computers | everything |

It creates the test agents `sim-linux`, `sim-windows`, `sim-extra` and saves their keys in `.fake-dns-keys.json` for the next run.
Use `--dry-run` to see what would be sent. To test **auto-block**: Settings > Blocking > turn on auto-block, then send `critical`.
To test **manual block**: open any alert from `high` and click Block. Fake agents cannot enforce blocks (they are not real agents),
so the block shows up on the Blocks page but nothing is dropped. For a real enforcement test, use a real Linux/Windows agent.
The levels are checked by `tests/test_fake_traffic.py`, so an engine change that moves them shows up as a failing test.

## The dashboard

| Page | What it is for |
|---|---|
| Overview | status banner, getting-started steps, alert counts, campaigns, engine status |
| Alerts | plain-language alert cards. Click one for a **short view** (what happened, what to do), then **Show detailed view** (score breakdown, timeline, sample requests) |
| Agents | add Linux or Windows agents, copy install commands, see who is online and whether blocking works. Click one for short then detailed view |
| Blocks | block / unblock domains, see what is blocked where and why, recent history |
| Logs | **DNS requests** the agents sent (search, filters, live), **agent activity**, and the **audit trail** (who signed in, who changed what) |
| Settings | one-click sensitivity (Relaxed / Balanced / Strict), trusted domains, both detection checks, clue weights and thresholds, agent options, retention |
| My account | change password, sign out |

A **Help & glossary** panel explains every term. Passwords are stored as salted PBKDF2 hashes; sessions are
HttpOnly + SameSite=Strict cookies; failed sign-ins are rate-limited. Scripts can still use the API with the
`X-Admin-Key` header (key in `data/admin.key`).

## What it looks at

| Signal | Idea |
|---|---|
| Entropy | random-looking subdomains (base32/64) |
| Subdomain depth | unusually deep label chains |
| Record types | many TXT / NULL / CNAME / MX |
| Query rate | many queries to one domain per minute |
| Beacon timing | machine-like regular intervals |
| Unique subdomains | the set of names keeps growing |
| Data volume | characters of data carried in subdomains |

Each signal gives a strength 0–1, weights are auto-balanced to 100%, score = 0–100.
Every alert lists the evidence behind the score. All settings (weights, thresholds, windows, trusted domains)
are edited in the dashboard **Settings** page. Trusted domains are skipped completely.

## Windows agent facts

- Standard library only, no driver, no Npcap: one raw IPv4 socket per local address (`SIO_RCVALL`), rescanned every 30 s (VPN / new Wi-Fi are picked up).
- **IPv4 only** (Windows raw sockets cannot sniff IPv6). No kernel filter, so Python drops non-DNS packets itself; fine on a workstation.
- Direction comes from the source address (Windows gives no in/out flag). `--check` does a real lookup of a random `.invalid` name and confirms the query was seen leaving.

## Agent facts

- One raw socket on **all interfaces** with a kernel filter: only UDP/TCP port 53 reaches Python.
- Queries sent **by this machine** only. Traffic to **loopback** resolvers (127.0.0.53) is ignored so each query is counted once, on the wire.
- Each DNS transaction becomes one record: name, type, **resolver IP**, protocol, query bytes, response bytes, response code. No answer content is stored.
- Manager down? Batches wait in `/var/lib/dnshollow` (size-capped, oldest dropped first) and are resent with the same batch id.
- Limits: DNS over HTTPS/TLS is not visible; DNS messages split over several TCP segments or IP fragments are skipped.

## Tests

```bash
pip install -r requirements-dev.txt
pytest                      # real-capture tests run only as root (they use raw sockets)
bash tests/ui/run.sh        # optional: drives the real dashboard in a simulated browser (needs node)
```

## Layout

```
agent/dnshollow_agent/   the agent for Linux and Windows (standard library only; blocker.py = block DNS, capture_win.py = Windows capture)
manager/api/             REST API   (docs at /docs; set DNSHOLLOW_DOCS=0 to hide)
manager/engine/          features, scorer, runner
manager/dashboard/       the web dashboard (plain HTML/CSS/JS, no libraries)
manager/dist/            installer scripts served to agents (install-linux.sh, install-windows.ps1)
tools/                   demos and a fake-agent simulator
```
