'use strict';
/* DNSHollow dashboard. Rules that keep this file safe:
   - Domain names come from the network and can contain anything, so every value that goes
     into HTML passes through esc() or one of the helpers below.
   - A variable whose name ends in H already holds safe HTML. */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// ---------- words used all over the page (plain language) ----------
const SIG = {
  entropy: {name:'Random-looking names', unit:'bits', phrase:'random-looking names',
    what:'Tunnels hide data inside the domain name, so the name looks like a jumble of random letters and numbers.'},
  depth: {name:'Very long names', unit:'levels', phrase:'unusually long, nested names',
    what:'Tunnels often stack many parts in front of the domain (a.b.c.d.example.com).'},
  record_types: {name:'Unusual request types', unit:'% of requests', phrase:'unusual request types such as TXT or NULL', pct:true,
    what:'Normal browsing asks for A and AAAA records. TXT and NULL requests can carry hidden data.'},
  frequency: {name:'Request rate', unit:'requests per minute', phrase:'a high number of requests',
    what:'Tunnels often send many requests to one domain in a short time.'},
  timing: {name:'Steady rhythm', unit:'variation (lower = steadier)', phrase:'a steady, machine-like rhythm',
    what:'Malware often "calls home" at regular intervals, like a heartbeat. Humans are not that regular.'},
  unique_subdomains: {name:'Many different names', unit:'different names', phrase:'a growing list of different names',
    what:'A tunnel keeps inventing new names, because each one carries new data.'},
  data_volume: {name:'Hidden data amount', unit:'characters', phrase:'a lot of text packed into the names',
    what:'How much text is packed into the names. Normal sites send very little.'},
};
const RCODES = {0:'OK', 1:'Format error', 2:'Server failure', 3:'Name not found', 4:'Not implemented', 5:'Refused'};
const SEV = {high:'High', medium:'Medium', low:'Low'};
const SEVRANK = {high:3, medium:2, low:1};
const STATUS = {open:'Open', ack:'Acknowledged', false_positive:'False positive', expired:'Expired'};
const ACTIONS = {login:'Signed in', login_failed:'Failed sign-in', logout:'Signed out', password_changed:'Changed password',
  password_change_failed:'Failed password change', password_reset_cli:'Password reset (terminal)', first_user_created:'First user created',
  agent_created:'Agent created', agent_enabled:'Agent enabled', agent_disabled:'Agent disabled', agent_enrolled:'Agent installed',
  agent_key_rotated:'Agent key replaced', install_command_created:'Install command created', settings_changed:'Settings changed',
  settings_replaced:'Settings replaced', settings_reset:'Settings reset', preset_applied:'Sensitivity preset applied',
  alert_ack:'Alert acknowledged', alert_open:'Alert re-opened', alert_false_positive:'Marked false positive', domain_trusted:'Domain trusted',
  block_added:'DNS blocked', block_removed:'DNS unblocked', auto_block:'Auto-blocked'};

// ---------- small HTML helpers (all return safe HTML) ----------
const ICONS = {
  overview:'<path d="M3 3h8v8H3zM13 3h8v5h-8zM13 11h8v10h-8zM3 14h8v7H3z"/>',
  alerts:'<path d="M12 3a6 6 0 0 0-6 6v4l-2 3h16l-2-3V9a6 6 0 0 0-6-6zM10 19a2 2 0 0 0 4 0"/>',
  agents:'<path d="M3 4h18v6H3zM3 14h18v6H3zM7 7h.01M7 17h.01"/>',
  logs:'<path d="M4 6h16M4 12h16M4 18h10"/>',
  settings:'<path d="M4 7h9M17 7h3M4 17h3M11 17h9M15 5v4M9 15v4"/>',
  account:'<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  blocks:'<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
  help:'<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .8-1 1.5M12 17h.01"/>',
  ok:'<circle cx="12" cy="12" r="9"/><path d="M8 12.5l3 3 5-6"/>',
  warn:'<path d="M12 3l10 18H2zM12 10v5M12 18h.01"/>',
  info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/>',
};
const icon = n => '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' + (ICONS[n] || '') + '</svg>';
const pill = (txt, cls) => `<span class="pill ${esc(cls)}">${esc(txt)}</span>`;
const sevB = s => pill(SEV[s] || s, s);
const statusPill = s => pill(STATUS[s] || s, s === 'open' ? 'info' : 'off');
const bar = (p, cls) => `<div class="bar ${esc(cls || '')}"><i style="width:${esc(Math.round(Math.max(0, Math.min(1, +p || 0)) * 100))}%"></i></div>`;
const help = t => `<span class="tip" tabindex="0" data-tip="${esc(t)}">?</span>`;
const empty = (title, text) => `<div class="empty"><b>${esc(title)}</b>${esc(text)}</div>`;
function spark(counts) {
  const W = 300, H = 60, n = counts.length, mx = Math.max(1, ...counts), bw = W / n; let r = '';
  counts.forEach((c, i) => { const h = Math.round(c / mx * (H - 4)); r += '<rect x="' + (i * bw + 1).toFixed(1) + '" y="' + (H - h) + '" width="' + (bw - 2).toFixed(1) + '" height="' + h + '" rx="1"/>'; });
  return '<svg class="spark" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" role="img" aria-label="Requests over time">' + r + '</svg>';
}
const fmtTime = ts => ts ? new Date(ts * 1000).toLocaleString() : '—';
const ago = ts => { if (!ts) return 'never'; const s = Math.max(0, Date.now() / 1000 - ts);
  return s < 5 ? 'just now' : s < 60 ? Math.floor(s) + 's ago' : s < 3600 ? Math.floor(s / 60) + ' min ago' : s < 86400 ? Math.floor(s / 3600) + ' h ago' : Math.floor(s / 86400) + ' d ago'; };
const dur = s => s < 120 ? Math.round(s) + ' seconds' : s < 7200 ? Math.round(s / 60) + ' minutes' : s < 172800 ? Math.round(s / 3600) + ' hours' : Math.round(s / 86400) + ' days';
const bytes = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
const num = n => Number(n || 0).toLocaleString();
function toast(msg, bad) { const t = $('#toast'); t.textContent = msg; t.className = bad ? 'show bad' : 'show';
  clearTimeout(toast.t); toast.t = setTimeout(() => t.className = '', 4500); }

// ---------- talking to the server ----------
let me = null, view = 'overview', timer = null;
const A = {};   // alerts by id (cache for the drawer)

function errText(d, st) { const det = d && d.detail; if (det && det.errors) return det.errors.join(' '); if (det && det.message) return det.message;
  return typeof det === 'string' ? det : 'Something went wrong (' + st + ').'; }
async function api(path, method = 'GET', body) {
  const r = await fetch('/api/v1' + path, {method, credentials: 'same-origin', headers: {'Content-Type': 'application/json'},
    body: body === undefined ? undefined : JSON.stringify(body)});
  const d = await r.json().catch(() => ({}));
  if (r.status === 401 && !path.startsWith('/session')) { showScreen('login'); throw new Error('auth'); }
  if (r.status === 403 && d.detail && d.detail.code === 'password_change_required') { start(); throw new Error('auth'); }
  if (!r.ok) throw new Error(errText(d, r.status));
  return d;
}
const guard = fn => async (...a) => { try { return await fn(...a); } catch (e) { if (e.message !== 'auth') toast(e.message, true); } };

// ---------- screens: sign in / change password / app ----------
function showScreen(name) {
  clearTimeout(timer); closeDrawer();
  $('#screen-login').classList.toggle('hide', name !== 'login');
  $('#screen-change').classList.toggle('hide', name !== 'change');
  $('#app').classList.toggle('hide', name !== 'app');
  if (name === 'login') { $('#lp').value = ''; setTimeout(() => $('#lu').focus(), 0); }
}

function pwFormH(prefix) {
  return `<form class="pwform" data-p="${esc(prefix)}" autocomplete="off">
    <label>Current password<input data-f="cur" type="password" autocomplete="current-password" required></label>
    <label>New password<input data-f="new" type="password" autocomplete="new-password" required></label>
    <label>Type the new password again<input data-f="new2" type="password" autocomplete="new-password" required></label>
    <ul class="rules"><li data-r="len">At least 10 characters</li><li data-r="same">Both new passwords match</li>
    <li data-r="diff">Different from the current password</li><li data-r="user">Does not contain your username</li></ul>
    <button class="btn p" data-f="go">Save new password</button><p class="err" data-f="err" role="alert"></p></form>`;
}
function bindPwForm(root, onDone) {
  const f = k => $('[data-f="' + k + '"]', root);
  const check = () => {
    const n = f('new').value, c = f('cur').value, u = (me && me.username || '').toLowerCase();
    const ok = {len: n.length >= 10, same: n.length > 0 && n === f('new2').value, diff: n.length > 0 && n !== c, user: !u || !n.toLowerCase().includes(u)};
    $$('[data-r]', root).forEach(li => li.classList.toggle('good', ok[li.dataset.r]));
    return Object.values(ok).every(Boolean);
  };
  $$('input', root).forEach(i => i.addEventListener('input', check));
  root.addEventListener('submit', async e => {
    e.preventDefault(); f('err').textContent = '';
    if (!check()) { f('err').textContent = 'Please meet all the rules above.'; return; }
    f('go').disabled = true;
    try { await api('/account/password', 'POST', {current_password: f('cur').value, new_password: f('new').value});
      $$('input', root).forEach(i => i.value = ''); check(); await onDone(); }
    catch (er) { if (er.message !== 'auth') f('err').textContent = er.message; }
    f('go').disabled = false;
  });
}

$('#lf').addEventListener('submit', async e => {
  e.preventDefault(); $('#lerr').textContent = '';
  try { await api('/session', 'POST', {username: $('#lu').value.trim(), password: $('#lp').value}); start(); }
  catch (er) { $('#lerr').textContent = er.message; $('#lp').value = ''; }
});
$('#force-out').addEventListener('click', signOut);
async function signOut() { await fetch('/api/v1/session', {method: 'DELETE', credentials: 'same-origin'}); me = null; showScreen('login'); }

async function start() {
  let s;
  try { s = await api('/session'); } catch (e) { return showScreen('login'); }
  me = s;
  if (s.must_change) {
    $('#force-form').innerHTML = pwFormH('force'); bindPwForm($('#force-form .pwform'), async () => { toast('Password changed. Welcome!'); await start(); });
    showScreen('change'); return;
  }
  $('#who-name').textContent = s.username; $('#avatar').textContent = s.username.slice(0, 1).toUpperCase();
  buildNav(); showScreen('app'); route();
}

// ---------- navigation ----------
const VIEWS = {
  overview: ['Overview', 'A quick look at what is happening on your network right now.'],
  alerts: ['Alerts', 'DNS activity that looks like tunneling. Click an alert to see why.'],
  agents: ['Agents', 'Small programs on your Linux and Windows machines. They watch DNS and report to this dashboard.'],
  blocks: ['Blocks', 'Domains whose DNS is blocked on your machines. Block by hand, or let DNSHollow do it automatically.'],
  logs: ['Logs', 'Everything the agents sent, and what people did in the dashboard.'],
  settings: ['Settings', 'Choose how sensitive detection is. Changes apply within a few seconds.'],
  account: ['My account', 'Your sign-in details.'],
};
function buildNav() {
  $('#nav').innerHTML = ['overview', 'alerts', 'agents', 'blocks', 'logs', 'settings', 'account'].map(v =>
    `<a href="#${esc(v)}" data-v="${esc(v)}">${icon(v)}<span>${esc(VIEWS[v][0])}</span><span class="cnt hide" data-cnt="${esc(v)}"></span></a>`).join('');
  $('#help-btn').innerHTML = icon('help') + '<span>Help &amp; glossary</span>';
}
function route() {
  view = (location.hash || '#overview').slice(1); if (!VIEWS[view]) view = 'overview';
  $$('main > section').forEach(s => s.classList.toggle('hide', s.id !== 'v-' + view));
  $$('#nav a').forEach(a => a.classList.toggle('on', a.dataset.v === view));
  $('#title').textContent = VIEWS[view][0]; $('#subtitle').textContent = VIEWS[view][1];
  $('#run').classList.toggle('hide', view !== 'overview');
  built[view] = false; closeDrawer(); load();
}
const built = {};
async function load() {
  clearTimeout(timer);
  try { await views[view](); } catch (e) { if (e.message !== 'auth') toast(e.message, true); return; }
  if (view !== 'overview') api('/stats').then(setBadge).catch(() => {});      // keep the alert counter fresh
  const every = {overview: 10000, alerts: 10000, agents: 10000, blocks: 10000, logs: LOGS.live ? 5000 : 0}[view];
  if (every) timer = setTimeout(load, every);
}

// ---------- drawer ----------
function openDrawer(html) { $('#drawer').innerHTML = '<button class="x" data-act="close" aria-label="Close">×</button>' + html;
  $('#drawer').classList.remove('hide'); $('#scrim').classList.remove('hide'); $('#drawer').scrollTop = 0; }
function closeDrawer() { $('#drawer').classList.add('hide'); $('#scrim').classList.add('hide'); }

// ---------- alerts: plain-language pieces ----------
const reasonsOf = a => a.signals.filter(s => s.strength >= 0.5 && s.points > 0).slice(0, 3).map(s => SIG[s.name] ? SIG[s.name].phrase : s.label);
const titleOf = a => a.severity === 'low' ? 'Suspicious DNS activity' : 'Possible DNS tunnel';
const joinWords = l => l.length < 2 ? l.join('') : l.slice(0, -1).join(', ') + ' and ' + l[l.length - 1];

function alertCardH(a) {
  A[a.id] = a;
  const why = reasonsOf(a), whyText = why.length ? 'Shows ' + joinWords(why) + '.' : 'Several small signs add up.';
  const statusH = (a.status === 'open' ? '' : statusPill(a.status)) + ((a.blocks || []).length ? ' ' + pill('Blocked', 'bad') : '');
  return `<div class="acard ${esc(a.severity)}${esc(a.status === 'open' ? '' : ' done')}" data-alert="${esc(a.id)}" tabindex="0">
    <div><span class="t">${esc(titleOf(a))}</span> ${sevB(a.severity)} ${statusH}</div>
    <div class="sc"><b>${esc(a.score)}</b><br><span class="mut">of 100</span></div>
    <div class="meta"><span class="dom">${esc(a.parent)}</span> · from <b>${esc(a.host)}</b> · ${esc(ago(a.last_seen))}</div>
    <div class="why">${esc(whyText)}</div></div>`;
}
const sortAlerts = l => l.slice().sort((a, b) => SEVRANK[b.severity] - SEVRANK[a.severity] || b.last_seen - a.last_seen);

// ---------- overview ----------
function engineInfo(e) {
  if (!e.scheduler) return {state: 'Off', cls: 'bad', text: 'The background engine is switched off.'};
  const now = Date.now() / 1000, parts = []; let state = 'Running', cls = 'ok';
  Object.keys(e.profiles).forEach(n => { const p = e.profiles[n]; if (!p.enabled) return;
    if (!p.last_run) { parts.push(n + ': starting'); if (state === 'Running') { state = 'Starting'; cls = 'warn'; } return; }
    if (p.ok === false || now - p.last_run > 3 * p.run_every + 30) { state = 'Stalled'; cls = 'bad'; }
    parts.push(n + ': ' + ago(p.last_run)); });
  return {state, cls, text: 'Checks all traffic by itself. Last run — ' + parts.join(', ')};
}
function bannerH(st) {
  const o = st.alerts_open, n = o.high + o.medium + o.low; let cls, ic, head, text;
  if (st.agents.total === 0) { cls = 'info'; ic = 'info'; head = 'Welcome! Add your first agent to get started.'; text = 'An agent is a small program that watches DNS on one Linux machine. Open the Agents page to add one.'; }
  else if (o.high > 0) { cls = 'bad'; ic = 'warn'; head = o.high + (o.high > 1 ? ' high-severity alerts need' : ' high-severity alert needs') + ' your attention.'; text = 'These look like real DNS tunnels. Open an alert to see why.'; }
  else if (n > 0) { cls = 'warn'; ic = 'warn'; head = n + (n > 1 ? ' alerts' : ' alert') + ' to review.'; text = 'Nothing critical, but worth a look.'; }
  else if (st.agents.online === 0) { cls = 'warn'; ic = 'warn'; head = 'No agent is online right now.'; text = 'Detection only works while agents are running. Check the Agents page.'; }
  else { cls = 'ok'; ic = 'ok'; head = 'All clear. No suspicious DNS activity.'; text = 'Agents are reporting and nothing looks like a tunnel.'; }
  return '<div class="banner ' + cls + '">' + icon(ic) + '<div><b>' + esc(head) + '</b><span>' + esc(text) + '</span></div></div>';
}
function setBadge(st) { const c = st.alerts_open.high + st.alerts_open.medium; const el = $('[data-cnt="alerts"]');
  if (el) { el.textContent = c; el.classList.toggle('hide', c === 0); } }

async function vOverview() {
  const [st, al, ca, ba, bk] = await Promise.all([api('/stats'), api('/alerts?status=open&limit=100'), api('/campaigns'), api('/logs/batches?limit=6'), api('/blocks')]);
  setBadge(st);
  const open = sortAlerts(al.items), o = st.alerts_open, eng = engineInfo(st.engine);
  const todo = [[st.agents.total > 0, 'Add your first agent', 'Open the Agents page, type a name, and copy the install command.'],
    [st.agents.online > 0, 'Run the command on a Linux machine', 'Paste it into a terminal as root. The agent shows as online within a minute.'],
    [st.queries_last_hour > 0, 'Wait for DNS data', 'Use the machine as usual. Requests appear on the Logs page.']];
  const stepsH = todo.map((s, i) => `<li class="${esc(s[0] ? 'done' : '')}"><span class="n">${esc(s[0] ? '✓' : i + 1)}</span><div><b>${esc(s[1])}</b><br><span class="mut">${esc(s[2])}</span></div></li>`).join('');
  const startH = todo.every(s => s[0]) ? '' : `<div class="card"><h3>Getting started</h3><ol class="steps">${stepsH}</ol></div>`;
  const alertsH = open.length ? '<div class="alist">' + open.slice(0, 5).map(alertCardH).join('') + '</div>' +
    (open.length > 5 ? '<p><a href="#alerts">See all ' + esc(open.length) + ' open alerts</a></p>' : '')
    : empty('No open alerts', 'When something looks like a DNS tunnel it will show up here.');
  const campH = ca.length ? ca.map(c => `<p><span class="dom">${esc(c.parent)}</span><br><span class="mut">${esc(c.hosts)} computers: ${esc(c.host_list.join(', '))} · highest score ${esc(c.max_score)}</span></p>`).join('')
    : '<p class="mut">None. A campaign means several computers contact the same suspicious domain, which is a stronger warning sign.</p>';
  const actH = ba.items.length ? ba.items.map(b => `<p>${esc(b.agent || 'agent')} sent <b>${esc(num(b.accepted))}</b> requests <span class="mut">· ${esc(ago(b.received_at))}</span></p>`).join('')
    : '<p class="mut">Nothing received yet.</p>';
  const blkOnH = bk.enabled ? pill('On', 'ok') : pill('Off', 'off');
  const blkAutoH = bk.auto.auto_block ? pill('on at score ' + bk.auto.auto_min_score, 'bad') : pill('off', 'off');
  const agentCls = st.agents.total && st.agents.online === st.agents.total ? 'ok' : st.agents.total ? 'warn' : '';
  $('#v-overview').innerHTML = bannerH(st) + startH + `<div class="kpis">
    <div class="card kpi"><div class="l">Open alerts ${help('Alerts that nobody has reviewed yet. High = most likely a real tunnel.')}</div><div class="v">${esc(o.high + o.medium + o.low)}</div>
      <div class="s">${sevB('high')} ${esc(o.high)} ${sevB('medium')} ${esc(o.medium)} ${sevB('low')} ${esc(o.low)}</div></div>
    <div class="card kpi ${esc(agentCls)}"><div class="l">Agents online ${help('Agents that reported recently. Offline agents cannot see DNS traffic.')}</div><div class="v">${esc(st.agents.online)} / ${esc(st.agents.total)}</div><div class="s"><a href="#agents">Manage agents</a></div></div>
    <div class="card kpi"><div class="l">DNS requests, last hour ${help('How many DNS requests the agents sent to this dashboard in the last hour.')}</div><div class="v">${esc(num(st.queries_last_hour))}</div><div class="s"><a href="#logs">See the log</a></div></div>
    <div class="card kpi ${esc(eng.cls)}"><div class="l">Detection engine ${help('The part that scores traffic and raises alerts. It runs by itself all the time.')}</div><div class="v">${esc(eng.state)}</div><div class="s">${esc(eng.text)}</div></div></div>
    <div class="cols"><div class="card"><h3>Needs attention</h3>${alertsH}</div>
    <div><div class="card"><h3>Campaigns ${help('One domain contacted by several of your computers.')}</h3>${campH}</div><div class="card"><h3>Blocking</h3><p>${blkOnH} Auto-block ${blkAutoH}</p>
      <p>Domains blocked right now: <b>${esc(bk.active.length)}</b> · <a href="#blocks">Manage blocks</a></p></div>
      <div class="card"><h3>Latest agent activity</h3>${actH}</div></div></div>`;
}

// ---------- alerts list ----------
const vAlerts = async () => {
  if (!built.alerts) {
    $('#v-alerts').innerHTML = `<div class="card"><div class="filters">
      <label class="chk">Show <select id="f-status"><option value="open">open alerts</option><option value="">all alerts</option><option value="ack">acknowledged</option>
      <option value="false_positive">false positives</option><option value="expired">expired</option></select></label>
      <select id="f-sev"><option value="">any severity</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
      <select id="f-prof"><option value="">fast + slow checks</option><option value="fast">fast check (noisy tunnels)</option><option value="slow">slow check (stealthy tunnels)</option></select>
      <span class="sp"></span><span class="mut">${help('Fast check: looks at the last 5 minutes. Slow check: looks at the last 24 hours to catch tunnels that send very little.')}</span></div>
      <div id="al-list"></div></div>`;
    ['f-status', 'f-sev', 'f-prof'].forEach(id => $('#' + id).addEventListener('change', () => load()));
    built.alerts = true;
  }
  const q = new URLSearchParams({limit: 100});
  [['f-status', 'status'], ['f-sev', 'severity'], ['f-prof', 'profile']].forEach(([id, k]) => { if ($('#' + id).value) q.set(k, $('#' + id).value); });
  const d = await api('/alerts?' + q);
  $('#al-list').innerHTML = d.items.length ? '<div class="alist">' + sortAlerts(d.items).map(alertCardH).join('') + '</div>' + '<p class="mut">' + esc(d.total) + ' alert' + (d.total === 1 ? '' : 's') + ' match.</p>'
    : empty('Nothing here', 'No alerts match these filters. That is good news if you were looking for problems.');
};

// ---------- alert drawer: short view first, detailed view on request ----------
function openAlert(id) {
  const a = A[id]; if (!a) return;
  const why = reasonsOf(a), whyH = why.length ? ' that show <b>' + esc(joinWords(why)) + '</b>' : '';
  const introH = 'The computer <b>' + esc(a.host) + '</b> is sending DNS requests to <b class="dom">' + esc(a.parent) + '</b>' + whyH + '. This is how malware can hide a secret channel inside normal-looking DNS.';
  const stateH = a.status === 'open' ? '' : '<p>Status: ' + statusPill(a.status) + '</p>';
  const btnH = a.status === 'open'
    ? `<button class="btn" data-act="ack" data-id="${esc(a.id)}">I'm looking into it</button><button class="btn" data-act="fp" data-id="${esc(a.id)}">Not a threat</button><button class="btn" data-act="trust" data-id="${esc(a.id)}">Trust this domain</button>`
    : `<button class="btn" data-act="reopen" data-id="${esc(a.id)}">Re-open</button><button class="btn" data-act="trust" data-id="${esc(a.id)}">Trust this domain</button>`;
  openDrawer(`<h2>${esc(titleOf(a))}</h2><p class="dom mut">${esc(a.parent)}</p>
    <div class="row" style="margin:10px 0"><span class="big">${esc(a.score)}</span><div>${sevB(a.severity)}<br><span class="mut">risk score out of 100</span></div></div>${stateH}
    <p>${introH}</p>
    <div class="facts"><div><span>Computer</span>${esc(a.host)}</div><div><span>Checked by</span>${esc(a.profile === 'slow' ? 'slow check (24 h)' : 'fast check (5 min)')}</div>
      <div><span>First seen</span>${esc(fmtTime(a.first_seen))}</div><div><span>Last seen</span>${esc(ago(a.last_seen))}</div></div>
    <div class="callout"><b>What should I do?</b><ol>
      <li>Find out which program on <b>${esc(a.host)}</b> is sending these requests.</li>
      <li>If you do not recognize <span class="dom">${esc(a.parent)}</span>, <b>block it</b> below and investigate the machine.</li>
      <li>If it belongs to something you trust (a CDN, backup or security tool), choose <b>Trust this domain</b>. It will stop alerting.</li></ol></div>
    ${blockBoxH(a)}
    <div class="acts">${btnH}</div>
    <h4>Want the full picture?</h4><button class="btn" data-act="detail" data-id="${esc(a.id)}">Show detailed view</button><div id="adetail"></div>`);
}

const untilH = ts => ts ? 'until ' + esc(fmtTime(ts)) : 'until you unblock it';
function blockBoxH(a) {
  const bl = a.blocks || [];
  if (bl.length) return '<div class="callout warn"><b>DNS for this domain is blocked</b> ' + bl.map(b =>
    `<p style="margin:6px 0 0">${esc(b.scope === 'all' ? 'On all computers' : 'On ' + a.host)} · ${esc(b.source === 'auto' ? 'automatic' : 'by hand')} · ${untilH(b.expires_at)} <button class="btn sm" data-act="unblock" data-bid="${esc(b.id)}">Unblock</button></p>`).join('') + '</div>';
  return `<div class="callout"><b>Stop it now</b><p class="mut" style="margin:4px 0 8px">Blocking makes the machine drop DNS for <span class="dom">${esc(a.parent)}</span> and all its subdomains. Agents must have blocking enabled.</p>
    <div class="acts" style="margin-top:0"><button class="btn d" data-act="blockalert" data-id="${esc(a.id)}" data-scope="host">Block on ${esc(a.host)}</button><button class="btn d" data-act="blockalert" data-id="${esc(a.id)}" data-scope="all">Block on all computers</button></div></div>`;
}

function detailH(d) {
  const a = d.alert, s = d.summary;
  const sigH = a.signals.map(x => { const info = SIG[x.name] || {name: x.label, what: ''}; const on = x.strength >= 0.5;
    const strongH = on ? pill('strong', 'bad') : '';
    return `<div class="sg"><div class="sl"><span><b>${esc(info.name)}</b> ${strongH}</span><span class="nowrap"><b>+${esc(x.points)}</b> <span class="mut">of ${esc(x.weight_pct)}</span></span></div>
      ${bar(x.strength, on ? 'high' : '')}<p>${esc(x.detail)}. ${esc(info.what)}</p></div>`; }).join('');
  const chipsH = (list, fmt) => list.length ? '<div class="chips">' + list.map(c => `<span class="chip">${esc(fmt(c.value))}<b>${esc(num(c.count))}</b></span>`).join('') + '</div>' : '<p class="mut">No data.</p>';
  const othersH = d.other_hosts.length ? `<div class="callout warn"><b>Also seen from other computers:</b> ${esc(d.other_hosts.join(', '))}<br>Several computers contacting the same domain is a stronger sign of a real problem.</div>` : '';
  const rowsH = d.samples.length ? d.samples.map(r => `<tr><td class="nw">${esc(new Date(r.ts * 1000).toLocaleTimeString())}</td><td class="dom">${esc(r.qname)}</td><td>${esc(r.qtype)}</td><td>${esc(r.resolver || '—')}</td><td>${esc(r.rcode == null ? '—' : (RCODES[r.rcode] || r.rcode))}</td></tr>`).join('')
    : '<tr><td colspan="5" class="mut">The raw requests are no longer stored (see retention in Settings).</td></tr>';
  return `<h4>Why it scored ${esc(a.score)}</h4><p class="mut">Each clue is rated from 0 to 100%, multiplied by how much it matters, and added up.</p>${sigH}
    <h4>The numbers</h4><div class="facts"><div><span>Time analysed</span>${esc(dur(d.window.seconds))}</div><div><span>Requests</span>${esc(num(s.queries))}</div>
      <div><span>Different names</span>${esc(num(s.unique_names))}</div><div><span>Data sent out in names</span>${esc(bytes(s.bytes_out))}</div>
      <div><span>First request</span>${esc(fmtTime(s.first))}</div><div><span>Last request</span>${esc(fmtTime(s.last))}</div></div>
    <h4>Requests over time</h4>${spark(d.timeline.counts)}<p class="mut">Each bar is ${esc(dur(d.timeline.step))}. Steady bars can mean a machine, not a person.</p>
    <h4>Breakdown</h4><p class="mut" style="margin:0">Request types</p>${chipsH(s.qtypes, v => v)}<p class="mut" style="margin:10px 0 0">Servers asked</p>${chipsH(s.resolvers, v => v || 'unknown')}
    <p class="mut" style="margin:10px 0 0">Results</p>${chipsH(s.rcodes, v => v == null ? 'no answer seen' : (RCODES[v] || 'code ' + v))}
    ${othersH}<h4>Latest requests</h4><div class="scroll"><table class="t"><thead><tr><th>Time</th><th>Name</th><th>Type</th><th>Server</th><th>Result</th></tr></thead><tbody>${rowsH}</tbody></table></div>`;
}
const showDetail = guard(async id => {
  const box = $('#adetail'); if (box.dataset.loaded) { box.classList.toggle('hide'); return; }
  box.innerHTML = '<p class="mut">Loading…</p>';
  box.innerHTML = detailH(await api('/alerts/' + id + '/details')); box.dataset.loaded = '1';
});

// ---------- help ----------
function openHelp() {
  const sigH = Object.keys(SIG).map(k => `<p><b>${esc(SIG[k].name)}.</b> ${esc(SIG[k].what)}</p>`).join('');
  openDrawer(`<h2>Help &amp; glossary</h2>
    <h4>What is DNS tunneling?</h4><p>DNS is the internet's phone book. Attackers can hide stolen data or remote-control messages inside DNS requests, because DNS is almost never blocked. DNSHollow looks for the clues listed below.</p>
    <h4>How it works</h4><p><b>Agents</b> run on your Linux machines and report which DNS requests they see. The <b>manager</b> (this dashboard) scores them every few seconds, all day, and raises an <b>alert</b> when the clues add up.</p>
    <h4>Risk levels</h4><p>${sevB('high')} Very likely a tunnel. Look at it now.</p><p>${sevB('medium')} Suspicious. Review it today.</p><p>${sevB('low')} A few weak signs. Keep an eye on it.</p>
    <h4>The seven clues</h4>${sigH}
    <h4>Two checks</h4><p><b>Fast check</b> studies the last 5 minutes and catches noisy tunnels. <b>Slow check</b> studies the last 24 hours and catches quiet, stealthy ones that only send a little.</p>
    <h4>Trusted domains</h4><p>Domains you trust are ignored completely. Use this for services you know are safe, like your company's own domains or a CDN.</p>
    <h4>Blocking</h4><p><b>Block</b> makes a computer drop all DNS for a domain (and its subdomains). Do it from an alert or on the Blocks page. <b>Auto-block</b> does it for you when a score passes the level you choose (Settings). Unblock any time. <b>Not a threat</b> and <b>Trust this domain</b> also lift blocks.</p>
    <h4>Alert buttons</h4><p><b>I'm looking into it</b> marks it as seen. <b>Not a threat</b> hides it and stops new alerts for that computer and domain. <b>Trust this domain</b> ignores the domain for everyone.</p>`);
}

// ---------- agents ----------
let INST = null, pendingInstall = null, INSTOS = 'linux';
const blockStateH = a => { const b = a.blocking;
  if (!b) return pill('unknown', 'off');
  if (b.error && !b.capable) return pill('not available', 'off');
  if (b.error) return pill('error', 'bad');
  return b.enforcing ? pill('blocking ' + b.applied.length, 'ok') : pill('ready', 'info'); };
const agentStatusH = a => !a.enabled ? pill('Disabled', 'off') : a.online ? pill('Online', 'ok') : pill('Offline', 'bad');

function buildCmd() {
  if (!INST) return;
  const addr = $('#ai-addr').value.trim().replace(/\/+$/, ''), warn = $('#ai-warn'), box = $('#ai-cmd'); warn.textContent = '';
  if (!/^https?:\/\/[A-Za-z0-9.\-]+(:\d{1,5})?$/.test(addr)) { box.value = ''; warn.textContent = 'Use an address like http://192.168.1.10:8000'; return; }
  if (/^https?:\/\/(localhost|127\.)/.test(addr)) warn.textContent = 'This address only works on this computer. Use the manager\'s network (LAN) address so other machines can reach it.';
  const k = $('#ai-insecure').checked, b = $('#ai-block').checked;
  if (INSTOS === 'windows') box.value = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "' + (k ? '[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; ' : '') +
    "& ([scriptblock]::Create((Invoke-RestMethod -UseBasicParsing '" + addr + "/install/windows.ps1'))) -Server '" + addr + "' -Token '" + INST.token + "' -Sha256 '" + INST.sha256 + "'" + (k ? ' -Insecure' : '') + (b ? ' -EnableBlocking' : '') + '"';
  else box.value = 'curl -fsSL' + (k ? 'k' : '') + ' ' + addr + '/install/linux.sh | sudo bash -s -- --server ' + addr +
    ' --token ' + INST.token + ' --sha256 ' + INST.sha256 + (k ? ' --insecure' : '') + (b ? ' --enable-blocking' : '');
  box.style.height = 'auto'; box.style.height = Math.max(box.scrollHeight + 4, 130) + 'px';
  $('#ai-hint').textContent = INSTOS === 'windows' ? 'Run it in an Administrator PowerShell on the Windows machine. Needs Python 3.8+ installed for all users.' : 'Run it as root on the Linux machine.';
}
const installFor = guard(async (id, name) => {
  INST = await api('/admin/agents/' + id + '/enroll-token', 'POST');
  $('#ai-title').textContent = 'Install command for "' + name + '"';
  if (!$('#ai-addr').value) $('#ai-addr').value = location.origin;
  $('#a-install').classList.remove('hide'); buildCmd(); $('#a-install').scrollIntoView({behavior: 'smooth', block: 'nearest'});
});

async function vAgents() {
  if (!built.agents) {
    $('#v-agents').innerHTML = `<div class="card"><h3>How agents work</h3><div class="howto">
      <div><b>1. Create</b>Give the agent a name below. We make a one-time install command for you.</div>
      <div><b>2. Install</b>Pick Linux or Windows, then paste the command on that machine (as root / Administrator).</div>
      <div><b>3. Watch and block</b>The agent reads a copy of that machine's DNS traffic and reports here. It only blocks DNS if you installed it with blocking on and you (or auto-block) ask for it.</div></div></div>
      <div class="card"><h3>Add an agent</h3>
      <form id="af" class="row"><input id="a-name" placeholder="A name, e.g. lab-pc" pattern="[A-Za-z0-9_.\-]{1,64}" title="Letters, numbers, dot, dash and underscore" required>
      <button class="btn p">Create and get install command</button></form>
      <div id="a-install" class="keybox hide"><p><b id="ai-title"></b><br><span class="mut"><span id="ai-hint"></span> It works once and expires in 15 minutes.</span></p>
        <div class="tabs" id="ai-os"><button data-os="linux" class="on">Linux</button><button data-os="windows">Windows</button></div>
        <label class="chk"><input type="checkbox" id="ai-block" checked> Let DNSHollow block DNS on this machine (needs extra permission: firewall changes)</label>
        <label>Manager address <span class="hintline">Must be reachable from that machine. Use this computer's network address, not "localhost".</span><input id="ai-addr"></label>
        <label class="chk"><input type="checkbox" id="ai-insecure"> My manager uses HTTPS with a self-signed certificate</label>
        <div class="cmdhead"><span>Run this command</span><button class="btn p sm" id="ai-copy" type="button">Copy command</button></div><textarea id="ai-cmd" class="cmdbox" rows="6" readonly spellcheck="false"></textarea><p id="ai-warn" class="err"></p></div></div>
      <div class="card"><h3>Your agents</h3><div id="ag-list" class="scroll"></div></div>`;
    $('#af').addEventListener('submit', guard(async e => { e.preventDefault();
      const r = await api('/admin/agents', 'POST', {name: $('#a-name').value.trim(), os: INSTOS});
      $('#a-name').value = ''; await installFor(r.id, r.name); load(); }));
    $('#ai-addr').addEventListener('input', buildCmd); $('#ai-insecure').addEventListener('change', buildCmd); $('#ai-block').addEventListener('change', buildCmd);
    $('#ai-os').addEventListener('click', e => { const b = e.target.closest('[data-os]'); if (!b) return; INSTOS = b.dataset.os;
      $$('#ai-os button').forEach(x => x.classList.toggle('on', x === b)); buildCmd(); });
    $('#ai-copy').addEventListener('click', async () => { const ta = $('#ai-cmd');
      try { await navigator.clipboard.writeText(ta.value); } catch (e) { ta.select(); document.execCommand('copy'); } toast('Command copied'); });
    built.agents = true;
  }
  const list = await api('/admin/agents');
  $('#ag-list').innerHTML = !list.length ? empty('No agents yet', 'Create one above to start watching a machine.') :
    '<table class="t"><thead><tr><th>Name</th><th>Status</th><th>Last report</th><th>Requests sent</th><th>Blocking</th><th>System</th></tr></thead><tbody>' +
    list.map(a => `<tr data-agent="${esc(a.id)}" tabindex="0"><td><b>${esc(a.name)}</b></td><td>${agentStatusH(a)}</td><td>${esc(ago(a.last_seen))}</td><td>${esc(num(a.total_queries))}</td><td>${blockStateH(a)}</td><td class="mut">${esc(a.os || '—')}</td></tr>`).join('') + '</tbody></table>';
  if (pendingInstall) { const p = pendingInstall; pendingInstall = null; installFor(p.id, p.name); }
}

const openAgent = guard(async id => {
  const d = await api('/admin/agents/' + id + '/details'), a = d.agent;
  const batchH = d.recent_batches.length ? d.recent_batches.map(b => `<tr><td class="nw">${esc(fmtTime(b.received_at))}</td><td>${esc(num(b.accepted))}</td><td>${esc(b.dropped)}</td><td>${esc(b.ignored)}</td></tr>`).join('')
    : '<tr><td colspan="4" class="mut">Nothing received yet.</td></tr>';
  const domH = d.top_domains_last_hour.length ? '<div class="chips">' + d.top_domains_last_hour.map(x => `<span class="chip dom">${esc(x.parent)}<b>${esc(num(x.count))}</b></span>`).join('') + '</div>' : '<p class="mut">No requests in the last hour.</p>';
  const tipH = !a.enabled ? '<div class="callout">This agent is <b>disabled</b>. The manager rejects its reports until you enable it again.</div>'
    : a.online ? '' : '<div class="callout warn"><b>This agent is not reporting.</b> Linux: run <code>systemctl status dnshollow-agent</code> and <code>journalctl -u dnshollow-agent -n 30</code>. Windows: open <code>C:\\ProgramData\\DNSHollow\\agent.log</code>.</div>';
  const bs = a.blocking, blkH = !bs ? '<p class="mut">No report yet.</p>' : bs.error ? `<div class="callout warn"><b>Blocking problem:</b> ${esc(bs.error)}</div>`
    : `<p>${blockStateH(a)} ${esc(bs.method || '')}</p>` + (bs.applied.length ? '<div class="chips">' + bs.applied.map(x => `<span class="chip dom">${esc(x)}</span>`).join('') + '</div>' : '<p class="mut">Nothing is blocked on this machine right now.</p>');
  openDrawer(`<h2>${esc(a.name)}</h2><p>${agentStatusH(a)}</p>${tipH}
    <div class="facts"><div><span>Last report</span>${esc(ago(a.last_seen))}</div><div><span>Requests sent</span>${esc(num(a.total_queries))}</div>
      <div><span>System</span>${esc(a.os || '—')}</div><div><span>Agent version</span>${esc(a.version || '—')}</div></div>
    <div class="acts"><button class="btn" data-act="install" data-id="${esc(a.id)}" data-name="${esc(a.name)}">Get install command</button>
      <button class="btn ${esc(a.enabled ? 'd' : '')}" data-act="toggle" data-id="${esc(a.id)}" data-en="${esc(a.enabled ? 0 : 1)}">${esc(a.enabled ? 'Disable agent' : 'Enable agent')}</button></div>
    <h4>DNS blocking on this machine</h4>${blkH}
    <h4>Want more detail?</h4><button class="btn" data-act="agdetail">Show detailed view</button>
    <div id="agbox" class="hide"><h4>Most contacted domains (last hour)</h4>${domH}
      <h4>Recent reports</h4><div class="scroll"><table class="t"><thead><tr><th>Received</th><th>Requests</th><th>Dropped</th><th>Trusted (skipped)</th></tr></thead><tbody>${batchH}</tbody></table></div>
      <p class="mut">"Dropped" means a request was malformed. "Trusted" requests are skipped on purpose.</p></div>`);
});

// ---------- blocks ----------
async function vBlocks() {
  const d = await api('/blocks');
  if (!built.blocks) {
    $('#v-blocks').innerHTML = `<div id="bk-top"></div><div class="card"><h3>Block a domain</h3>
      <p class="mut">The computer drops all DNS for the domain and its subdomains. Use the main domain, like <code>evil-dns.xyz</code>.</p>
      <form id="bf" class="row"><input id="b-dom" placeholder="evil-dns.xyz" required size="26"><select id="b-where"></select>
      <select id="b-hours"><option value="0">until I unblock it</option><option value="1">for 1 hour</option><option value="24">for 24 hours</option><option value="168">for 7 days</option></select>
      <button class="btn d">Block</button></form><p id="b-err" class="err" role="alert"></p></div>
      <div class="card"><h3>Blocked now</h3><div id="bk-list" class="scroll"></div></div>
      <details class="sec"><summary><span>Recently removed</span></summary><div class="in scroll" id="bk-hist"></div></details>`;
    $('#bf').addEventListener('submit', guard(async e => { e.preventDefault(); $('#b-err').textContent = '';
      const w = $('#b-where').value;
      try { await api('/blocks', 'POST', {parent: $('#b-dom').value.trim(), scope: w === '*' ? 'all' : 'host', host: w === '*' ? null : w, hours: +$('#b-hours').value || null, reason: 'Blocked by hand'});
        $('#b-dom').value = ''; toast('Blocked. Agents pick it up within a minute.'); built.blocks = true; load(); }
      catch (er) { if (er.message !== 'auth') $('#b-err').textContent = er.message; } }));
    built.blocks = true;
  }
  $('#bk-top').innerHTML = d.enabled ? '' : '<div class="banner warn">' + icon('warn') + '<div><b>Blocking is switched off.</b><span>Nothing is blocked while it is off. Turn it on in Settings.</span></div></div>';
  const sel = $('#b-where'), cur = sel.value;
  sel.innerHTML = '<option value="*">on all computers</option>' + d.agents.map(a => `<option value="${esc(a.name)}">on ${esc(a.name)}</option>`).join(''); if (cur) sel.value = cur;
  const row = (b, live) => {
    const whoH = b.host ? esc(b.host) : '<i>all computers</i>';
    const howH = b.source === 'auto' ? pill('auto', 'info') + (b.score != null ? ' ' + esc(b.score) : '') : 'by hand';
    const endH = live ? (b.expires_at ? esc(fmtTime(b.expires_at)) : 'until removed') : esc(fmtTime(b.removed_at)) + '<br><span class="mut">' + esc(b.removed_by || '') + '</span>';
    const actH = live ? `<button class="btn sm" data-act="unblock" data-bid="${esc(b.id)}">Unblock</button>` : '';
    return `<tr><td class="dom"><b>${esc(b.parent)}</b></td><td>${whoH}</td><td>${howH}<br><span class="mut">${esc(b.created_by || '')}</span></td>
    <td class="nw">${esc(fmtTime(b.created_at))}</td><td class="nw">${endH}</td><td>${actH}</td></tr>`;
  };
  const table = (list, live) => list.length ? '<table class="t"><thead><tr><th>Domain</th><th>Where</th><th>How</th><th>Since</th><th>' + (live ? 'Ends' : 'Removed') + '</th><th></th></tr></thead><tbody>' + list.map(b => row(b, live)).join('') + '</tbody></table>' : null;
  const live = d.active.length ? table(d.active, true) : empty('Nothing is blocked', 'When you block a domain it shows up here.');
  const agentsOff = d.agents.filter(a => a.enabled && a.state && !a.state.capable).map(a => esc(a.name));
  const offH = agentsOff.join(', ');
  $('#bk-list').innerHTML = live + (agentsOff.length && d.active.length ? `<p class="mut">These computers cannot enforce blocks (blocking not enabled on the agent): ${offH}. See the Agents page.</p>` : '');
  $('#bk-hist').innerHTML = table(d.history, false) || '<p class="mut">Nothing yet.</p>';
}

// ---------- logs ----------
const LOGS = {tab: 'queries', live: false, next: {}, f: {minutes: '60', agent: '', q: '', qtype: '', rcode: ''}, agents: []};
const LOGTABS = {queries: 'DNS requests', batches: 'Agent activity', audit: 'Audit trail'};
const LOGHELP = {queries: 'Every DNS request the agents saw. Newest first.', batches: 'Each time an agent sent a package of requests to this dashboard.',
  audit: 'Who signed in and what they changed. Useful to see what happened and when.'};
const LOGHEAD = {queries: ['Time', 'Computer', 'Name asked', 'Type', 'Server', 'Size', 'Result'], batches: ['Received', 'Agent', 'Requests', 'Dropped', 'Trusted (skipped)', 'Batch'], audit: ['Time', 'Who', 'What', 'Details', 'From']};
function resultH(c) { return c == null ? pill('no answer', 'off') : c === 0 ? pill('OK', 'ok') : c === 3 ? pill('Name not found', 'info') : pill(RCODES[c] || 'code ' + c, 'bad'); }

function logRowH(tab, r) {
  if (tab === 'queries') return `<tr><td class="nw">${esc(fmtTime(r.ts))}</td><td>${esc(r.host)}</td><td class="dom">${esc(r.qname)}</td><td>${esc(r.qtype)}</td><td>${esc(r.resolver || '—')}</td><td class="nw mut">${esc(r.qbytes == null ? '—' : r.qbytes + ' B')}${esc(r.rbytes == null ? '' : ' / ' + r.rbytes + ' B')}</td><td>${resultH(r.rcode)}</td></tr>`;
  if (tab === 'batches') return `<tr><td class="nw">${esc(fmtTime(r.received_at))}</td><td>${esc(r.agent || '—')}</td><td>${esc(num(r.accepted))}</td><td>${esc(r.dropped)}</td><td>${esc(r.ignored)}</td><td class="mut dom">${esc(String(r.batch_id).slice(0, 8))}</td></tr>`;
  return `<tr><td class="nw">${esc(fmtTime(r.ts))}</td><td>${esc(r.actor)}</td><td>${esc(ACTIONS[r.action] || r.action)}</td><td class="dom">${esc(r.detail)}</td><td class="mut">${esc(r.ip)}</td></tr>`;
}
function logFiltersH() {
  if (LOGS.tab !== 'queries') { const offH = LOGS.tab === 'audit' ? 'disabled' : '';
    return `<label class="chk"><input type="checkbox" id="lg-live" ${offH}> Live (refresh every 5 s)</label>`; }
  const agH = '<option value="">All computers</option>' + LOGS.agents.map(a => `<option value="${esc(a.name)}">${esc(a.name)}</option>`).join('');
  return `<select id="lg-agent">${agH}</select><input id="lg-q" placeholder="Search a domain name" size="22">
    <select id="lg-type"><option value="">Any type</option><option>A</option><option>AAAA</option><option>TXT</option><option>NULL</option><option>CNAME</option><option>MX</option></select>
    <select id="lg-rcode"><option value="">Any result</option><option value="0">OK</option><option value="3">Name not found</option><option value="2">Server failure</option><option value="5">Refused</option></select>
    <select id="lg-min"><option value="15">Last 15 minutes</option><option value="60">Last hour</option><option value="1440">Last 24 hours</option><option value="10080">Last 7 days</option></select>
    <label class="chk"><input type="checkbox" id="lg-live"> Live</label>`;
}
function setLogFilters() {
  $('#lg-filters').innerHTML = logFiltersH();
  const map = {'lg-agent': 'agent', 'lg-q': 'q', 'lg-type': 'qtype', 'lg-rcode': 'rcode', 'lg-min': 'minutes'};
  Object.keys(map).forEach(id => { const el = $('#' + id); if (!el) return; el.value = LOGS.f[map[id]];
    el.addEventListener('change', () => { LOGS.f[map[id]] = el.value; LOGS.next = {}; load(); }); });
  const live = $('#lg-live'); if (live) { live.checked = LOGS.live && LOGS.tab !== 'audit'; live.addEventListener('change', () => { LOGS.live = live.checked; load(); }); }
}
async function fetchLogs(append) {
  const tab = LOGS.tab, q = new URLSearchParams({limit: 100});
  if (append && LOGS.next[tab]) q.set('before_id', LOGS.next[tab]);
  if (tab === 'queries') { const f = LOGS.f; q.set('minutes', f.minutes); if (f.agent) q.set('agent', f.agent); if (f.q) q.set('q', f.q); if (f.qtype) q.set('qtype', f.qtype); if (f.rcode !== '') q.set('rcode', f.rcode); }
  const d = await api('/logs/' + tab + '?' + q);
  const rowsH = d.items.map(r => logRowH(tab, r)).join('');
  if (append) $('#lg-body').innerHTML += rowsH; else $('#lg-body').innerHTML = rowsH || `<tr><td colspan="7">${empty('Nothing to show', tab === 'queries' ? 'No DNS requests match. Is an agent online? Try a longer time range.' : 'Nothing has been recorded yet.')}</td></tr>`;
  LOGS.next[tab] = d.next_before_id; $('#lg-more').classList.toggle('hide', !d.next_before_id);
}
async function vLogs() {
  if (!built.logs) {
    LOGS.agents = await api('/admin/agents');
    const tabsH = Object.keys(LOGTABS).map(t => `<button data-tab="${esc(t)}">${esc(LOGTABS[t])}</button>`).join('');
    $('#v-logs').innerHTML = `<div class="card"><div class="tabs">${tabsH}</div>
      <p id="lg-help" class="mut"></p><div id="lg-filters" class="filters"></div>
      <div class="scroll"><table class="t"><thead id="lg-head"></thead><tbody id="lg-body"></tbody></table></div>
      <p><button class="btn hide" id="lg-more" data-act="more">Load older</button></p></div>`;
    built.logs = true; switchLogTab(LOGS.tab, true);
  }
  await fetchLogs(false);
}
function switchLogTab(t, keep) {
  LOGS.tab = t; if (!keep) { LOGS.next = {}; if (t === 'audit') LOGS.live = false; }
  $$('#v-logs .tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === t));
  $('#lg-help').textContent = LOGHELP[t]; $('#lg-head').innerHTML = '<tr>' + LOGHEAD[t].map(h => `<th>${esc(h)}</th>`).join('') + '</tr>';
  setLogFilters(); if (!keep) { $('#lg-body').innerHTML = ''; load(); }
}

// ---------- settings ----------
let S = null, PRESETS = [], dirty = false;
const presetMatch = (s, p) => Object.keys(p.config.profiles).every(n => { const a = s.profiles[n], b = p.config.profiles[n];
  return a.min_signals === b.min_signals && ['low', 'medium', 'high'].every(k => a.severity[k] === b.severity[k]); });

function profileH(n, p) {
  const title = n === 'fast' ? 'Fast check: catches noisy tunnels' : 'Slow check: catches stealthy tunnels';
  const blurb = n === 'fast' ? 'Looks at the last few minutes. Good at spotting tunnels that send a lot of requests.'
    : 'Looks at a whole day. Good at spotting quiet tunnels that only send a few requests, so you can use a smaller number of requests here.';
  const openH = n === 'fast' ? 'open' : '', onH = p.enabled ? 'checked' : '';
  const weightsH = Object.keys(SIG).map(k => `<div class="wl"><span>${esc(SIG[k].name)} ${help(SIG[k].what)}</span><input type="range" min="0" max="100" data-w="${esc(n)}" data-sig="${esc(k)}" value="${esc(Math.round(p.weights[k] * 100))}" aria-label="${esc(SIG[k].name)} importance"><output data-o="${esc(n)}-${esc(k)}"></output></div>`).join('');
  const rampsH = Object.keys(SIG).map(k => { const r = p.ramps[k], m = SIG[k].pct ? 100 : 1;
    return `<div class="ramp"><span>${esc(SIG[k].name)}<span class="hintline">${esc(SIG[k].unit)}</span></span>
      <input type="number" step="any" data-ramp="${esc(n)}.${esc(k)}.0" value="${esc(+(r[0] * m).toFixed(4))}" aria-label="starts to count at">
      <input type="number" step="any" data-ramp="${esc(n)}.${esc(k)}.1" value="${esc(+(r[1] * m).toFixed(4))}" aria-label="counts fully at"></div>`; }).join('');
  return `<details class="sec" ${openH}><summary><span>${esc(title)}</span>${pill(p.enabled ? 'On' : 'Off', p.enabled ? 'ok' : 'off')}</summary><div class="in">
    <p class="mut">${esc(blurb)}</p>
    <label class="chk"><input type="checkbox" data-pk="${esc(n)}.enabled" ${onH}> This check is on</label>
    <div class="grid">
      <label>Time window (minutes) ${help('How far back this check looks. 1440 minutes = 24 hours.')}<input type="number" min="1" step="any" data-pk="${esc(n)}.window" value="${esc(p.window_seconds / 60)}"></label>
      <label>Minimum requests ${help('A computer/domain pair needs at least this many requests in the window before it is judged. Prevents alerts from tiny samples.')}<input type="number" min="1" data-pk="${esc(n)}.min_queries" value="${esc(p.min_queries)}"></label>
      <label>Strong clues needed ${help('How many of the 7 clues must be strong (50% or more) before an alert is raised. Higher = fewer false alarms.')}<input type="number" min="1" max="7" data-pk="${esc(n)}.min_signals" value="${esc(p.min_signals)}"></label></div>
    <h4>When is it Low, Medium or High? ${help('The risk score goes from 0 to 100. These are the scores where each level starts.')}</h4>
    <div class="grid"><label>Low from<input type="number" data-pk="${esc(n)}.low" value="${esc(p.severity.low)}"></label>
      <label>Medium from<input type="number" data-pk="${esc(n)}.medium" value="${esc(p.severity.medium)}"></label>
      <label>High from<input type="number" data-pk="${esc(n)}.high" value="${esc(p.severity.high)}"></label></div>
    <h4>How much does each clue matter? ${help('Drag to make a clue count more or less. The percentages on the right show each clue\'s share of the score.')}</h4>${weightsH}
    <details style="margin-top:14px"><summary class="mut" style="cursor:pointer">Advanced: when does each clue start to count?</summary>
      <p class="mut">Each clue gives 0% below the first number and 100% at the second number, and grows evenly in between.</p>
      <div class="ramp mut"><span></span><span>Starts to count at</span><span>Counts fully at</span></div>${rampsH}</details></div></details>`;
}

async function vSettings() {
  if (built.settings) return;
  [S, PRESETS] = await Promise.all([api('/admin/settings'), api('/admin/settings/presets')]);
  const cur = PRESETS.find(p => presetMatch(S, p));
  const presetsH = PRESETS.map(p => { const on = cur && cur.name === p.name, onH = on ? ' on' : '', curH = on ? pill('Current', 'info') : '';
    return `<button type="button" class="preset${onH}" data-act="preset" data-name="${esc(p.name)}"><b>${esc(p.title)} ${curH}</b><span>${esc(p.description)}</span></button>`; }).join('');
  const bkc = S.blocking, enH = bkc.enabled ? 'checked' : '', autoH = bkc.auto_block ? 'checked' : '';
  const hostSelH = bkc.auto_scope === 'host' ? 'selected' : '', allSelH = bkc.auto_scope === 'all' ? 'selected' : '';
  const customH = cur ? '' : '<p class="mut">Your settings are custom: you changed individual values below. Choosing a preset resets the alert levels and the "strong clues needed" numbers.</p>';
  $('#v-settings').innerHTML = `<div class="card"><h3>How sensitive should detection be?</h3><p class="mut">Not sure? Keep Balanced. You can always change it.</p><div class="presets">${presetsH}</div>${customH}</div>
    <details class="sec" open><summary><span>Trusted domains</span></summary><div class="in"><p class="mut">Domains you know are safe. They are ignored completely: no scoring, no alerts, and the requests are not even stored.</p>
      <textarea id="trusted" rows="4" placeholder="example.com&#10;mycompany.local">${esc(S.trusted_domains.join('\n'))}</textarea><span class="hintline">One per line. Subdomains are included, so <code>example.com</code> also covers <code>www.example.com</code>.</span></div></details>
    ${profileH('fast', S.profiles.fast)}${profileH('slow', S.profiles.slow)}
    <details class="sec"><summary><span>Blocking</span>${pill(S.blocking.enabled ? (S.blocking.auto_block ? 'Auto' : 'On') : 'Off', S.blocking.enabled ? 'ok' : 'off')}</summary><div class="in">
      <p class="mut">Blocking makes an agent drop DNS for a domain. It only works on agents installed with blocking enabled. A wrong block can break a real service, so auto-block is <b>off</b> until you turn it on.</p>
      <label class="chk"><input type="checkbox" data-pk="blocking.enabled" ${enH}> Blocking is allowed (master switch: off removes every block)</label>
      <label class="chk"><input type="checkbox" data-pk="blocking.auto_block" ${autoH}> Block automatically when the score reaches the level below</label>
      <div class="grid">
        <label>Auto-block at score ${help('Same 0-100 score as alerts. Only alerts nobody has reviewed are auto-blocked, and trusted domains never are.')}<input type="number" min="1" max="100" data-pk="blocking.auto_min_score" value="${esc(S.blocking.auto_min_score)}"></label>
        <label>Auto-block applies to ${help('One computer is the safe choice. "All computers" stops the domain everywhere at once.')}<select data-pk="blocking.auto_scope"><option value="host" ${hostSelH}>only the computer that raised the alert</option><option value="all" ${allSelH}>every computer</option></select></label>
        <label>Auto-block lasts (hours) ${help('0 = until someone unblocks it.')}<input type="number" min="0" data-pk="blocking.auto_expire_hours" value="${esc(S.blocking.auto_expire_hours)}"></label></div></div></details>
    <details class="sec"><summary><span>Agents</span></summary><div class="in"><p class="mut">How agents send data. The defaults are fine for most networks.</p><div class="grid">
      <label>Send every (seconds)<input type="number" min="1" data-pk="agent.batch_interval_seconds" value="${esc(S.agent.batch_interval_seconds)}"></label>
      <label>Max requests per package<input type="number" min="1" max="20000" data-pk="agent.max_batch_size" value="${esc(S.agent.max_batch_size)}"></label>
      <label>Max packages per minute<input type="number" min="1" data-pk="agent.max_batches_per_minute" value="${esc(S.agent.max_batches_per_minute)}"></label></div></div></details>
    <details class="sec"><summary><span>Storage and campaigns</span></summary><div class="in"><div class="grid">
      <label>Keep raw requests for (days) ${help('Older requests are deleted. Must be at least as long as the slow check window.')}<input type="number" min="1" data-pk="retention_days" value="${esc(S.retention_days)}"></label>
      <label>Campaign = this many computers ${help('When this many computers contact the same suspicious domain it is listed as a campaign.')}<input type="number" min="2" data-pk="campaign_min_hosts" value="${esc(S.campaign_min_hosts)}"></label></div></div></details>
    <div class="savebar"><button class="btn p" data-act="save">Save changes</button><span id="save-state" class="mut">No changes yet.</span><span class="sp"></span><button class="btn d" data-act="reset">Reset everything to defaults</button></div>
    <p id="serr" class="err" role="alert"></p>`;
  ['fast', 'slow'].forEach(shares); dirty = false; built.settings = true;
}
function shares(n) { const ins = $$('[data-w="' + n + '"]'), tot = ins.reduce((a, i) => a + +i.value, 0);
  ins.forEach(i => { const o = $('[data-o="' + n + '-' + i.dataset.sig + '"]'); if (o) o.textContent = (tot ? Math.round(i.value / tot * 100) : 0) + '%'; }); }
function collect() {
  const num = el => { const v = parseFloat(el.value); if (Number.isNaN(v)) throw new Error('Please fill in every number field.'); return v; };
  const g = k => $('[data-pk="' + k + '"]');
  const cfg = {trusted_domains: $('#trusted').value.split(/[\s,]+/).map(x => x.trim().toLowerCase()).filter(Boolean), retention_days: num(g('retention_days')),
    campaign_min_hosts: Math.round(num(g('campaign_min_hosts'))),
    blocking: {enabled: g('blocking.enabled').checked, auto_block: g('blocking.auto_block').checked, auto_min_score: num(g('blocking.auto_min_score')),
      auto_scope: g('blocking.auto_scope').value, auto_expire_hours: num(g('blocking.auto_expire_hours'))},
    agent: {batch_interval_seconds: num(g('agent.batch_interval_seconds')), max_batch_size: Math.round(num(g('agent.max_batch_size'))), max_batches_per_minute: Math.round(num(g('agent.max_batches_per_minute')))}, profiles: {}};
  ['fast', 'slow'].forEach(n => { const w = {}, r = {};
    $$('[data-w="' + n + '"]').forEach(i => w[i.dataset.sig] = +i.value / 100);
    Object.keys(SIG).forEach(k => { const m = SIG[k].pct ? 100 : 1; r[k] = [num($('[data-ramp="' + n + '.' + k + '.0"]')) / m, num($('[data-ramp="' + n + '.' + k + '.1"]')) / m]; });
    cfg.profiles[n] = {enabled: g(n + '.enabled').checked, window_seconds: Math.round(num(g(n + '.window')) * 60), min_queries: Math.round(num(g(n + '.min_queries'))),
      min_signals: Math.round(num(g(n + '.min_signals'))), weights: w, ramps: r, severity: {low: num(g(n + '.low')), medium: num(g(n + '.medium')), high: num(g(n + '.high'))}}; });
  return cfg;
}

// ---------- account ----------
async function vAccount() {
  if (built.account) return;
  const s = await api('/session'), formH = pwFormH('acct');
  $('#v-account').innerHTML = `<div class="card"><h3>Signed in as ${esc(s.username)}</h3><p class="mut">This sign-in: ${esc(fmtTime(s.last_login))}</p><div class="acts"><button class="btn" data-act="signout">Sign out</button></div></div>
    <div class="card"><h3>Change your password</h3><p class="mut">This also signs you out on every other device.</p>${formH}</div>`;
  bindPwForm($('#v-account .pwform'), async () => toast('Password changed. Other devices were signed out.'));
  built.account = true;
}

const views = {overview: vOverview, alerts: vAlerts, agents: vAgents, blocks: vBlocks, logs: vLogs, settings: vSettings, account: vAccount};

// ---------- clicks, keys ----------
const setStatus = guard(async (id, status, msg) => { await api('/alerts/' + id, 'PATCH', {status}); toast(msg); closeDrawer(); load(); });
async function act(t) {
  const id = t.dataset.id;
  switch (t.dataset.act) {
    case 'close': return closeDrawer();
    case 'ack': return setStatus(id, 'ack', 'Marked as "looking into it"');
    case 'fp': return setStatus(id, 'false_positive', 'Marked as not a threat. New alerts for it are hidden.');
    case 'reopen': return setStatus(id, 'open', 'Alert re-opened');
    case 'trust': { const a = A[id]; if (!confirm('Ignore ' + (a ? a.parent : 'this domain') + ' for everyone from now on? You can remove it later in Settings.')) return;
      const r = await api('/alerts/' + id + '/trust-domain', 'POST'); toast(r.trusted + ' is now trusted'); closeDrawer(); return load(); }
    case 'blockalert': { const a = A[id]; const where = t.dataset.scope === 'all' ? 'ALL computers' : a.host;
      if (!confirm('Block all DNS for ' + a.parent + ' on ' + where + '? You can unblock it at any time.')) return;
      await api('/alerts/' + id + '/block', 'POST', {scope: t.dataset.scope}); toast('Blocked. Agents pick it up within a minute.'); closeDrawer(); return load(); }
    case 'unblock': { if (!confirm('Unblock this domain? Its open alerts are marked as "looking into it" so it is not blocked again by itself.')) return;
      await api('/blocks/' + t.dataset.bid, 'DELETE'); toast('Unblocked'); closeDrawer(); return load(); }
    case 'detail': return showDetail(id);
    case 'agdetail': $('#agbox').classList.toggle('hide'); return;
    case 'toggle': await api('/admin/agents/' + id, 'PATCH', {enabled: t.dataset.en === '1'}); toast(t.dataset.en === '1' ? 'Agent enabled' : 'Agent disabled'); closeDrawer(); return load();
    case 'install': closeDrawer(); if (view === 'agents') return installFor(id, t.dataset.name); pendingInstall = {id, name: t.dataset.name}; location.hash = '#agents'; return;
    case 'more': return fetchLogs(true);
    case 'preset': await api('/admin/settings/preset/' + t.dataset.name, 'POST'); toast('Sensitivity updated'); built.settings = false; return vSettings();
    case 'save': { $('#serr').textContent = '';
      try { await api('/admin/settings', 'PATCH', {config: collect()}); toast('Settings saved. They apply within a few seconds.'); built.settings = false; return vSettings(); }
      catch (er) { if (er.message !== 'auth') { $('#serr').textContent = er.message; toast('Not saved. See the message below.', true); } return; } }
    case 'reset': if (!confirm('Reset ALL settings to the defaults?')) return; await api('/admin/settings/reset', 'POST'); toast('Defaults restored'); built.settings = false; return vSettings();
    case 'signout': return signOut();
  }
}
document.addEventListener('click', async e => {
  const t = e.target.closest('[data-act]'), card = e.target.closest('[data-alert]'), row = e.target.closest('[data-agent]'), tab = e.target.closest('[data-tab]');
  try {
    if (t) return await act(t);
    if (tab) return switchLogTab(tab.dataset.tab);
    if (card) return openAlert(card.dataset.alert);
    if (row) return openAgent(row.dataset.agent);
  } catch (er) { if (er.message !== 'auth') toast(er.message, true); }
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeDrawer();
  if ((e.key === 'Enter' || e.key === ' ') && e.target.matches && e.target.matches('[data-alert],[data-agent]')) { e.preventDefault(); e.target.click(); }
});
document.addEventListener('input', e => {
  if (!e.target.closest('#v-settings')) return;
  if (e.target.dataset.w) shares(e.target.dataset.w);
  if (e.target.closest('.savebar') || e.target.id === 'serr') return;
  dirty = true; const el = $('#save-state'); if (el) el.textContent = 'You have unsaved changes.';
});
$('#scrim').addEventListener('click', closeDrawer);
$('#help-btn').addEventListener('click', openHelp);
$('#run').addEventListener('click', guard(async () => { await api('/admin/run/fast', 'POST'); await api('/admin/run/slow', 'POST'); toast('Checked right now'); load(); }));
window.addEventListener('hashchange', () => { if (me) route(); });
start();


// ---------- show / hide password ----------
function addEyes(root) {
  root.querySelectorAll('input[type=password]:not([data-eye])').forEach(inp => {
    inp.dataset.eye = '1';
    const wrap = document.createElement('span'); wrap.className = 'pw';
    inp.parentNode.insertBefore(wrap, inp); wrap.appendChild(inp);
    const b = document.createElement('button'); b.type = 'button'; b.className = 'eye'; b.textContent = 'Show';
    b.setAttribute('aria-label', 'Show password'); b.setAttribute('aria-pressed', 'false');
    b.addEventListener('click', () => { const show = inp.type === 'password'; inp.type = show ? 'text' : 'password';
      b.textContent = show ? 'Hide' : 'Show'; b.setAttribute('aria-label', show ? 'Hide password' : 'Show password'); b.setAttribute('aria-pressed', String(show)); });
    wrap.appendChild(b);
  });
}
addEyes(document);
new MutationObserver(() => addEyes(document)).observe(document.body, {childList: true, subtree: true});
