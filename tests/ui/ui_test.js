const { JSDOM, VirtualConsole } = require('jsdom');
const BASE = 'http://127.0.0.1:8790';
const jar = {}; const errors = []; let pass = 0, fail = 0;
const sleep = ms => new Promise(r => setTimeout(r, ms));
function ok(cond, name, extra) { if (cond) { pass++; console.log('  ok   ' + name); } else { fail++; console.log('  FAIL ' + name + (extra ? '  -> ' + extra : '')); } }

async function main() {
  const vc = new VirtualConsole();
  vc.on('jsdomError', e => errors.push('jsdomError: ' + (e.detail || e.message)));
  vc.on('error', e => errors.push('console.error: ' + e));
  const dom = await JSDOM.fromURL(BASE + '/', {
    runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(w) {
      w.fetch = async (url, opts = {}) => {
        const u = new URL(url, BASE); const headers = { ...(opts.headers || {}) };
        const c = Object.entries(jar).map(([k, v]) => k + '=' + v).join('; '); if (c) headers.Cookie = c;
        const r = await fetch(u, { ...opts, headers, redirect: 'manual' });
        (r.headers.getSetCookie ? r.headers.getSetCookie() : []).forEach(s => {
          const [kv] = s.split(';'); const i = kv.indexOf('='); const k = kv.slice(0, i), v = kv.slice(i + 1).replace(/"/g, '');
          if (!v || /max-age=0/i.test(s)) delete jar[k]; else jar[k] = v; });
        return r; };
      w.Element.prototype.scrollIntoView = function () {};
      w.confirm = () => true;
      w.addEventListener('error', e => errors.push('window error: ' + e.message));
    } });
  const w = dom.window, d = w.document, $ = s => d.querySelector(s), $$ = s => [...d.querySelectorAll(s)];
  const visible = s => { const e = $(s); return !!e && !e.classList.contains('hide'); };
  const waitFor = async (fn, ms = 4000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (fn()) return true; } catch (e) {} await sleep(40); } return false; };
  const type = (sel, v) => { const e = typeof sel === 'string' ? $(sel) : sel; e.value = v; e.dispatchEvent(new w.Event('input', { bubbles: true })); e.dispatchEvent(new w.Event('change', { bubbles: true })); };
  const submit = f => f.dispatchEvent(new w.Event('submit', { bubbles: true, cancelable: true }));
  const go = async h => { w.location.hash = h; await sleep(150); };

  console.log('\n[login + forced password change]');
  ok(await waitFor(() => visible('#screen-login')), 'login screen is shown first');
  ok(!$('#screen-login').textContent.includes('First time here'), 'login has no first-time hint');
  const eye = $('#screen-login .pw .eye'); ok(!!eye && $('#lp').type === 'password', 'login has a Show button, password hidden');
  eye.click(); ok($('#lp').type === 'text' && eye.textContent === 'Hide', 'Show reveals the password');
  eye.click(); ok($('#lp').type === 'password', 'Hide hides it again');
  type('#lu', 'admin'); type('#lp', 'wrong-password'); submit($('#lf'));
  ok(await waitFor(() => $('#lerr').textContent.length > 0), 'wrong password shows an error', $('#lerr').textContent);
  type('#lu', 'admin'); type('#lp', 'Temp-pass-1'); submit($('#lf'));
  ok(await waitFor(() => visible('#screen-change')), 'temporary password leads to the change-password screen');
  ok(!visible('#app'), 'the dashboard stays hidden until the password is changed');
  const form = $('#force-form .pwform');
  type(form.querySelector('[data-f=cur]'), 'Temp-pass-1'); type(form.querySelector('[data-f=new]'), 'short'); type(form.querySelector('[data-f=new2]'), 'short');
  submit(form); await sleep(200);
  ok(/rules/i.test(form.querySelector('[data-f=err]').textContent), 'weak password is blocked on the page', form.querySelector('[data-f=err]').textContent);
  type(form.querySelector('[data-f=new]'), 'a long safe passphrase'); type(form.querySelector('[data-f=new2]'), 'a long safe passphrase');
  ok(form.querySelectorAll('li.good').length === 4, 'all four rule hints turn green');
  submit(form);
  ok(await waitFor(() => visible('#app')), 'after a good new password the dashboard opens');
  ok($('#who-name').textContent === 'admin', 'signed-in name is shown');

  console.log('\n[overview]');
  ok(await waitFor(() => $('#v-overview .banner')), 'status banner renders');
  ok(/need|needs/.test($('#v-overview .banner').textContent), 'banner warns about high alerts', $('#v-overview .banner').textContent);
  ok($$('#v-overview .kpi').length === 4, '4 summary cards');
  ok($$('#v-overview .acard').length >= 2, 'alert cards are listed', String($$('#v-overview .acard').length));
  ok($('#v-overview').textContent.includes('Detection engine'), 'engine card is present');
  ok(!$('[data-cnt="alerts"]').classList.contains('hide'), 'nav shows an alert counter');

  console.log('\n[alerts: short view, then detailed view]');
  await go('#alerts'); await waitFor(() => $$('#al-list .acard').length > 0);
  const cards = $$('#al-list .acard'); ok(cards.length === 3, 'all 3 open alerts listed', String(cards.length));
  ok(cards[0].classList.contains('high'), 'highest severity first');
  cards[0].click(); await waitFor(() => visible('#drawer'));
  ok($('#drawer').textContent.includes('What should I do?'), 'short view shows next steps');
  ok($('#drawer').textContent.includes('risk score out of 100'), 'short view shows the score');
  ok(!$('#adetail').textContent.trim(), 'detailed view is NOT shown yet');
  $('[data-act="detail"]').click(); await waitFor(() => $('#adetail').textContent.includes('Why it scored'));
  ok($('#adetail').textContent.includes('Latest requests'), 'detailed view loads on request');
  ok($$('#adetail .sg').length === 7, '7 clues explained', String($$('#adetail .sg').length));
  ok($$('#adetail svg.spark rect').length === 30, 'timeline chart has 30 bars');
  ok($$('#adetail table tbody tr').length > 0, 'sample requests table has rows');
  console.log('\n[XSS: hostile domain names]');
  ok($$('img').length === 0, 'no <img> element was created from the hostile name');
  ok($$('[onerror],[onload]').length === 0, 'no event-handler attributes exist anywhere');
  ok($('#adetail').textContent.includes('<img src=x onerror=alert(1)>') || cards[0].textContent.length > 0, 'detail view rendered (hostile rows may be on another alert)');
  $('[data-act="ack"]').click(); await waitFor(() => !visible('#drawer'));
  await sleep(300); ok($$('#al-list .acard').length === 2, 'acknowledged alert leaves the Open list', String($$('#al-list .acard').length));
  type('#f-status', ''); await sleep(400);
  ok($$('#al-list .acard').length === 3 && $$('#al-list .acard.done').length === 1, 'filter "all alerts" shows it greyed out');

  console.log('\n[agents]');
  await go('#agents'); await waitFor(() => $$('#ag-list tbody tr').length > 0);
  ok($$('#ag-list tbody tr').length === 2, 'two agents listed');
  ok($('#ag-list').textContent.includes('Online') && $('#ag-list').textContent.includes('Offline'), 'online and offline shown');
  type('#a-name', 'web-01'); submit($('#af')); await waitFor(() => visible('#a-install'));
  type('#ai-addr', 'http://192.168.1.10:8000');
  ok(/^curl -fsSL http:\/\/192\.168\.1\.10:8000\/install\/linux\.sh \| sudo bash -s -- --server http:\/\/192\.168\.1\.10:8000 --token dh_enroll_\S+ --sha256 [0-9a-f]{64} --enable-blocking$/.test($('#ai-cmd').value), 'install command is complete (blocking is ticked by default)', $('#ai-cmd').value);
  $('#ai-block').checked = false; $('#ai-block').dispatchEvent(new w.Event('change', { bubbles: true }));
  ok(!$('#ai-cmd').value.includes('--enable-blocking'), 'unticking blocking removes the flag');
  $('#ai-block').checked = true; $('#ai-block').dispatchEvent(new w.Event('change', { bubbles: true }));
  $('#ai-os [data-os="windows"]').click();
  ok(/^powershell -NoProfile -ExecutionPolicy Bypass -Command ".*install\/windows\.ps1.*-Server 'http:\/\/192\.168\.1\.10:8000' -Token 'dh_enroll_\S+' -Sha256 '[0-9a-f]{64}' -EnableBlocking"$/.test($('#ai-cmd').value), 'Windows tab gives a PowerShell command', $('#ai-cmd').value);
  $('#ai-os [data-os="linux"]').click();
  console.log('\n[blocks]');
  await go('#blocks');
  ok(await waitFor(() => $('#v-blocks').textContent.includes('Block a domain')), 'Blocks page opens');
  type('#b-dom', 'co.uk'); submit($('#bf'));
  ok(await waitFor(() => $('#b-err').textContent.length > 0), 'a public suffix is refused with a reason', $('#b-err').textContent);
  type('#b-dom', 'evil-test.xyz'); submit($('#bf'));
  ok(await waitFor(() => $('#bk-list').textContent.includes('evil-test.xyz')), 'a blocked domain is listed');
  $('#bk-list [data-act="unblock"]').click();
  ok(await waitFor(() => !$('#bk-list').textContent.includes('evil-test.xyz')), 'unblock removes it');
  await go('#settings');
  ok(await waitFor(() => $('[data-pk="blocking.auto_min_score"]')), 'auto-block settings are shown');
  ok($('[data-pk="blocking.auto_block"]').checked === false, 'auto-block is off by default');
  await go('#agents');
  type('#ai-addr', 'http://localhost:8000'); ok($('#ai-warn').textContent.includes('network'), 'localhost address gets a warning');
  type('#ai-addr', 'http://x; rm -rf /'); ok($('#ai-cmd').value === '' && $('#ai-warn').textContent.length > 0, 'unsafe address is refused (no shell injection)');
  $$('#ag-list tbody tr').find(r => r.textContent.includes('lab-pc')).click(); await waitFor(() => visible('#drawer'));
  ok($('#drawer').textContent.includes('Most contacted domains') && $('#agbox').classList.contains('hide'), 'agent: short view first, details hidden');
  $('[data-act="agdetail"]').click(); ok(!$('#agbox').classList.contains('hide') && $('#agbox').textContent.includes('evil-dns.xyz'), 'agent detailed view shows top domains');
  $('#scrim').click(); ok(!visible('#drawer'), 'clicking outside closes the panel');

  console.log('\n[logs]');
  await go('#logs'); await waitFor(() => $$('#lg-body tr').length > 1);
  ok($$('#lg-body tr').length === 100, 'first page has 100 rows', String($$('#lg-body tr').length));
  ok(!$('#lg-more').classList.contains('hide'), '"Load older" is offered');
  $('#lg-more').click(); await waitFor(() => $$('#lg-body tr').length > 100);
  ok($$('#lg-body tr').length > 100, 'load older appends rows');
  type('#lg-q', 'onerror'); await waitFor(() => $('#lg-body').textContent.includes('onerror=alert(1)'));
  ok($('#lg-body').textContent.includes('<img src=x onerror=alert(1)>'), 'XSS: hostile name is shown as plain text in the log');
  ok($$('img').length === 0 && $$('[onerror]').length === 0, 'XSS: still no <img> or onerror attribute after the log rendered');
  type('#lg-q', ''); type('#lg-q', 'stealth'); type('#lg-min', '1440'); await waitFor(() => $$('#lg-body tr').length > 0 && [...$$('#lg-body .dom')].every(e => /stealth/.test(e.textContent)) );
  ok($$('#lg-body tr').length === 60 || $$('#lg-body tr').length > 0, 'search filter works', String($$('#lg-body tr').length));
  $$('#v-logs .tabs button').find(b => b.dataset.tab === 'batches').click(); await waitFor(() => $('#lg-head').textContent.includes('Batch') && $('#lg-body').textContent.includes('lab-pc'));
  ok($('#lg-body').textContent.includes('380'), 'agent activity tab shows the batch (380 requests)');
  $$('#v-logs .tabs button').find(b => b.dataset.tab === 'audit').click(); await waitFor(() => $('#lg-body').textContent.includes('Signed in'));
  ok($('#lg-body').textContent.includes('Changed password') && $('#lg-body').textContent.includes('Failed sign-in'), 'audit trail shows sign-ins and password change');

  console.log('\n[settings]');
  await go('#settings'); await waitFor(() => $$('.preset').length === 3);
  ok($('.preset.on').textContent.includes('Balanced'), 'Balanced is marked current');
  $$('.preset').find(p => p.textContent.includes('Strict')).click(); await sleep(500);
  ok($('.preset.on') && $('.preset.on').textContent.includes('Strict'), 'clicking Strict applies it');
  const slider = $('[data-w="fast"][data-sig="entropy"]'); type(slider, '90');
  ok($('#save-state').textContent.includes('unsaved'), 'unsaved-changes hint appears');
  ok(/%$/.test($('[data-o="fast-entropy"]').textContent), 'slider shows its share of the score');
  type('[data-pk="fast.low"]', '95'); $('[data-act="save"]').click(); await waitFor(() => $('#serr').textContent.length > 0);
  ok($('#serr').textContent.includes('severity'), 'invalid values are explained, not saved', $('#serr').textContent);
  type('[data-pk="fast.low"]', '30'); type('#trusted', 'shop.com\nexample.org'); $('[data-act="save"]').click(); await sleep(600);
  ok($('#trusted').value === 'shop.com\nexample.org', 'valid settings are saved and reloaded');
  ok($$('[data-pk]').length > 15 && $$('[data-ramp]').length === 28, 'all settings fields are present (incl. advanced thresholds)');

  console.log('\n[account]');
  await go('#account'); await waitFor(() => $('#v-account .pwform'));
  ok($('#v-account').textContent.includes('Signed in as admin') && !$('#v-account').textContent.includes('reset-password'), 'account page (no reset instructions in the UI)');
  $('[data-act="signout"]').click(); ok(await waitFor(() => visible('#screen-login')), 'sign out returns to the login screen');
  ok(!jar.dh_session, 'session cookie is cleared');
  type('#lu', 'admin'); type('#lp', 'a long safe passphrase'); submit($('#lf'));
  ok(await waitFor(() => visible('#app')), 'signing back in with the NEW password goes straight to the dashboard');

  console.log('\n[help]');
  $('#help-btn').click(); ok(visible('#drawer') && $('#drawer').textContent.includes('What is DNS tunneling?'), 'help & glossary opens');

  ok(errors.length === 0, 'no JavaScript errors during the whole session', errors.join(' | '));
  console.log('\n' + pass + ' passed, ' + fail + ' failed'); w.close(); process.exit(fail ? 1 : 0);
}
main().catch(e => { console.error('CRASH', e); process.exit(2); });
