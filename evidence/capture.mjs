// Evidence capture for T1-T8 and Part B against the running portal, using Playwright + Chromium.
// Passkeys come from Chromium's CDP virtual WebAuthn authenticator, so the real browser
// WebAuthn flow and the real server-side verification are exercised end to end.
//
// Usage:  BASE_URL=http://localhost:3000 node evidence/capture.mjs
// Enrollment codes are read from S001_CODE / L001_CODE if set, otherwise from the
// gitignored data/db-enrollment-codes.txt written by the seed step; never stored here.
import { chromium } from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = path.dirname(fileURLToPath(import.meta.url));
const BASE = process.env.BASE_URL || 'http://localhost:3000';
const codesFile = path.join(OUT, '..', 'data', 'db-enrollment-codes.txt');
const seeded = fs.existsSync(codesFile)
  ? Object.fromEntries(fs.readFileSync(codesFile, 'utf8').trim().split('\n').map((l) => l.trim().split(/\s+/)))
  : {};
const CODES = { S001: process.env.S001_CODE || seeded.S001, L001: process.env.L001_CODE || seeded.L001 };
if (!CODES.S001 || !CODES.L001) throw new Error('No enrollment codes: run `npm run seed -- --reset` or set S001_CODE and L001_CODE.');

const browser = await chromium.launch();

// One browser context (own cookie jar) and one virtual authenticator per account.
async function openAs() {
  const context = await browser.newContext({ viewport: { width: 1360, height: 900 }, deviceScaleFactor: 1 });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    },
  });
  return { context, page };
}

const logText = (page) => page.locator('#log').innerText();
async function waitForLog(page, needle, timeout = 15000) {
  await page.waitForFunction((n) => document.getElementById('log').textContent.includes(n), needle, { timeout });
}
async function openActivityLog(page) {
  const details = page.locator('details.activity');
  if (!(await details.getAttribute('open'))) await page.locator('details.activity summary').click();
}
async function shot(page, name) {
  await page.waitForTimeout(1500); // let the sign-in transition settle
  await page.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: true });
  console.log(`saved ${name}.png`);
}

async function register(page, id) {
  await page.goto(`${BASE}/`);
  await page.click('#mode-toggle');
  await page.fill('#enroll-id', id);
  await page.fill('#enroll-code', CODES[id]);
  await openActivityLog(page);
  await page.click('#btn-register');
  await waitForLog(page, 'POST /api/register/verify');
}
async function signIn(page, id) {
  await page.goto(`${BASE}/`);
  await page.fill('#login-id', id);
  await openActivityLog(page);
  await page.click('#btn-login');
  await waitForLog(page, 'POST /api/login/verify');
  await page.waitForSelector('#signed-in:not([hidden])');
}

const observed = {};

// ---- T1 + T2: S001 registers, then signs in ----
const s = await openAs();
await register(s.page, 'S001');
observed.T1 = (await logText(s.page)).split('\n').find((l) => l.includes('/api/register/verify'));
await shot(s.page, 'T1_register_S001');

await signIn(s.page, 'S001');
await s.page.waitForSelector('#my-record table');
observed.T2 = (await logText(s.page)).split('\n').find((l) => l.includes('/api/login/verify'));
await shot(s.page, 'T2_signin_S001_record');

// ---- T3: tampered and replayed sign-in responses (security test page) ----
await s.page.goto(`${BASE}/security-tests.html`);
await s.page.click('#t3a');
await waitForLog(s.page, 'GET /api/me afterwards');
await s.page.click('#t3b');
await s.page.waitForFunction(() => (document.getElementById('log').textContent.match(/GET \/api\/me afterwards/g) || []).length >= 2);
observed.T3 = await logText(s.page);
await shot(s.page, 'T3_tampered_and_replayed_rejected');

// ---- T5, T6, T7: signed in as S001, direct requests ----
await signIn(s.page, 'S001');
await s.page.goto(`${BASE}/security-tests.html`);
await s.page.click('#t5'); await waitForLog(s.page, 'T5 GET');
await s.page.click('#t6'); await waitForLog(s.page, 'T6 GET');
await s.page.click('#t7'); await waitForLog(s.page, 'grade is still');
observed.T5_T7 = await logText(s.page);
await shot(s.page, 'T5_T6_T7_direct_requests_S001');

// ---- T4: log out, then request a protected record ----
await s.page.click('#t4'); await waitForLog(s.page, 'T4 (after logout)');
observed.T4 = (await logText(s.page)).split('\n').find((l) => l.startsWith('T4'));
await shot(s.page, 'T4_no_session_denied');

// ---- Part B: encrypted export from the security test page, signed in again as S001 ----
await signIn(s.page, 'S001');
await s.page.goto(`${BASE}/security-tests.html`);
await s.page.click('#b1'); await waitForLog(s.page, 'decrypted === original');
await s.page.click('#b2'); await waitForLog(s.page, 'nonces differ');
await s.page.click('#b3'); await waitForLog(s.page, 'original still decrypts');
await s.page.click('#b4'); await waitForLog(s.page, 'S002/export as S001');
observed.PartB = await logText(s.page);
await shot(s.page, 'PartB_encrypted_export_S001');
await s.context.close();

// ---- T8: L001 registers, signs in, updates S002's C101 grade ----
const l = await openAs();
await register(l.page, 'L001');
await signIn(l.page, 'L001');
await l.page.waitForSelector('#roster select[data-sid="S002"]');
await l.page.selectOption('#roster select[data-sid="S002"]', 'A-');
await l.page.click('#roster button[data-save="S002"]');
await waitForLog(l.page, 'POST /api/courses/C101/grades/S002');
observed.T8 = (await logText(l.page)).split('\n').find((l2) => l2.includes('/grades/S002'));
await shot(l.page, 'T8_L001_updates_S002_grade');
await l.context.close();

// ---- Terminal evidence: npm test output and server deny/fail lines, rendered as-is ----
const esc = (t) => t.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]);
async function renderText(title, text, name) {
  const page = await browser.newPage({ viewport: { width: 1360, height: 400 } });
  await page.setContent(`<!doctype html><meta charset="utf-8"><body style="margin:0;background:#1d1a19;color:#e6ddd6;font:13px/1.55 Menlo,monospace">
    <div style="padding:10px 18px;background:#2a2523;color:#bdb3ac;font-family:system-ui,sans-serif">${esc(title)}</div>
    <pre style="margin:0;padding:16px 18px;white-space:pre-wrap">${esc(text)}</pre></body>`);
  await page.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: true });
  console.log(`saved ${name}.png`);
  await page.close();
}
await renderText('$ npm test', fs.readFileSync(path.join(OUT, 'npm-test-output.txt'), 'utf8').trim(), 'npm_test_output');
const denyLines = fs.readFileSync(path.join(OUT, 'server-log.txt'), 'utf8').split('\n')
  .filter((x) => /AUTHZ DENY|LOGIN FAIL/.test(x)).join('\n');
await renderText('evidence/server-log.txt  (lines matching AUTHZ DENY | LOGIN FAIL)', denyLines || '(no matching lines)', 'server_deny_fail_lines');

fs.writeFileSync(path.join(OUT, 'observed.json'), JSON.stringify(observed, null, 2));
await browser.close();
