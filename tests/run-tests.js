// Automated T1 to T8 security test matrix (plus a few extra negative tests).
// Starts its own server on port 3100 with a separate, freshly seeded test datastore,
// drives it over real HTTP with a software passkey authenticator, and writes
// tests/results.md and tests/server-log.txt as evidence.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SoftAuthenticator } from './soft-authenticator.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const PORT = 3100;
const ORIGIN = `http://localhost:${PORT}`;
const TEST_DB = path.join(ROOT, 'data', 'test-db.json');

process.env.DB_FILE = TEST_DB;
const { seed } = await import('../src/seed.js');
const codes = seed();

// ---- start server ----
const serverLog = [];
const server = spawn(process.execPath, [path.join(ROOT, 'src', 'server.js')], {
  env: { ...process.env, PORT: String(PORT), DB_FILE: TEST_DB },
  stdio: ['ignore', 'pipe', 'pipe'],
});
server.stdout.on('data', (d) => serverLog.push(...d.toString().trim().split('\n')));
server.stderr.on('data', (d) => serverLog.push(...d.toString().trim().split('\n')));
await new Promise((ok, fail) => {
  const t = setTimeout(() => fail(new Error('server did not start')), 8000);
  server.stdout.on('data', (d) => d.toString().includes('listening') && (clearTimeout(t), ok()));
});

// ---- tiny HTTP client with its own cookie jar (one per browser/identity) ----
class Client {
  constructor(label) { this.label = label; this.cookie = ''; }
  async req(method, url, body) {
    const res = await fetch(ORIGIN + url, {
      method,
      headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(this.cookie ? { Cookie: this.cookie } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const set = res.headers.getSetCookie?.() || [];
    for (const c of set) {
      const pair = c.split(';')[0];
      if (pair.startsWith('portal.sid=')) this.cookie = pair.endsWith('=') ? '' : pair;
    }
    let data = null; try { data = await res.json(); } catch {}
    return { status: res.status, data };
  }
}

const auth = new SoftAuthenticator({ origin: ORIGIN, rpId: 'localhost' });

async function register(client, userId) {
  const s = await client.req('POST', '/api/enroll/start', { userId, enrollmentCode: codes[userId] });
  if (s.status !== 200) return s;
  const o = await client.req('POST', '/api/register/options');
  return client.req('POST', '/api/register/verify', auth.create(o.data));
}
async function login(client, userId) {
  const o = await client.req('POST', '/api/login/options', { userId });
  return client.req('POST', '/api/login/verify', auth.get(o.data));
}
const readDb = () => JSON.parse(fs.readFileSync(TEST_DB, 'utf8'));
const gradeOf = (sid, cid) => readDb().enrollments.find((e) => e.studentId === sid && e.courseId === cid).grade;

// ---- results ----
const results = [];
function record(id, identity, action, expected, observed, pass) {
  results.push({ id, identity, action, expected, observed, pass });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${id.padEnd(4)} ${identity.padEnd(14)} ${action}  ->  ${observed}`);
}

try {
  // ===== T1: S001 registers a passkey =====
  const s001 = new Client('S001');
  let r = await register(s001, 'S001');
  const stored = readDb().credentials.find((c) => c.userId === 'S001');
  record('T1', 'S001', 'Enroll with one-time code, register passkey', 'Credential bound to S001; public key stored',
    `HTTP ${r.status}; credential ${stored?.id.slice(0, 10)}… stored for ${stored?.userId}, publicKey ${stored?.publicKey.length} chars (b64url COSE)`,
    r.status === 200 && stored?.userId === 'S001' && !!stored.publicKey);

  // setup: register S002 and L001 too
  await register(new Client('S002'), 'S002');
  await register(new Client('L001'), 'L001');

  // ===== T2: S001 signs in =====
  r = await login(s001, 'S001');
  const me = await s001.req('GET', '/api/me');
  record('T2', 'S001', 'Sign in with registered passkey', 'Fresh challenge verified; session created',
    `HTTP ${r.status}; GET /api/me -> ${me.status} (${me.data?.id}, ${me.data?.role})`, r.status === 200 && me.status === 200 && me.data.id === 'S001');

  // ===== T3a: altered signature =====
  let attacker = new Client('attacker');
  let o = await attacker.req('POST', '/api/login/options', { userId: 'S001' });
  let resp = auth.get(o.data);
  const sig = Buffer.from(resp.response.signature, 'base64url'); sig[sig.length - 1] ^= 0x01;
  resp.response.signature = sig.toString('base64url');
  r = await attacker.req('POST', '/api/login/verify', resp);
  let after = await attacker.req('GET', '/api/me');
  record('T3a', 'S001 (altered)', 'Submit sign-in response with 1 bit of signature flipped', 'Rejected; no session',
    `HTTP ${r.status} ${JSON.stringify(r.data)}; GET /api/me -> ${after.status}`, r.status === 401 && after.status === 401);

  // ===== T3b: replayed response =====
  const victim = new Client('S001-b');
  o = await victim.req('POST', '/api/login/options', { userId: 'S001' });
  const captured = auth.get(o.data);
  const firstUse = await victim.req('POST', '/api/login/verify', captured);
  attacker = new Client('attacker');
  await attacker.req('POST', '/api/login/options', { userId: 'S001' }); // attacker gets a new challenge
  r = await attacker.req('POST', '/api/login/verify', captured); // ...and replays the old signed response
  after = await attacker.req('GET', '/api/me');
  record('T3b', 'S001 (replay)', 'Replay a previously accepted sign-in response', 'Rejected (challenge mismatch); no session',
    `1st use HTTP ${firstUse.status}; replay HTTP ${r.status}; GET /api/me -> ${after.status}`, firstUse.status === 200 && r.status === 401 && after.status === 401);

  // ===== T3c: response signed for a phishing origin =====
  attacker = new Client('attacker');
  o = await attacker.req('POST', '/api/login/options', { userId: 'S001' });
  r = await attacker.req('POST', '/api/login/verify', auth.get(o.data, { origin: 'http://portal-login.example' }));
  after = await attacker.req('GET', '/api/me');
  record('T3c', 'S001 (phish)', 'Valid signature but clientData origin = phishing site', 'Rejected (origin mismatch); no session',
    `HTTP ${r.status}; GET /api/me -> ${after.status}`, r.status === 401 && after.status === 401);

  // ===== T4: no session =====
  const anon = new Client('anon');
  r = await anon.req('GET', '/api/students/S001');
  record('T4', 'Unauthenticated', 'GET /api/students/S001 with no session cookie', 'Denied (401)', `HTTP ${r.status} ${JSON.stringify(r.data)}`, r.status === 401);

  // ===== T5: own record =====
  r = await s001.req('GET', '/api/students/S001');
  record('T5', 'S001', 'GET /api/students/S001', 'Allowed', `HTTP ${r.status}; ${r.data?.name}, ${r.data?.enrollments?.length} enrollments`, r.status === 200 && r.data.id === 'S001');

  // ===== T6: another student's record by changing the ID =====
  r = await s001.req('GET', '/api/students/S002');
  record('T6', 'S001', 'GET /api/students/S002 (ID changed in URL)', 'Denied by server (403/404)', `HTTP ${r.status} ${JSON.stringify(r.data)}`, r.status === 403 && !r.data?.name);

  // ===== T7: student calls lecturer endpoint directly =====
  const beforeGrade = gradeOf('S001', 'C101');
  r = await s001.req('POST', '/api/courses/C101/grades/S001', { grade: 'A' });
  const afterGrade = gradeOf('S001', 'C101');
  record('T7', 'S001', 'POST /api/courses/C101/grades/S001 {"grade":"A"}', 'Denied; grade unchanged',
    `HTTP ${r.status}; grade before ${beforeGrade}, after ${afterGrade}`, r.status === 403 && beforeGrade === afterGrade);

  // ===== T8: lecturer updates grade in assigned course =====
  const l001 = new Client('L001');
  await login(l001, 'L001');
  const g0 = gradeOf('S002', 'C101');
  r = await l001.req('POST', '/api/courses/C101/grades/S002', { grade: 'A-' });
  const g1 = gradeOf('S002', 'C101');
  const audit = readDb().gradeAudit.at(-1);
  record('T8', 'L001', 'POST /api/courses/C101/grades/S002 {"grade":"A-"}', 'Allowed; lecturer/course verified',
    `HTTP ${r.status}; grade ${g0} -> ${g1}; audit entry by ${audit?.by}`, r.status === 200 && g1 === 'A-');

  // ===== extra negative tests =====
  const g2 = gradeOf('S003', 'C102');
  r = await l001.req('POST', '/api/courses/C102/grades/S003', { grade: 'F' });
  record('X1', 'L001', 'POST grade in C102 (not assigned)', 'Denied; grade unchanged', `HTTP ${r.status}; grade ${g2} -> ${gradeOf('S003', 'C102')}`, r.status === 403 && gradeOf('S003', 'C102') === g2);

  r = await l001.req('GET', '/api/students/S003');
  record('X2', 'L001', 'GET /api/students/S003 (not in L001\'s course)', 'Denied', `HTTP ${r.status}`, r.status === 403);

  r = await l001.req('GET', '/api/students/S001');
  record('X3', 'L001', 'GET /api/students/S001 (in C101)', 'Allowed, C101 grades only', `HTTP ${r.status}; courses shown: ${r.data?.enrollments?.map((e) => e.courseId).join(',')}`,
    r.status === 200 && r.data.enrollments.every((e) => e.courseId === 'C101'));

  r = await new Client('x').req('POST', '/api/enroll/start', { userId: 'S001', enrollmentCode: codes.S001 });
  record('X4', 'S001 code', 'Reuse S001 enrollment code to register attacker passkey', 'Denied (code is single-use)', `HTTP ${r.status}`, r.status === 403);

  r = await l001.req('POST', '/api/logout');
  const post = await l001.req('GET', '/api/courses/C101/roster');
  record('X5', 'L001', 'POST /api/logout, then GET roster', 'Session invalidated; 401', `logout HTTP ${r.status}; roster HTTP ${post.status}`, r.status === 200 && post.status === 401);
} finally {
  server.kill();
}

// ---- write evidence ----
const passed = results.filter((x) => x.pass).length;
const md = [
  `# Security test results`,
  ``,
  `Run: ${new Date().toISOString()} · server ${ORIGIN} · Node ${process.version} · ${passed}/${results.length} passed`,
  ``,
  `| Test | Identity | Action | Expected | Observed | Result |`,
  `|---|---|---|---|---|---|`,
  ...results.map((x) => `| ${x.id} | ${x.identity} | ${x.action} | ${x.expected} | ${x.observed.replace(/\|/g, '\\|')} | ${x.pass ? 'PASS' : 'FAIL'} |`),
  ``,
].join('\n');
fs.writeFileSync(path.join(__dirname, 'results.md'), md);
fs.writeFileSync(path.join(__dirname, 'server-log.txt'), serverLog.join('\n') + '\n');
console.log(`\n${passed}/${results.length} passed. Evidence written to tests/results.md and tests/server-log.txt`);
process.exit(passed === results.length ? 0 : 1);
