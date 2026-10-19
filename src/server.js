// Secure Student Records Portal (ICS570 Lab 2). Synthetic data, local lab use only.
// Authentication: WebAuthn passkeys verified server-side with @simplewebauthn/server.
// Authorization: server-side RBAC + record-level checks in src/policy.js, applied on every protected route.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import session from 'express-session';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import * as db from './db.js';
import { sha256, seed, CODES_FILE } from './seed.js';
import { canReadStudent, canUpdateGrade, canReadRoster, visibleEnrollments } from './policy.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---- Relying-party configuration (checked on every registration and login) ----
const PORT = Number(process.env.PORT || 3000);
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;
const RP_NAME = 'Student Records Portal (Lab)';
const ALLOWED_GRADES = ['A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D', 'F'];

// First run: seed synthetic data so `npm start` works straight after `npm install`.
// The hosted demo loads (and if needed seeds) its datastore from Redis per request instead.
if (!db.HOSTED) {
  if (!fs.existsSync(db.DB_FILE)) seed();
  db.load();
}

// Hosted demo only: sessions live in Redis so every serverless instance sees the same
// session, including the stored challenge that sign-in consumes (replay protection).
class RedisSessionStore extends session.Store {
  get(sid, cb) { db.redis.get(`sess:${sid}`).then((s) => cb(null, s ?? null), cb); }
  set(sid, sess, cb) { db.redis.set(`sess:${sid}`, sess, { ex: 30 * 60 }).then(() => cb?.(), cb); }
  destroy(sid, cb) { db.redis.del(`sess:${sid}`).then(() => cb?.(), cb); }
}

const app = express();
app.disable('x-powered-by');
if (process.env.VERCEL) app.set('trust proxy', 1); // HTTPS ends at Vercel's proxy; needed for secure cookies
app.use(express.json({ limit: '32kb' }));

// Request log: method, path, status, user. No bodies, cookies, challenges or credentials are logged.
app.use((req, res, next) => {
  res.on('finish', () => {
    const who = req.session?.userId || '-';
    console.log(`${new Date().toISOString()} ${req.method} ${req.path} -> ${res.statusCode} user=${who}`);
  });
  next();
});

app.use(
  session({
    name: 'portal.sid',
    store: db.HOSTED ? new RedisSessionStore() : undefined, // default in-memory store locally
    // Random per process unless set; sessions do not survive a restart (acceptable for a lab).
    // The hosted demo sets SESSION_SECRET so all instances sign cookies the same way.
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // not readable from page JavaScript
      sameSite: 'strict', // not sent on cross-site requests (CSRF mitigation)
      secure: ORIGIN.startsWith('https://'), // localhost over http is a WebAuthn secure context
      maxAge: 30 * 60 * 1000, // 30 minutes
    },
  }),
);

// Hosted demo: load the current datastore from Redis before any API route runs.
if (db.HOSTED) {
  app.use('/api', async (req, res, next) => {
    if (!(await db.refresh())) await seed();
    next();
  });
}

// Static UI + the SimpleWebAuthn browser bundle
app.use(express.static(path.join(__dirname, '..', 'public')));
app.get('/vendor/simplewebauthn-browser.js', (req, res) =>
  res.sendFile(path.join(__dirname, '..', 'node_modules', '@simplewebauthn', 'browser', 'dist', 'bundle', 'index.umd.min.js')),
);

// ---- helpers ----
const regenerate = (req) => new Promise((ok, fail) => req.session.regenerate((e) => (e ? fail(e) : ok())));
const b64urlToBytes = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const safeEqualHex = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
// Library error messages can echo challenge values; strip quoted values before logging.
const redact = (msg) => String(msg).replace(/"[^"]*"/g, '"[redacted]"');
const userView = (u) => ({ id: u.id, role: u.role, displayName: u.displayName });

function logDenied(req, action, reason) {
  console.warn(`AUTHZ DENY user=${req.user?.id || '-'} role=${req.user?.role || '-'} action=${action} reason="${reason}"`);
}

// ---- Authentication middleware: no valid session -> 401 ----
function requireAuth(req, res, next) {
  const user = req.session.userId ? db.findUser(req.session.userId) : null;
  if (!user) return res.status(401).json({ error: 'authentication required' });
  req.user = user; // role is re-read from the datastore on every request, so role changes apply immediately
  next();
}

// =====================================================================
// 1. ENROLLMENT + PASSKEY REGISTRATION
// =====================================================================
// Step 1: prove you are the account holder with the one-time enrollment code
// (a stand-in for the code a registrar would hand out in person / by verified email).
app.post('/api/enroll/start', async (req, res) => {
  const { userId, enrollmentCode } = req.body || {};
  const user = typeof userId === 'string' ? db.findUser(userId.trim().toUpperCase()) : null;
  const ok =
    user &&
    !user.enrollmentUsed &&
    typeof enrollmentCode === 'string' &&
    safeEqualHex(sha256(enrollmentCode.trim().toUpperCase()), user.enrollmentCodeHash);
  if (!ok) return res.status(403).json({ error: 'invalid or already-used enrollment code' });

  await regenerate(req);
  req.session.enrollUserId = user.id; // enrollment-only session: cannot read records
  res.json({ ok: true });
});

// Step 2: issue a one-time registration challenge. Allowed for an enrollment
// session (first passkey) or a fully signed-in user (adding another passkey).
app.post('/api/register/options', async (req, res) => {
  const userId = req.session.userId || req.session.enrollUserId;
  const user = userId ? db.findUser(userId) : null;
  if (!user) return res.status(401).json({ error: 'enrollment or sign-in required' });

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: user.id,
    userDisplayName: user.displayName,
    userID: b64urlToBytes(user.webauthnUserId),
    attestationType: 'none',
    excludeCredentials: db.credentialsFor(user.id).map((c) => ({ id: c.id, transports: c.transports })),
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
  });
  req.session.regChallenge = options.challenge;
  res.json(options);
});

// Step 3: verify the authenticator's response and bind the public key to the account.
app.post('/api/register/verify', async (req, res) => {
  const userId = req.session.userId || req.session.enrollUserId;
  const user = userId ? db.findUser(userId) : null;
  const expectedChallenge = req.session.regChallenge;
  delete req.session.regChallenge; // one-time: consumed whether or not verification succeeds
  if (!user || !expectedChallenge) return res.status(400).json({ error: 'no registration in progress' });

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
    });
  } catch (err) {
    console.warn(`REGISTER FAIL user=${user.id} reason="${redact(err.message)}"`);
    return res.status(400).json({ error: 'registration verification failed' });
  }
  if (!verification.verified) return res.status(400).json({ error: 'registration not verified' });

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  if (db.findCredential(credential.id)) return res.status(409).json({ error: 'credential already registered' });

  const data = db.load();
  data.credentials.push({
    id: credential.id,
    userId: user.id,
    publicKey: Buffer.from(credential.publicKey).toString('base64url'), // public key only; no private key ever reaches the server
    counter: credential.counter,
    transports: credential.transports || [],
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,
    createdAt: new Date().toISOString(),
  });
  if (req.session.enrollUserId) user.enrollmentUsed = true; // enrollment code is single-use
  await db.save();
  console.log(`REGISTER OK user=${user.id} credential=${credential.id.slice(0, 8)}…`);

  // End the enrollment session; the user must now sign in with the passkey.
  if (req.session.enrollUserId) await regenerate(req);
  res.json({ ok: true, userId: user.id, credentialId: credential.id });
});

// =====================================================================
// 2. PASSKEY SIGN-IN
// =====================================================================
app.post('/api/login/options', async (req, res) => {
  const userId = typeof req.body?.userId === 'string' ? req.body.userId.trim().toUpperCase() : '';
  const user = db.findUser(userId);
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'required',
    // Unknown users get an empty list, so the response does not reveal which IDs exist.
    allowCredentials: user ? db.credentialsFor(user.id).map((c) => ({ id: c.id, transports: c.transports })) : [],
  });
  req.session.authChallenge = options.challenge; // fresh, random, single-use
  req.session.authUserId = user ? user.id : null;
  res.json(options);
});

app.post('/api/login/verify', async (req, res) => {
  const expectedChallenge = req.session.authChallenge;
  const expectedUserId = req.session.authUserId;
  delete req.session.authChallenge; // consume immediately: a replayed response can never match again
  delete req.session.authUserId;
  if (!expectedChallenge) return res.status(400).json({ error: 'no sign-in in progress' });

  const cred = typeof req.body?.id === 'string' ? db.findCredential(req.body.id) : null;
  if (!cred || (expectedUserId && cred.userId !== expectedUserId)) {
    console.warn('LOGIN FAIL reason="unknown credential or credential not bound to this account"');
    return res.status(401).json({ error: 'sign-in failed' });
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: { id: cred.id, publicKey: b64urlToBytes(cred.publicKey), counter: cred.counter, transports: cred.transports },
      requireUserVerification: true,
    });
  } catch (err) {
    console.warn(`LOGIN FAIL user=${cred.userId} reason="${redact(err.message)}"`);
    return res.status(401).json({ error: 'sign-in failed' });
  }
  if (!verification.verified) {
    console.warn(`LOGIN FAIL user=${cred.userId} reason="signature did not verify with the stored public key"`);
    return res.status(401).json({ error: 'sign-in failed' });
  }

  cred.counter = verification.authenticationInfo.newCounter;
  cred.lastUsedAt = new Date().toISOString();
  await db.save();

  await regenerate(req); // new session ID on login (prevents session fixation)
  req.session.userId = cred.userId;
  const user = db.findUser(cred.userId);
  console.log(`LOGIN OK user=${user.id} role=${user.role}`);
  res.json({ ok: true, user: userView(user) });
});

// =====================================================================
// 3. SESSION CONTROL
// =====================================================================
app.post('/api/logout', (req, res) => {
  const who = req.session.userId;
  req.session.destroy(() => {
    res.clearCookie('portal.sid');
    if (who) console.log(`LOGOUT user=${who}`);
    res.json({ ok: true });
  });
});

// =====================================================================
// 4. PROTECTED API: authentication (requireAuth) then authorization (policy.js)
// =====================================================================
app.get('/api/me', requireAuth, (req, res) => res.json(userView(req.user)));

app.get('/api/students/:studentId', requireAuth, (req, res) => {
  const { studentId } = req.params;
  const decision = canReadStudent(req.user, studentId);
  if (!decision.allowed) {
    logDenied(req, `read:student/${studentId}`, decision.reason);
    return res.status(403).json({ error: 'forbidden' });
  }
  const s = db.findStudent(studentId);
  res.json({ ...s, enrollments: visibleEnrollments(req.user, studentId) });
});

app.get('/api/courses/:courseId/roster', requireAuth, (req, res) => {
  const { courseId } = req.params;
  const decision = canReadRoster(req.user, courseId);
  if (!decision.allowed) {
    logDenied(req, `read:roster/${courseId}`, decision.reason);
    return res.status(403).json({ error: 'forbidden' });
  }
  const roster = db
    .load()
    .enrollments.filter((e) => e.courseId === courseId)
    .map((e) => ({ studentId: e.studentId, name: db.findStudent(e.studentId)?.name, grade: e.grade }));
  res.json({ courseId, title: db.findCourse(courseId).title, roster });
});

app.post('/api/courses/:courseId/grades/:studentId', requireAuth, async (req, res) => {
  const { courseId, studentId } = req.params;
  const decision = canUpdateGrade(req.user, courseId, studentId);
  if (!decision.allowed) {
    logDenied(req, `update:grade/${courseId}/${studentId}`, decision.reason);
    return res.status(403).json({ error: 'forbidden' });
  }
  const grade = req.body?.grade;
  if (!ALLOWED_GRADES.includes(grade)) return res.status(400).json({ error: `grade must be one of ${ALLOWED_GRADES.join(', ')}` });

  const enrollment = db.findEnrollment(courseId, studentId);
  const before = enrollment.grade;
  enrollment.grade = grade;
  db.load().gradeAudit.push({ at: new Date().toISOString(), by: req.user.id, courseId, studentId, before, after: grade });
  await db.save();
  console.log(`GRADE UPDATE by=${req.user.id} ${courseId}/${studentId} ${before} -> ${grade}`);
  res.json({ ok: true, courseId, studentId, before, after: grade });
});

// =====================================================================
// 5. PART B: AES-256-GCM encrypted export of one student record
// =====================================================================
// Same steps as partB/crypto-demo.js, behind the same authentication and
// authorization as GET /api/students/:studentId. The key is 256 random bits
// per server process, held in memory only; it is never sent or logged.
const EXPORT_KEY = crypto.randomBytes(32);

function gcmEncrypt(plaintext) {
  const nonce = crypto.randomBytes(12); // fresh 96-bit nonce for every encryption
  const cipher = crypto.createCipheriv('aes-256-gcm', EXPORT_KEY, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { nonce, ciphertext, tag: cipher.getAuthTag() };
}
function gcmDecrypt({ nonce, ciphertext, tag }) {
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', EXPORT_KEY, nonce);
    decipher.setAuthTag(tag);
    return { ok: true, plaintext: Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8') };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}
const flipBit = (buf, i) => { const copy = Buffer.from(buf); copy[i] ^= 0x01; return copy; };

app.post('/api/students/:studentId/export', requireAuth, (req, res) => {
  const { studentId } = req.params;
  const decision = canReadStudent(req.user, studentId);
  if (!decision.allowed) {
    logDenied(req, `export:student/${studentId}`, decision.reason);
    return res.status(403).json({ error: 'forbidden' });
  }
  const record = JSON.stringify({ ...db.findStudent(studentId), enrollments: visibleEnrollments(req.user, studentId) });

  const a = gcmEncrypt(record);
  const b = gcmEncrypt(record); // same record, same key, encrypted again
  const decrypted = gcmDecrypt(a);
  const tamperedCiphertext = gcmDecrypt({ ...a, ciphertext: flipBit(a.ciphertext, 5) });
  const tamperedTag = gcmDecrypt({ ...a, tag: flipBit(a.tag, 0) });
  const outcome = (r) => (r.ok ? 'decrypted (unexpected)' : `rejected: ${r.error}`);

  console.log(`EXPORT by=${req.user.id} student=${studentId} aes-256-gcm`);
  res.json({
    encrypt: {
      plaintextBytes: Buffer.byteLength(record),
      nonce: a.nonce.toString('hex'),
      ciphertext: `${a.ciphertext.subarray(0, 16).toString('hex')}… (${a.ciphertext.length} bytes)`,
      tag: a.tag.toString('hex'),
    },
    decrypt: { matchesOriginal: decrypted.ok && decrypted.plaintext === record },
    freshNonce: {
      nonceA: a.nonce.toString('hex'),
      nonceB: b.nonce.toString('hex'),
      noncesDiffer: !a.nonce.equals(b.nonce),
      ciphertextsDiffer: !a.ciphertext.equals(b.ciphertext),
    },
    tamper: {
      ciphertextByte5Flipped: outcome(tamperedCiphertext),
      tagByte0Flipped: outcome(tamperedTag),
      originalStillDecrypts: gcmDecrypt(a).ok,
    },
  });
});

// =====================================================================
// 6. HOSTED DEMO ONLY: show unused enrollment codes and reset the demo
// =====================================================================
// On a public URL each one-time code can be used once, so the first visitor would
// lock everyone else out. The Register page shows the unused codes, and anyone can
// reset the demo: all passkeys and sessions are wiped and fresh codes are issued.
// Codes stay single-use. These routes do not exist when running locally.
if (db.HOSTED) {
  app.get('/api/demo/accounts', (req, res) => {
    const { users, demoCodes = {} } = db.load();
    res.json(users.map((u) => ({ id: u.id, role: u.role, code: u.enrollmentUsed ? null : demoCodes[u.id] || null })));
  });

  app.post('/api/demo/reset', async (req, res) => {
    await seed();
    let cursor = '0';
    do {
      const [next, keys] = await db.redis.scan(cursor, { match: 'sess:*', count: 100 });
      if (keys.length) await db.redis.del(...keys);
      cursor = String(next);
    } while (cursor !== '0');
    console.log('DEMO RESET: passkeys and sessions wiped, new enrollment codes issued');
    res.clearCookie('portal.sid');
    res.json({ ok: true });
  });
}

// Any other /api path: 404 (deny by default)
app.use('/api', (req, res) => res.status(404).json({ error: 'not found' }));

// Lab convenience: list enrollment codes for accounts that have not registered yet,
// read from the gitignored file the seed step writes (db.json holds only hashes).
function printUnusedCodes() {
  const pending = db.load().users.filter((u) => !u.enrollmentUsed);
  if (!pending.length) return console.log('All seeded accounts have registered a passkey.');
  const codes = fs.existsSync(CODES_FILE)
    ? Object.fromEntries(fs.readFileSync(CODES_FILE, 'utf8').trim().split('\n').map((l) => l.trim().split(/\s+/)))
    : {};
  console.log('Accounts waiting for a first passkey (synthetic, lab use only):');
  for (const u of pending) console.log(`  ${u.id.padEnd(5)} ${u.role.padEnd(9)} code: ${codes[u.id] || '(unknown: run npm run seed -- --reset)'}`);
}

// Vercel imports the app and serves it; locally we listen on PORT.
export default app;
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`Student Records Portal listening on ${ORIGIN} (RP ID: ${RP_ID})`);
    printUnusedCodes();
  });
}
