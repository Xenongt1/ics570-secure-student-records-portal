// Secure Student Records Portal (ICS570 Lab 2). Synthetic data, local lab use only.
// Authentication: WebAuthn passkeys verified server-side with @simplewebauthn/server.
// Authorization: server-side RBAC + record-level checks in src/policy.js, applied on every protected route.
import crypto from 'node:crypto';
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
import { sha256 } from './seed.js';
import { canReadStudent, canUpdateGrade, canReadRoster, visibleEnrollments } from './policy.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---- Relying-party configuration (checked on every registration and login) ----
const PORT = Number(process.env.PORT || 3000);
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;
const RP_NAME = 'Student Records Portal (Lab)';
const ALLOWED_GRADES = ['A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D', 'F'];

db.load(); // fail fast if the datastore has not been seeded

const app = express();
app.disable('x-powered-by');
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
    // Random per process unless set; sessions do not survive a restart (acceptable for a lab).
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
  db.save();
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
  db.save();

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

app.post('/api/courses/:courseId/grades/:studentId', requireAuth, (req, res) => {
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
  db.save();
  console.log(`GRADE UPDATE by=${req.user.id} ${courseId}/${studentId} ${before} -> ${grade}`);
  res.json({ ok: true, courseId, studentId, before, after: grade });
});

// Any other /api path: 404 (deny by default)
app.use('/api', (req, res) => res.status(404).json({ error: 'not found' }));

app.listen(PORT, () => {
  console.log(`Student Records Portal listening on ${ORIGIN} (RP ID: ${RP_ID})`);
});
