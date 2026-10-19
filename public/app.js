// Browser side of the portal. The UI only *shows* what the role can do;
// every decision is enforced again on the server (src/policy.js).
const { startRegistration, startAuthentication, browserSupportsWebAuthn } = SimpleWebAuthnBrowser;
const $ = (id) => document.getElementById(id);

function log(msg) {
  const line = `[${new Date().toLocaleTimeString()}] ${msg}`;
  $('log').textContent = line + '\n' + $('log').textContent;
}

async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  });
  let data = null;
  try { data = await res.json(); } catch {}
  return { status: res.status, data };
}

// ---------- Registration (T1) ----------
async function registerPasskey({ viaEnrollment }) {
  if (viaEnrollment) {
    const r = await api('POST', '/api/enroll/start', { userId: $('enroll-id').value, enrollmentCode: $('enroll-code').value });
    log(`POST /api/enroll/start -> ${r.status} ${JSON.stringify(r.data)}`);
    if (r.status !== 200) return;
  }
  const opts = await api('POST', '/api/register/options');
  log(`POST /api/register/options -> ${opts.status} (fresh challenge issued)`);
  if (opts.status !== 200) return;
  let attResp;
  try {
    attResp = await startRegistration({ optionsJSON: opts.data });
  } catch (e) {
    return log(`Authenticator error: ${e.name}: ${e.message}`);
  }
  const v = await api('POST', '/api/register/verify', attResp);
  log(`POST /api/register/verify -> ${v.status} ${JSON.stringify(v.data)}`);
  if (v.status === 200 && viaEnrollment) log('Passkey registered. Now sign in with it (section 2).');
}

// ---------- Sign-in (T2) ----------
async function signIn() {
  const userId = $('login-id').value;
  const opts = await api('POST', '/api/login/options', { userId });
  log(`POST /api/login/options -> ${opts.status} (fresh challenge issued)`);
  let asseResp;
  try {
    asseResp = await startAuthentication({ optionsJSON: opts.data });
  } catch (e) {
    return log(`Authenticator error: ${e.name}: ${e.message}`);
  }
  const v = await api('POST', '/api/login/verify', asseResp);
  log(`POST /api/login/verify -> ${v.status} ${JSON.stringify(v.data)}`);
  if (v.status === 200) await refresh();
}

async function logout() {
  const r = await api('POST', '/api/logout');
  log(`POST /api/logout -> ${r.status}`);
  await refresh();
}

// ---------- Views ----------
async function refresh() {
  const me = await api('GET', '/api/me');
  const signedIn = me.status === 200;
  $('signed-out').hidden = signedIn;
  $('signed-in').hidden = !signedIn;
  if (!signedIn) return;

  const u = me.data;
  $('welcome').textContent = `Signed in as ${u.id}`;
  $('role-line').textContent = `${u.displayName} · role: ${u.role}`;
  $('student-panel').hidden = u.role !== 'student';
  $('lecturer-panel').hidden = u.role !== 'lecturer';

  if (u.role === 'student') {
    const r = await api('GET', `/api/students/${u.id}`);
    const s = r.data;
    $('my-record').innerHTML = `
      <p><b>${esc(s.name)}</b> · ${esc(s.programme)} · Year ${s.year}</p>
      <table><tr><th>Course</th><th>Grade</th></tr>
      ${s.enrollments.map((e) => `<tr><td>${esc(e.courseId)}</td><td>${esc(e.grade)}</td></tr>`).join('')}</table>`;
  } else if (u.role === 'lecturer') {
    await loadRoster();
  }
}

async function loadRoster() {
  const r = await api('GET', '/api/courses/C101/roster');
  if (r.status !== 200) {
    $('roster').textContent = `Roster unavailable (${r.status})`;
    return;
  }
  const grades = ['A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D', 'F'];
  $('roster').innerHTML = `<p class="muted">${esc(r.data.title)}</p><table>
    <tr><th>Student</th><th>Name</th><th>Grade</th><th></th></tr>
    ${r.data.roster.map((row) => `<tr>
      <td>${esc(row.studentId)}</td><td>${esc(row.name)}</td>
      <td><select data-sid="${esc(row.studentId)}">${grades.map((g) => `<option ${g === row.grade ? 'selected' : ''}>${g}</option>`).join('')}</select></td>
      <td><button class="secondary" data-save="${esc(row.studentId)}">Save</button></td></tr>`).join('')}
  </table>`;
  $('roster').querySelectorAll('button[data-save]').forEach((b) =>
    b.addEventListener('click', async () => {
      const sid = b.dataset.save;
      const grade = $('roster').querySelector(`select[data-sid="${sid}"]`).value;
      const res = await api('POST', `/api/courses/C101/grades/${sid}`, { grade });
      log(`POST /api/courses/C101/grades/${sid} -> ${res.status} ${JSON.stringify(res.data)}`);
    }),
  );
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

// ---------- wire up ----------
$('btn-register').addEventListener('click', () => registerPasskey({ viaEnrollment: true }));
$('btn-login').addEventListener('click', signIn);
$('btn-logout').addEventListener('click', logout);
$('btn-add-passkey').addEventListener('click', () => registerPasskey({ viaEnrollment: false }));
if (!browserSupportsWebAuthn()) log('This browser does not support WebAuthn.');
refresh();
