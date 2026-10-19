// Presentation helper for the security test page: shows whether a session exists,
// lets you sign back in with your passkey (T3a/T3b sign you out), and warns when
// T5-T7 are about to run without a session. The test logic itself is in the inline script.
(() => {
  const $ = (id) => document.getElementById(id);
  const say = (m) => ($('log').textContent += m + '\n');
  let signedIn = false;

  async function refreshStatus() {
    const r = await fetch('/api/me', { credentials: 'same-origin' });
    signedIn = r.ok;
    const me = signedIn ? await r.json() : null;
    $('session-text').textContent = signedIn ? `Signed in as ${me.id} (${me.role})` : 'Not signed in';
    $('session-dot').classList.toggle('off', !signedIn);
    $('session-signin').hidden = signedIn;
  }

  $('session-signin').addEventListener('click', async () => {
    const userId = $('uid').value.trim() || 'S001';
    try {
      const opts = await (await fetch('/api/login/options', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ userId }),
      })).json();
      const resp = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: opts });
      const v = await fetch('/api/login/verify', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(resp),
      });
      say(`Signed in as ${userId} -> ${v.status}`);
    } catch (e) {
      say(`Sign-in cancelled or failed: ${e.message}`);
    }
    refreshStatus();
  });

  // Warn before access-control tests that would only show 401 because there is no session.
  ['t5', 't6', 't7'].forEach((id) =>
    $(id).addEventListener('click', () => {
      if (!signedIn) say(`(${id.toUpperCase()}: you are not signed in, so expect 401, not the authorization result. Use "Sign in with passkey" first.)`);
    }, true),
  );
  // Any test can change the session (T3a, T3b and T4 log out), so re-check afterwards.
  document.querySelectorAll('.test-row').forEach((b) => b.addEventListener('click', () => {
    setTimeout(refreshStatus, 1500);
    setTimeout(refreshStatus, 6000); // T3 waits on the passkey prompt, so check again later
  }));

  refreshStatus();
})();
