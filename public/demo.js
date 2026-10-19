// Hosted demo only. /api/demo/accounts exists only on the hosted deployment
// (locally it is a 404 and this script does nothing). It lists the seeded
// accounts with their unused one-time codes, and offers a reset that wipes all
// passkeys and issues fresh codes, so visitors are never locked out.
(() => {
  const $ = (id) => document.getElementById(id);
  const box = $('demo-accounts');

  async function render() {
    let accounts;
    try {
      const r = await fetch('/api/demo/accounts', { credentials: 'same-origin' });
      if (!r.ok) return;
      accounts = await r.json();
    } catch { return; }

    $('register-lead').textContent = 'Public demo: pick an account below to fill in its one-time code, then register a passkey.';
    document.querySelector('.accounts').hidden = true;
    box.hidden = false;
    $('demo-list').replaceChildren(...accounts.map((a) => {
      const row = document.createElement('button');
      row.type = 'button';
      row.className = 'demo-row';
      row.disabled = !a.code;
      row.innerHTML = `<b>${a.id}</b><span>${a.role}</span><code>${a.code || 'registered'}</code>`;
      row.addEventListener('click', () => { $('enroll-id').value = a.id; $('enroll-code').value = a.code; });
      return row;
    }));
  }

  $('demo-reset').addEventListener('click', async () => {
    if (!confirm('Reset the demo? Every registered passkey is deleted, everyone is signed out, and new codes are issued.')) return;
    await fetch('/api/demo/reset', { method: 'POST', credentials: 'same-origin' });
    location.reload();
  });

  // Codes change after each registration, so refresh whenever the Register form is shown.
  new MutationObserver(() => { if (!$('view-register').hidden) render(); })
    .observe($('view-register'), { attributes: true, attributeFilter: ['hidden'] });
  render();
})();
