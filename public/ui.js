// Presentation only: form switching, the sign-in morph, and the avatar.
// All auth logic stays in app.js.
(() => {
  const $ = (id) => document.getElementById(id);
  const stage = $('stage');
  let mode = 'login';

  function show(next) {
    mode = next;
    $('view-login').hidden = mode !== 'login';
    $('view-register').hidden = mode !== 'register';
    $('mode-label').textContent = mode === 'login' ? 'Register' : 'Sign In';
  }

  $('mode-toggle').addEventListener('click', () => show(mode === 'login' ? 'register' : 'login'));
  document.querySelectorAll('[data-go]').forEach((b) => b.addEventListener('click', () => show(b.dataset.go)));

  // Toggle the signed-in layout. While the page is still booting (e.g. a session restored on reload)
  // jump straight to the end state instead of animating.
  function setAuthed(on) {
    if (stage.classList.contains('authed') === on) return;
    const instant = stage.classList.contains('booting');
    if (instant) stage.classList.add('instant');
    stage.classList.toggle('authed', on);
    if (instant) requestAnimationFrame(() => requestAnimationFrame(() => stage.classList.remove('instant')));
  }

  function ready() {
    requestAnimationFrame(() => stage.classList.remove('booting'));
  }

  fetch('/api/me', { credentials: 'same-origin' })
    .then((r) => setAuthed(r.ok))
    .catch(() => {})
    .finally(ready);
  setTimeout(ready, 1500);

  // Follow app.js: it flips #signed-in after a successful sign-in or log-out.
  // Only write on change, otherwise this observer would re-trigger itself forever.
  new MutationObserver(() => {
    const signedIn = !$('signed-in').hidden;
    setAuthed(signedIn);
    if ($('mode-toggle').hidden !== signedIn) $('mode-toggle').hidden = signedIn;
    const id = ($('welcome').textContent.match(/\b([SL]\d+)\b/) || [])[1] || '';
    if ($('avatar').textContent !== id) $('avatar').textContent = id;
  }).observe(document.body, { subtree: true, attributes: true, attributeFilter: ['hidden'], childList: true, characterData: true });

  // After a successful registration, app.js logs a hint; move the user to the sign-in form.
  new MutationObserver(() => {
    if ($('log').textContent.split('\n')[0].includes('Passkey registered')) {
      $('login-id').value = $('enroll-id').value;
      show('login');
    }
  }).observe($('log'), { childList: true, characterData: true, subtree: true });
})();
