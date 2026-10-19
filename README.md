# Secure Student Records Portal (ICS570 Lab 2)

A deliberately simple portal showing passkey (WebAuthn/FIDO2) authentication and server-side, record-level authorization. **Synthetic data only.**

**Stack:** Node.js 20+ · Express 5 · express-session · @simplewebauthn/server 13 and @simplewebauthn/browser 13 · JSON-file datastore (`data/db.json`).

## Prerequisites
- Node.js 20 or newer (`node -v`)
- Chrome, Edge or Safari, plus an authenticator: Windows Hello, Touch ID, a phone passkey (QR code), a security key, or the browser's passkey manager
- Open the portal at **http://localhost:3000**. WebAuthn treats localhost as a secure context. Do not use `127.0.0.1` or a LAN IP, because the RP ID is `localhost`.

## Install and run
```bash
npm install
npm run seed      # creates data/db.json and prints a one-time enrollment code per account
npm start         # http://localhost:3000
npm test          # automated T1 to T8 matrix on port 3100 with its own test datastore
```
`npm run seed` resets everything, including all registered passkeys. It prints new codes each time.

## Test accounts (fictional)
**S001** student (C101, C102) · **S002** student (C101) · **S003** student (C102) · **L001** lecturer, assigned to **C101** · **L002** lecturer (C102)

## How it works
- **Registration:** account ID plus one-time code (stored as a SHA-256 hash, single-use) unlocks a registration challenge; the library verifies challenge, origin, RP ID and user verification, and the credential ID and public key are stored against that account.
- **Sign-in:** a fresh challenge is held in the session and consumed before the signature is verified against the stored public key; the session ID is then regenerated.
- **Authorization:** `requireAuth` returns 401 with no session; each protected route then calls `src/policy.js`, which returns 403 and logs `AUTHZ DENY` on denial. Cookies are `httpOnly`, `sameSite=strict`, 30-minute expiry; logs never contain cookies, codes, challenges or keys.

## Repeating T1 to T8
**Automated (all tests):** run `npm test`. It uses a software authenticator (real P-256 signatures via Node `crypto`) through the same server verification code. It writes `tests/results.md` and `tests/server-log.txt`.

**Browser screenshots (optional):** after a fresh seed, with the server running: `npm install --no-save playwright && npx playwright install chromium`, then `S001_CODE=<code> L001_CODE=<code> node evidence/capture.mjs` (Chromium virtual WebAuthn authenticator).

**Manually in a browser (real passkey):**

1. **T1:** `npm run seed`, then `npm start`. On the portal, click *Register* (top right), enter `S001` and its code, then click *Register passkey* and approve the prompt.
2. **T2:** under *Sign in*, enter `S001`, click *Sign in* and approve. You should see S001's record.
3. **T3:** open `/security-tests.html`. Click **T3a** (tampered signature) and **T3b** (replay). Both should return 401, `/api/me` should return 401, and the server terminal shows `LOGIN FAIL` lines.
4. **T5, T6, T7:** sign in as S001 on the portal, then use the buttons on the test page. Alternatively, run these in the DevTools console:
   ```js
   fetch('/api/students/S002').then(r => r.status)                                  // T6 -> 403
   fetch('/api/courses/C101/grades/S001', {method:'POST', headers:{'Content-Type':'application/json'}, body:'{"grade":"A"}'}).then(r => r.status)  // T7 -> 403
   ```
5. **T4:** log out, then open http://localhost:3000/api/students/S001. It should return 401.
6. **T8:** register and sign in as `L001`. In the C101 roster, change S002's grade and click *Save*. It should return 200.
