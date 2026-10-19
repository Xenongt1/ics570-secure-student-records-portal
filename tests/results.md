# Security test results

Run: 2026-10-19T20:46:44.844Z · server http://localhost:3100 · Node v22.20.0 · 15/15 passed

| Test | Identity | Action | Expected | Observed | Result |
|---|---|---|---|---|---|
| T1 | S001 | Enroll with one-time code, register passkey | Credential bound to S001; public key stored | HTTP 200; credential oN_wg1JHdq… stored for S001, publicKey 103 chars (b64url COSE) | PASS |
| T2 | S001 | Sign in with registered passkey | Fresh challenge verified; session created | HTTP 200; GET /api/me -> 200 (S001, student) | PASS |
| T3a | S001 (altered) | Submit sign-in response with 1 bit of signature flipped | Rejected; no session | HTTP 401 {"error":"sign-in failed"}; GET /api/me -> 401 | PASS |
| T3b | S001 (replay) | Replay a previously accepted sign-in response | Rejected (challenge mismatch); no session | 1st use HTTP 200; replay HTTP 401; GET /api/me -> 401 | PASS |
| T3c | S001 (phish) | Valid signature but clientData origin = phishing site | Rejected (origin mismatch); no session | HTTP 401; GET /api/me -> 401 | PASS |
| T4 | Unauthenticated | GET /api/students/S001 with no session cookie | Denied (401) | HTTP 401 {"error":"authentication required"} | PASS |
| T5 | S001 | GET /api/students/S001 | Allowed | HTTP 200; Ama Owusu, 2 enrollments | PASS |
| T6 | S001 | GET /api/students/S002 (ID changed in URL) | Denied by server (403/404) | HTTP 403 {"error":"forbidden"} | PASS |
| T7 | S001 | POST /api/courses/C101/grades/S001 {"grade":"A"} | Denied; grade unchanged | HTTP 403; grade before B+, after B+ | PASS |
| T8 | L001 | POST /api/courses/C101/grades/S002 {"grade":"A-"} | Allowed; lecturer/course verified | HTTP 200; grade B -> A-; audit entry by L001 | PASS |
| X1 | L001 | POST grade in C102 (not assigned) | Denied; grade unchanged | HTTP 403; grade A -> A | PASS |
| X2 | L001 | GET /api/students/S003 (not in L001's course) | Denied | HTTP 403 | PASS |
| X3 | L001 | GET /api/students/S001 (in C101) | Allowed, C101 grades only | HTTP 200; courses shown: C101 | PASS |
| X4 | S001 code | Reuse S001 enrollment code to register attacker passkey | Denied (code is single-use) | HTTP 403 | PASS |
| X5 | L001 | POST /api/logout, then GET roster | Session invalidated; 401 | logout HTTP 200; roster HTTP 401 | PASS |
