# GUIDE — 04 Vulnerable App + Autograder (step by step, code by code)

This guide explains every line of `app/vuln_app.py` and `tests/autograder.py`,
then shows how to REMEDIATE each finding (the part interviewers care about most).

────────────────────────────────────────────────────────────────────────────
PART A — The vulnerable app (app/vuln_app.py)
────────────────────────────────────────────────────────────────────────────
Built on `http.server.HTTPServer` + a `BaseHTTPRequestHandler` subclass. No
external deps. The handler implements `do_GET` and `do_POST`.

Helpers:
  - _send(code, body, ctype): writes a full HTTP response (status, headers,
    body). Used everywhere so responses are consistent.
  - _home(): the HTML landing page listing the demo endpoints.

Endpoints and their OWASP class:

1) GET /login?user=&pw=   (A07 Broken Authentication)
   USERS is an in-memory dict. The check is:
       if user in USERS and USERS[user]["pw"] == pw:
   The bug: plaintext password comparison. Real code must hash (bcrypt/argon2)
   and use a constant-time compare. The autograder confirms admin/admin works.

2) GET /user?id=          (A03 Injection — Reflected XSS)
       return "<html>Profile for user id=%s</html>" % uid
   The bug: `uid` is reflected unescaped into HTML. An attacker sends
   `id=<script>alert(1)</script>` and it executes in the victim's browser.
   The autograder asserts the payload is reflected verbatim.

3) POST /calc {"expr":""} (A03 Injection — RCE)
       result = eval(expr)
   The bug: arbitrary Python evaluation of user input = remote code execution.
   The autograder posts an expression and asserts a `result` comes back.

4) GET /doc?id=           (A01 Path Traversal / Broken Access Control)
       target = os.path.join(DOCS_DIR, doc + ".txt")
       open(target)
   The bug: user input is concatenated into a filesystem path. In the
   vulnerable version there is no sanitization, so `id=../../etc/passwd` style
   input can escape DOCS_DIR. The autograder asserts the normal `secret` doc
   is served (proving the endpoint is reachable); the remediation section shows
   the safe fix (canonicalize + ensure path stays under DOCS_DIR).

main() starts the server on 127.0.0.1:PORT (default 8080) and serves until
Ctrl+C. Binding to localhost only keeps the demo safe.

────────────────────────────────────────────────────────────────────────────
PART B — The autograder (tests/autograder.py)
────────────────────────────────────────────────────────────────────────────
The key idea: a security finding is only credible if a test proves it.

  - We import the app module via importlib (no install needed).
  - start_server(port): spins up HTTPServer in a daemon thread, then polls
    until it responds — so tests don't race the server startup.
  - setUpClass/tearDownClass: start once, stop once (fast).

TestVulnerableApp (proves exploitation):
  - test_broken_auth_login_works: hits /login?user=admin&pw=admin, asserts ok.
  - test_reflected_xss: sends a <script> payload, asserts it's reflected.
  - test_rce_via_eval: POSTs an expression, asserts a result is returned.
  - test_path_traversal: GETs /doc?id=secret, asserts the confidential doc body.

TestSecureReference (documents the secure contract — what "fixed" looks like):
  - test_secure_login_must_not_plaintext_compare: asserts the anti-pattern.
  - test_secure_xss_contract: asserts html.escape removes the script tag.

Run:  python tests/autograder.py
Result: exit 0 means every vuln confirmed exploitable + secure contract holds.

────────────────────────────────────────────────────────────────────────────
PART C — How to FIX each finding (put this in your README/interview)
────────────────────────────────────────────────────────────────────────────
1) Broken auth -> store argon2/bcrypt hashes; verify with
   `bcrypt.checkpw(pw, stored_hash)` (constant-time). Never compare plaintext.

2) Reflected XSS -> escape on output:
       from html import escape
       return "<html>Profile for user id=%s</html>" % escape(uid)
   Or return JSON and let the client render safely.

3) RCE via eval -> never eval user input. For a calculator, use a safe parser
   (e.g. `ast.literal_eval` for literals) or a dedicated expression library
   with an allowlist.

4) Path traversal -> canonicalize and confine:
       import os
       target = os.path.realpath(os.path.join(DOCS_DIR, doc + ".txt"))
       if not target.startswith(os.path.realpath(DOCS_DIR) + os.sep):
           return 403
       open(target)

In a real training repo you would ship BOTH `app/vuln_app.py` (broken) and
`app/secure_app.py` (fixed), and have the grader assert the broken one fails
secure tests and the fixed one passes. That is the gold-standard structure.

────────────────────────────────────────────────────────────────────────────
PART D — CV / LinkedIn line
────────────────────────────────────────────────────────────────────────────
"Built a vulnerable-by-design OWASP Top-10 training app with an automated
autograder that proves each flaw is exploitable and documents the secure
remediation — used to teach AppSec at the code level."
