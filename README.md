# 04 — Vulnerable-by-Design OWASP Training App + Autograder

**Hireability:** Proves AppSec teaching ability AND test automation — two skills
senior security engineers value. It also shows you understand the OWASP Top 10
at the code level, not just the theory.

**The story:** Modeled on the E-Tafakna legal-tech SaaS context (document
handling). Each endpoint demonstrates one OWASP class, and an automated grader
*proves* each vuln is exploitable — turning "I think this is vulnerable" into
"the test fails when the bug is fixed." That's the mindset that makes security
findings trustworthy.

## What it demonstrates (vulnerable on purpose)
| Endpoint | OWASP class |
|----------|-------------|
| `GET /login?user=admin&pw=admin` | A07 Broken Authentication (plaintext compare) |
| `GET /user?id=<script>` | A03 Injection / XSS (reflected) |
| `POST /calc {"expr":"..."}` | A03 Injection (RCE via eval) |
| `GET /doc?id=secret` | A01 Path Traversal / Broken Access Control |

## Why stdlib only?
`vuln_app.py` uses `http.server` (no Flask/FastAPI install). The autograder
starts it in-process and fires real HTTP requests. Zero install friction — runs
anywhere Python 3.7+ exists. (A FastAPI version is documented in GUIDE if you
prefer a modern stack for your CV.)

## Run
```
python app/vuln_app.py 8080        # start the training app
python tests/autograder.py          # prove each vuln is exploitable
```
Autograder exit 0 = every vuln confirmed + secure-contract tests pass.

## Files
- `app/vuln_app.py` — the vulnerable app (stdlib http.server)
- `app/docs/secret.txt` — secret used by the path-traversal demo
- `tests/autograder.py` — proves vulns + documents the secure contract
- `GUIDE.md` — step-by-step code walkthrough + the "how to fix it" section

See `GUIDE.md` for the full code-by-code explanation and remediation snippets.
