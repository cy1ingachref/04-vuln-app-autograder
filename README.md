# 04 — Vulnerable-by-Design OWASP Training App + Autograder

A deliberately vulnerable training application paired with an automated autograder that proves each vulnerability is exploitable. Intended for teaching, testing, and continuous validation of remediation efforts.

Why this project matters

- Demonstrates AppSec pedagogy and the ability to automate vulnerability verification — a strong indicator of practical security engineering skill.
- Uses Python standard library only to minimize setup friction and enable easy demos and CI integration.

What it demonstrates

| Endpoint | OWASP class |
|----------|-------------|
| `GET /login?user=admin&pw=admin` | A07 Broken Authentication (plaintext compare) |
| `GET /user?id=<script>` | A03 Injection / XSS (reflected) |
| `POST /calc {"expr":"..."}` | A03 Injection (RCE via eval) |
| `GET /doc?id=secret` | A01 Path Traversal / Broken Access Control |

Run locally

# start the vulnerable app
python app/vuln_app.py 8080

# run the autograder to validate each vuln is exploitable
python tests/autograder.py

Autograder returns exit code 0 when all vulnerable behaviors are confirmed and the secure-contract tests pass.

Files

- `app/vuln_app.py` — vulnerable demo app (stdlib `http.server`)
- `app/docs/secret.txt` — secret used for path-traversal demo
- `tests/autograder.py` — automated tests that validate each vulnerability
- `GUIDE.md` — walkthrough and remediation guidance

Notes

- A FastAPI version and remediation examples are provided in GUIDE.md for reference.
