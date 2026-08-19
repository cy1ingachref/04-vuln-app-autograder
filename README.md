# 04 — Vulnerable-by-Design OWASP Training App + Autograder

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)  
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)](#)  

## Overview

A deliberately vulnerable training application that demonstrates common OWASP Top 10 issues and includes an autograder that programmatically verifies each vulnerability. Designed for hands-on learning and automated assessments without external dependencies.

This README was upgraded to a full professional template automatically. See CHANGELOG below for details.

---

## Quick links
- Repository: https://github.com/cy1ingachref/04-vuln-app-autograder
- Training app: `app/vuln_app.py`
- Autograder: `tests/autograder.py`

## What it demonstrates
- OWASP classes implemented intentionally for education:
  - A07 Broken Authentication (simple password check)
  - A03 Injection / XSS (reflected)
  - A03 Injection (RCE via eval in calculator)
  - A01 Path Traversal / Broken Access Control

## Requirements
- Python 3.7+

## Run the app and autograder
Start the training app:

```bash
python app/vuln_app.py 8080
```

Run the autograder to validate vulnerabilities:

```bash
python tests/autograder.py
```

Autograder exit code 0 = all vulnerabilities confirmed. Non-zero indicates a failing test.

## Development & Testing
Run unit tests:

```bash
python -m unittest discover -v
```

## Contributing
1. Fork the repository and create a branch from `main`.
2. Run tests locally and ensure all pass.
3. Open a PR with a clear description of the change.

See CONTRIBUTING.md for details (auto-generated placeholder).

## License
MIT License — see LICENSE file.

## Maintainer
- Achref Ferjani — https://github.com/cy1ingachref

## CHANGELOG
- 2026-08-19: README upgraded to full professional template by automated process.
