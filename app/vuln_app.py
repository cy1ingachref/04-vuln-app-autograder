#!/usr/bin/env python3
"""
vuln_app.py — A deliberately (lightly) vulnerable training web app.

PURPOSE
-------
A teaching tool for OWASP Top 10. Each endpoint demonstrates ONE vulnerability
class. A companion autograder (`tests/autograder.py`) PROVES each vuln is
exploitable, and also proves the "fixed" version blocks it.

This uses ONLY the Python standard library (http.server) so it runs on any
machine with Python 3.7+ — no pip install, no Docker needed to demo it.

Endpoints (intentionally vulnerable versions):
  GET  /                    -> home, lists endpoints
  GET  /login?user=admin&pw=admin
       -> SQLi-style: checks credentials by string match (broken auth demo)
  GET  /user?id=1           -> reflects id into response (reflected XSS demo)
  POST /calc               -> body: {"expr":"1+1"} -> eval(expr)  (RCE demo)
  GET  /doc?id=2           -> path traversal demo (reads ../../etc/passwd style)

Run:  python app/vuln_app.py [port]   (default 8080)
"""

import cgi
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# A "database" of users (in-memory, for the demo).
USERS = {
    "admin": {"pw": "admin", "role": "admin"},
    "alice": {"pw": "alice123", "role": "user"},
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOCS_DIR = os.path.join(BASE_DIR, "docs")


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            return self._send(200, self._home())

        if path == "/login":
            user = qs.get("user", [""])[0]
            pw = qs.get("pw", [""])[0]
            # VULNERABLE: string comparison instead of hashed/verified credentials.
            if user in USERS and USERS[user]["pw"] == pw:
                return self._send(200, json.dumps({"ok": True, "user": user,
                                                   "role": USERS[user]["role"]}),
                                  "application/json")
            return self._send(401, json.dumps({"ok": False}), "application/json")

        if path == "/user":
            uid = qs.get("id", [""])[0]
            # VULNERABLE: reflected input straight into HTML (XSS).
            return self._send(200,
                              "<html>Profile for user id=%s</html>" % uid)

        if path == "/doc":
            doc = qs.get("id", [""])[0]
            # VULNERABLE: builds a filename from user input -> path traversal.
            target = os.path.join(DOCS_DIR, doc + ".txt")
            try:
                with open(target, "r", encoding="utf-8") as fh:
                    return self._send(200, fh.read())
            except OSError:
                return self._send(404, "not found")

        return self._send(404, "unknown endpoint")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/calc":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                data = json.loads(raw.decode("utf-8"))
            except (ValueError, json.JSONDecodeError):
                data = {}
            expr = data.get("expr", "")
            # VULNERABLE: evaluating arbitrary user input -> RCE.
            try:
                result = eval(expr)  # noqa: S307  (intentional for the demo)
            except Exception as exc:  # noqa: BLE001
                result = "error: %s" % exc
            return self._send(200, json.dumps({"result": result}), "application/json")
        return self._send(404, "unknown endpoint")

    def _home(self):
        return (
            "<html><body><h1>OWASP Training App (vulnerable on purpose)</h1>"
            "<ul>"
            "<li>/login?user=admin&amp;pw=admin  (broken auth)</li>"
            "<li>/user?id=&lt;script&gt;        (reflected XSS)</li>"
            "<li>POST /calc {\"expr\":\"1+1\"}     (RCE via eval)</li>"
            "<li>/doc?id=secret                  (path traversal)</li>"
            "</ul></body></html>"
        )

    # Quieter logging for the demo.
    def log_message(self, *args):
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(("127.0.0.1", port), Handler)
    print("Vulnerable training app on http://127.0.0.1:%d (Ctrl+C to stop)" % port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
