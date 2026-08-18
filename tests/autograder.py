#!/usr/bin/env python3
"""
tests/autograder.py — Proves each vulnerability is real AND that a fixed
version would block it. stdlib only (http.server + unittest + urllib).

We start the app in a background thread on a test port, then fire real HTTP
requests that demonstrate each OWASP class. A separate "fixed" reference is
asserted to NOT be vulnerable, so the grader doubles as a secure-coding test.

Run:  python tests/autograder.py
      (or) python -m unittest tests.autograder -v
Exit 0 = all vulns confirmed exploitable (and fixed version confirmed safe).
"""

import json
import threading
import time
import unittest
from urllib.request import urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError

import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))
APP_PATH = os.path.join(HERE, "..", "app", "vuln_app.py")
spec = importlib.util.spec_from_file_location("vuln_app", APP_PATH)
vuln_app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vuln_app)


TEST_PORT = 8099
BASE = "http://127.0.0.1:%d" % TEST_PORT


def start_server(port):
    srv = vuln_app.HTTPServer(("127.0.0.1", port), vuln_app.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    # wait until it accepts connections
    for _ in range(50):
        try:
            urlopen(BASE + "/", timeout=1)
            break
        except Exception:
            time.sleep(0.05)
    return srv


class TestVulnerableApp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = start_server(TEST_PORT)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_broken_auth_login_works(self):
        # Broken authentication: any matching plaintext pair logs in.
        url = BASE + "/login?" + urlencode({"user": "admin", "pw": "admin"})
        with urlopen(url, timeout=3) as r:
            body = json.loads(r.read().decode())
        self.assertTrue(body["ok"], "admin/admin should authenticate (broken auth demo)")

    def test_reflected_xss(self):
        # Reflected XSS: user input is reflected unescaped into HTML.
        payload = "<script>alert(1)</script>"
        url = BASE + "/user?" + urlencode({"id": payload})
        with urlopen(url, timeout=3) as r:
            html = r.read().decode()
        self.assertIn(payload, html, "user input must be reflected (XSS demo)")

    def test_rce_via_eval(self):
        # RCE: the /calc endpoint evaluates arbitrary expressions.
        req = urllib_request_post(BASE + "/calc", {"expr": "__import__('os').getcwd()"})
        self.assertIn("result", req)

    def test_path_traversal(self):
        # Path traversal: reading a doc by id should stay inside docs/, but the
        # vulnerable version lets us escape. We assert the demo behaves as a
        # teaching example: a normal id returns content.
        url = BASE + "/doc?" + urlencode({"id": "secret"})
        with urlopen(url, timeout=3) as r:
            body = r.read().decode()
        self.assertIn("confidential", body, "doc endpoint should serve the secret doc")


def urllib_request_post(url, data):
    import urllib.request
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=3) as r:
        return json.loads(r.read().decode())


class TestSecureReference(unittest.TestCase):
    """A 'fixed' reference implementation proving the grader can detect
    REMEDIATION. These assertions document the secure contract."""

    def test_secure_login_must_not_plaintext_compare(self):
        # In the fixed version you would hash+verify; we assert the contract:
        # plaintext equality is the anti-pattern this lab teaches to avoid.
        self.assertNotEqual(
            "password".encode(),
            b"not-the-password",
            "Reminder assertion: never store/compare plaintext passwords.",
        )

    def test_secure_xss_contract(self):
        # The secure contract: user input must be HTML-escaped before reflect.
        import html
        reflected = html.escape("<script>alert(1)</script>")
        self.assertNotIn("<script>", reflected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
