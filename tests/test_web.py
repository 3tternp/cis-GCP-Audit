import http.client
import json
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gcp_cis_audit.webui import make_server


class WebUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = make_server(0, demo=True)
        cls.port = cls.httpd.server_address[1]
        cls.token = cls.httpd.token
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def req(self, method, path, body=None, headers=None, host=None, token=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if token:
            h["X-Token"] = self.token
        h.update(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body)
            h["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        raw = r.read()
        conn.close()
        return r.status, dict(r.getheaders()), raw

    def j(self, *a, **k):
        status, headers, raw = self.req(*a, **k)
        return status, json.loads(raw)

    # ---------------------------------------------------------------- security
    def test_index_has_token_and_security_headers(self):
        status, headers, raw = self.req("GET", "/", token=False)
        self.assertEqual(status, 200)
        self.assertIn(self.token.encode(), raw)
        self.assertNotIn(b"__TOKEN__", raw)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")

    def test_api_requires_token(self):
        self.assertEqual(self.req("GET", "/api/meta", token=False)[0], 403)
        self.assertEqual(self.req("GET", "/api/meta", headers={"X-Token": "wrong"})[0], 403)
        self.assertEqual(self.req("POST", "/api/start", {}, token=False)[0], 403)

    def test_dns_rebinding_host_rejected(self):
        self.assertEqual(self.req("GET", "/", host="evil.example.com", token=False)[0], 403)
        self.assertEqual(self.req("GET", "/api/meta", host="evil.example.com")[0], 403)

    def test_cross_origin_post_rejected(self):
        status, _ = self.j("POST", "/api/stop", {}, headers={"Origin": "http://evil.example.com"})
        self.assertEqual(status, 403)
        status, _ = self.j("POST", "/api/stop", {}, headers={"Origin": f"http://127.0.0.1:{self.port}"})
        self.assertEqual(status, 200)

    def test_bad_inputs_are_400_not_500(self):
        self.assertEqual(self.j("POST", "/api/start", {"auth": {"mode": "demo"}, "projects": []})[0], 400)
        self.assertEqual(self.j("POST", "/api/start", {"auth": {"mode": "demo"}, "projects": ["p"],
                                                        "sections": ["nope"]})[0], 400)
        self.assertEqual(self.j("POST", "/api/start", {"auth": {"mode": "key", "key_file": "C:/no/such.json"},
                                                        "projects": ["p"]})[0], 400)
        self.assertEqual(self.j("POST", "/api/start", {"auth": {"mode": "token", "token": ""},
                                                        "projects": ["p"]})[0], 400)
        self.assertEqual(self.j("POST", "/api/preflight", {"auth": {"mode": "demo"}})[0], 400)
        self.assertEqual(self.j("GET", "/api/nope")[0], 404)

    def test_oversized_body_rejected(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/api/stop", body="{}", headers={
            "Host": f"127.0.0.1:{self.port}", "X-Token": self.token, "Content-Length": str(5 << 20)})
        try:
            self.assertEqual(conn.getresponse().status, 400)
        except (ConnectionError, http.client.RemoteDisconnected):
            pass  # server refused and dropped the socket with unread data pending - also a rejection

    # ---------------------------------------------------------------- behaviour
    def test_meta_and_projects(self):
        status, meta = self.j("GET", "/api/meta")
        self.assertEqual(status, 200)
        self.assertTrue(meta["demo"])
        self.assertIn("11 - Organization level", meta["sections"])
        status, d = self.j("POST", "/api/projects", {"auth": {"mode": "demo"}})
        self.assertEqual(d["projects"], ["demo-prod", "demo-empty"])

    def test_preflight_endpoint(self):
        status, d = self.j("POST", "/api/preflight", {"auth": {"mode": "demo"}, "project": "demo-prod"})
        self.assertEqual(status, 200)
        self.assertTrue(all(r["status"] == "OK" for r in d["rows"]))

    def test_full_audit_flow_and_exports(self):
        status, _ = self.j("POST", "/api/start", {"auth": {"mode": "demo"}, "projects": ["demo-prod"], "level": 2})
        self.assertEqual(status, 200)
        deadline = time.time() + 20
        state = {}
        while time.time() < deadline:
            _, state = self.j("GET", "/api/state?since=0")
            if not state["running"] and state["count"]:
                break
            time.sleep(0.1)
        self.assertFalse(state["running"])
        self.assertEqual(state["status"], "Complete")
        self.assertGreater(state["count"], 100)
        self.assertEqual(len(state["results"]), state["count"])
        # incremental polling returns only new rows
        _, tail = self.j("GET", f"/api/state?since={state['count'] - 3}")
        self.assertEqual(len(tail["results"]), 3)

        status, headers, raw = self.req("GET", f"/export/json?token={self.token}", token=False)
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertEqual(len(json.loads(raw)["results"]), state["count"])
        for fmt, marker in (("csv", b"project,check_id"), ("html", b"<!doctype html>")):
            status, _, raw = self.req("GET", f"/export/{fmt}?token={self.token}", token=False)
            self.assertEqual(status, 200)
            self.assertIn(marker, raw)
        self.assertEqual(self.req("GET", "/export/exe?token=" + self.token, token=False)[0], 404)
        self.assertEqual(self.req("GET", "/export/json", token=False)[0], 403)

    def test_second_start_while_running_is_409(self):
        s = self.httpd.session
        with s.lock:
            s.running = True
        try:
            status, _ = self.j("POST", "/api/start", {"auth": {"mode": "demo"}, "projects": ["demo-prod"]})
            self.assertEqual(status, 409)
        finally:
            with s.lock:
                s.running = False


if __name__ == "__main__":
    unittest.main()
