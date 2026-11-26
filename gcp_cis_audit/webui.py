"""Browser-based UI: a small local web server (standard library only).

Security model
  * binds to 127.0.0.1 only
  * every request must carry a Host header for this exact address (blocks DNS rebinding)
  * API calls need a random per-run token (sent as X-Token, or ?token= for downloads)
  * POSTs with an Origin header must come from this same origin (blocks cross-site requests)
  * credentials live in memory for the duration of a run and are never written to disk
"""
from __future__ import annotations

import json
import os
import secrets
import tempfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__, report
from .checks import SECTIONS
from .demo import DemoClient
from .preflight import run_preflight
from .runner import select_checks, run_audit, summarize

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
MAX_BODY = 1 << 20

_CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class Session:
    """State of the (single) audit job."""

    def __init__(self):
        self.lock = threading.Lock()
        self.results = []
        self.total = 0
        self.running = False
        self.error = None
        self.status = "Idle"
        self.stop = threading.Event()


def make_client(auth: dict):
    mode = (auth or {}).get("mode", "adc")
    if mode == "demo":
        return DemoClient()
    from .client import GcpClient
    if mode == "key":
        path = (auth.get("key_file") or "").strip()
        if not os.path.isfile(path):
            raise ValueError("Service account key file not found on this machine.")
        return GcpClient("key", path)
    if mode == "token":
        tok = (auth.get("token") or "").strip()
        if not tok:
            raise ValueError("Paste an access token.")
        return GcpClient("token", token=tok)
    return GcpClient("adc")


class Handler(BaseHTTPRequestHandler):
    server_version = "CISGCPAudit/" + __version__

    def log_message(self, fmt, *args):  # keep the console quiet (and free of query tokens)
        pass

    # ---------------------------------------------------------------- plumbing
    def _send(self, code, body: bytes, ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode("utf-8"))

    def _err(self, code, msg):
        self._json({"error": msg}, code)

    def _host_ok(self):
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in (f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}")

    def _origin_ok(self):
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        return origin in (f"http://127.0.0.1:{self.server.server_address[1]}",
                          f"http://localhost:{self.server.server_address[1]}")

    def _token_ok(self, query):
        supplied = self.headers.get("X-Token") or (query.get("token") or [""])[0]
        return secrets.compare_digest(supplied, self.server.token)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("Request too large")
        if n == 0:
            return {}
        data = json.loads(self.rfile.read(n).decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Expected a JSON object")
        return data

    # ---------------------------------------------------------------- routing
    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if not self._host_ok():
            return self._err(403, "Bad Host header")
        if url.path == "/":
            return self._index()
        if url.path == "/icon.png":
            return self._icon()
        if not self._token_ok(q):
            return self._err(403, "Missing or invalid token")
        if url.path == "/api/meta":
            return self._json({"version": __version__, "sections": SECTIONS, "demo": self.server.demo})
        if url.path == "/api/state":
            return self._state(q)
        if url.path.startswith("/export/"):
            return self._export(url.path.rsplit("/", 1)[-1])
        self._err(404, "Not found")

    def do_POST(self):
        url = urlparse(self.path)
        if not (self._host_ok() and self._origin_ok()):
            return self._err(403, "Bad Host or Origin")
        if not self._token_ok({}):
            return self._err(403, "Missing or invalid token")
        try:
            body = self._body()
            handler = {"/api/projects": self._projects, "/api/preflight": self._preflight,
                       "/api/start": self._start, "/api/stop": self._stop}.get(url.path)
            if handler is None:
                return self._err(404, "Not found")
            handler(body)
        except ValueError as exc:
            self._err(400, str(exc))
        except Exception as exc:  # never leak a traceback to the browser
            self._err(500, f"{type(exc).__name__}: {exc}"[:300])

    # ---------------------------------------------------------------- handlers
    def _index(self):
        with open(os.path.join(_HERE, "web", "index.html"), encoding="utf-8") as fh:
            page = fh.read().replace("__TOKEN__", self.server.token)
        self._send(200, page.encode("utf-8"), "text/html; charset=utf-8", {"Content-Security-Policy": _CSP})

    def _icon(self):
        try:
            with open(os.path.join(_ROOT, "assets", "icon.png"), "rb") as fh:
                self._send(200, fh.read(), "image/png")
        except OSError:
            self._err(404, "No icon")

    def _projects(self, body):
        client = make_client(body.get("auth"))
        self._json({"projects": client.discover_projects()})

    def _preflight(self, body):
        project = (body.get("project") or "").strip()
        if not project:
            raise ValueError("Enter or select a project for the preflight check.")
        self._json({"rows": run_preflight(make_client(body.get("auth")), project)})

    def _start(self, body):
        s = self.server.session
        projects = [p for p in body.get("projects", []) if isinstance(p, str) and p.strip()]
        if not projects:
            raise ValueError("Select at least one project.")
        sections = [x for x in body.get("sections", SECTIONS) if x in SECTIONS]
        level = 1 if body.get("level") == 1 else 2
        checks = select_checks(sections, level)
        if not checks:
            raise ValueError("Select at least one section.")
        client = make_client(body.get("auth"))
        with s.lock:
            if s.running:
                return self._err(409, "An audit is already running.")
            s.results, s.total, s.error, s.status = [], 0, None, "Starting..."
            s.running = True
            s.stop.clear()

        def work():
            def on_result(r, done, total):
                with s.lock:
                    s.results.append(r)
                    s.total = total
                    s.status = f"{r.project}: {r.check_id}"
            try:
                run_audit(client, projects, checks, on_result=on_result, stop=s.stop)
                final = "Stopped" if s.stop.is_set() else "Complete"
            except Exception as exc:
                with s.lock:
                    s.error = f"Audit failed: {exc}"[:400]
                final = "Failed"
            with s.lock:
                s.running = False
                s.status = final

        threading.Thread(target=work, daemon=True).start()
        self._json({"started": True})

    def _stop(self, _body):
        self.server.session.stop.set()
        self._json({"stopping": True})

    def _state(self, q):
        s = self.server.session
        try:
            since = max(0, int((q.get("since") or ["0"])[0]))
        except ValueError:
            since = 0
        with s.lock:
            new = [r.to_dict() for r in s.results[since:]]
            payload = {"running": s.running, "status": s.status, "error": s.error, "total": s.total,
                       "count": len(s.results), "results": new, "summary": summarize(s.results)}
        self._json(payload)

    def _export(self, fmt):
        writers = {"json": (report.to_json, "application/json"), "csv": (report.to_csv, "text/csv"),
                   "html": (report.to_html, "text/html")}
        if fmt not in writers:
            return self._err(404, "Unknown format")
        s = self.server.session
        with s.lock:
            results = list(s.results)
        if not results:
            return self._err(409, "Run an audit first.")
        fn, ctype = writers[fmt]
        fd, path = tempfile.mkstemp(suffix="." + fmt)
        os.close(fd)
        try:
            fn(results, path)
            with open(path, "rb") as fh:
                data = fh.read()
        finally:
            os.remove(path)
        self._send(200, data, ctype + "; charset=utf-8",
                   {"Content-Disposition": f'attachment; filename="cis-gcp-audit.{fmt}"'})


class AuditServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, demo: bool):
        super().__init__(("127.0.0.1", port), Handler)
        self.token = secrets.token_urlsafe(24)
        self.session = Session()
        self.demo = demo


def make_server(port: int = 0, demo: bool = False) -> AuditServer:
    return AuditServer(port, demo)


def serve(port: int = 8765, demo: bool = False, open_browser: bool = True):
    try:
        httpd = make_server(port, demo)
    except OSError:  # requested port busy -> let the OS pick one
        httpd = make_server(0, demo)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"CIS GCP Audit web UI running at {url}  (Ctrl+C to stop)")
    print("Listening on localhost only. Credentials stay in memory and are never written to disk.")
    if open_browser:
        threading.Timer(0.4, webbrowser.open, args=(url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
