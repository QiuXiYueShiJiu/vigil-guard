#!/usr/bin/env python3
"""Static file server for frontend development only.

Serves the frontend directory on 127.0.0.1:9311 and proxies /api/ to the
backend on 9310, which is what nginx does in production. Kept tiny on
purpose; it is never deployed.
"""
import http.server
import os
import sys
import urllib.request
import urllib.error

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
BACKEND = "http://127.0.0.1:9310"
PORT = int(os.environ.get("VIGIL_DEV_WEB_PORT", "9311"))


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/api/"):
            return self.proxy()
        return super().do_GET()

    def do_HEAD(self):
        if self.path.startswith("/api/"):
            return self.proxy(head=True)
        return super().do_HEAD()

    def proxy(self, head=False):
        req = urllib.request.Request(BACKEND + self.path, method="GET")
        for key in ("Cookie", "X-Vigil-Token", "User-Agent", "X-Forwarded-For", "Host"):
            if self.headers.get(key):
                req.add_header(key, self.headers[key])
        try:
            with urllib.request.urlopen(req, timeout=600) as res:
                self.send_response(res.status)
                for key, val in res.getheaders():
                    if key.lower() in ("transfer-encoding", "connection", "keep-alive"):
                        continue
                    self.send_header(key, val)
                self.end_headers()
                if head:
                    return
                while True:
                    chunk = res.read(8192)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except urllib.error.HTTPError as exc:
            body = exc.read()
            self.send_response(exc.code)
            for key, val in exc.headers.items():
                if key.lower() in ("transfer-encoding", "connection", "keep-alive"):
                    continue
                self.send_header(key, val)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:                      # noqa: BLE001
            body = ("proxy error: %s" % exc).encode()
            self.send_response(502)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


if __name__ == "__main__":
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    sys.stderr.write("dev-web on http://127.0.0.1:%d -> %s\n" % (PORT, ROOT))
    srv.serve_forever()
