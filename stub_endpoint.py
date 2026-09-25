#!/usr/bin/env python3
"""stub_endpoint.py — a local HTTP stub for testing the vault's call path.

Echoes back EVERYTHING a request contains (method, path, headers, body) as
JSON, so a test can assert "the vault really substituted the secret into
this header" without any live API or real key. Listens on a local port only.

Usage:
    python3 stub_endpoint.py [port]        # default 18181
Then point a vault call at http://127.0.0.1:PORT/anything — the stub returns
the full request so the test can check where the secret landed.

Deliberately returns instantly and logs to stdout (single line) so tests can
grep the response.
"""
import sys, json, http.server

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18181

class Handler(http.server.BaseHTTPRequestHandler):
    def _reply(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode(errors="replace") if length else ""
        # echo the ENTIRE request back so tests can confirm substitution
        out = {
            "method": self.command,
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items()},
            "body": body,
        }
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):   self._reply()
    def do_POST(self):  self._reply()
    def do_PUT(self):   self._reply()
    def do_DELETE(self):self._reply()

    def log_message(self, fmt, *args):   # keep logs terse for tests
        pass

if __name__ == "__main__":
    http.server.HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()