#!/usr/bin/env python3
"""LOCAL DEV ONLY: serve frontend/ and answer POST /check on one origin.

    AWS_PROFILE=policylens .venv/bin/python scripts/dev_server.py
    # open http://localhost:8010

Uses real Bedrock if AWS credentials are set, otherwise the template
explanation. Production is Amplify + API Gateway + Lambda (scripts/deploy.sh).
"""

from __future__ import annotations

import json
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.handler import check  # noqa: E402

PORT = 8010


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(ROOT / "frontend"), **kw)

    def log_message(self, *a):
        pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_POST(self):
        if self.path.rstrip("/") != "/check":
            self.send_error(404)
            return
        n = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            data = {}
        result = check(str(data.get("message", "")), str(data.get("language", "en")))
        body = json.dumps(result, ensure_ascii=False).encode()
        self.send_response(200 if result["ok"] else 400)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print(f"Is This Legit? dev server: http://localhost:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
