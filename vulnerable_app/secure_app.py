#!/usr/bin/env python3
"""
VulnShop -- SECURE version.

Same functionality as app.py, but with each vulnerability fixed:
  - Parameterized SQL queries (no string concatenation)
  - HTML-escaped output (no raw rendering of user input)
  - No shell invocation for ping; validated host + subprocess without shell=True

Run the scanner against this version to see it report zero findings.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import sqlite3
import os
import re
import html
import subprocess

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnerable_secure.db")
COMMENTS = []
HOST_RE = re.compile(r"^[a-zA-Z0-9.\-]+$")


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)")
    conn.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", ("admin", "S3cretPass!", "admin@example.com"))
    conn.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", ("alice", "alice123", "alice@example.com"))
    conn.commit()
    conn.close()


class SecureHandler(BaseHTTPRequestHandler):
    def _send(self, status, body, content_type="text/html"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body.encode())

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode() if length else ""
        return parse_qs(raw)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/":
            self._send(200, "<h1>VulnShop (secure) demo</h1>")
        elif path == "/login":
            self._send(200, '<form method="POST" action="/login">Username: <input name="username"><br>Password: <input name="password" type="password"><br><input type="submit"></form>')
        elif path == "/search":
            self.handle_search(params)
        elif path == "/comment":
            self.render_comments()
        elif path == "/ping":
            self.handle_ping(params)
        else:
            self._send(404, "Not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = self._read_body()

        if path == "/login":
            self.handle_login(params)
        elif path == "/comment":
            text = params.get("text", [""])[0]
            COMMENTS.append(text)
            self.render_comments()
        else:
            self._send(404, "Not found")

    # --- FIX 1: parameterized query, no string concatenation ---
    def handle_login(self, params):
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        ).fetchone()
        conn.close()
        if row:
            self._send(200, f"Welcome {html.escape(row[1])}! (logged in)")
        else:
            self._send(401, "Invalid credentials")

    # --- FIX 2: parameterized query ---
    def handle_search(self, params):
        q = params.get("q", [""])[0]
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            "SELECT username, email FROM users WHERE username LIKE ?",
            (f"%{q}%",)
        ).fetchall()
        conn.close()
        self._send(200, str({"results": rows}), content_type="application/json")

    # --- FIX 3: escape output before rendering ---
    def render_comments(self):
        body = "<h2>Comments</h2>"
        for c in COMMENTS:
            body += f"<p>{html.escape(c)}</p>"
        body += '<form method="POST" action="/comment"><input name="text"><input type="submit"></form>'
        self._send(200, body)

    # --- FIX 4: validate input, no shell invocation ---
    def handle_ping(self, params):
        host = params.get("host", ["127.0.0.1"])[0]
        if not HOST_RE.match(host):
            self._send(400, "Invalid host")
            return
        try:
            result = subprocess.run(
                ["ping", "-c", "1", host],
                capture_output=True, text=True, timeout=5
            ).stdout
        except Exception as e:
            result = str(e)
        self._send(200, f"<pre>{html.escape(result)}</pre>")

    def log_message(self, format, *args):
        pass


def run(port=5001):
    init_db()
    server = ThreadingHTTPServer(("127.0.0.1", port), SecureHandler)
    print(f"VulnShop (secure) running on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
