#!/usr/bin/env python3
"""
VulnShop -- a deliberately vulnerable demo web app for security testing practice.

Contains INTENTIONAL vulnerabilities:
  - SQL injection (auth bypass) in /login
  - SQL injection (UNION-based data exfiltration) in /search
  - Stored XSS in /comment
  - OS command injection in /ping

Only run this locally / in an isolated environment. Never expose it to
a real network -- it is deliberately broken for educational purposes.
Built with the Python standard library only (no external dependencies).
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnerable.db")
COMMENTS = []


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)")
    conn.execute("INSERT INTO users (username, password, email) VALUES ('admin', 'S3cretPass!', 'admin@example.com')")
    conn.execute("INSERT INTO users (username, password, email) VALUES ('alice', 'alice123', 'alice@example.com')")
    conn.commit()
    conn.close()


class VulnHandler(BaseHTTPRequestHandler):
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
            self._send(200, "<h1>VulnShop demo</h1><p>Endpoints: /login (POST), /search?q=, /comment (GET/POST), /ping?host=</p>")
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

    # --- VULN 1: SQL injection in login (auth bypass) ---
    def handle_login(self, params):
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]
        conn = sqlite3.connect(DB_PATH)
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            row = conn.execute(query).fetchone()
        except Exception as e:
            self._send(500, f"DB error: {e}")
            conn.close()
            return
        conn.close()
        if row:
            self._send(200, f"Welcome {row[1]}! (logged in)")
        else:
            self._send(401, "Invalid credentials")

    # --- VULN 2: SQL injection in search (UNION-based exfiltration) ---
    def handle_search(self, params):
        q = params.get("q", [""])[0]
        conn = sqlite3.connect(DB_PATH)
        query = f"SELECT username, email FROM users WHERE username LIKE '%{q}%'"
        try:
            rows = conn.execute(query).fetchall()
        except Exception as e:
            self._send(500, f"DB error: {e}")
            conn.close()
            return
        conn.close()
        self._send(200, str({"results": rows}), content_type="application/json")

    # --- VULN 3: Stored XSS in comments ---
    def render_comments(self):
        body = "<h2>Comments</h2>"
        for c in COMMENTS:
            body += f"<p>{c}</p>"  # raw, unescaped -- vulnerable
        body += '<form method="POST" action="/comment"><input name="text"><input type="submit"></form>'
        self._send(200, body)

    # --- VULN 4: OS command injection ---
    def handle_ping(self, params):
        host = params.get("host", ["127.0.0.1"])[0]
        result = os.popen(f"ping -c 1 {host}").read()  # vulnerable -- unsanitized shell string
        self._send(200, f"<pre>{result}</pre>")

    def log_message(self, format, *args):
        pass  # quiet request logging


def run(port=5000):
    init_db()
    server = ThreadingHTTPServer(("127.0.0.1", port), VulnHandler)
    print(f"VulnShop running on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
