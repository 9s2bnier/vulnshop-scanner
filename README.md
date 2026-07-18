# VulnShop + VulnScan

A deliberately vulnerable demo web app (`VulnShop`) paired with an automated
vulnerability scanner (`VulnScan`) built to find its flaws. Demonstrates both
sides of application security: writing (and recognizing) vulnerable code, and
building tooling that detects it.

## ⚠️ Only run these against apps you own or have explicit permission to test.
`VulnShop` is intentionally broken. Never deploy it anywhere reachable from
the internet — run it locally only.

## What's inside

```
vulnerable_app/
  app.py          # VulnShop -- intentionally vulnerable (stdlib only, no deps)
  secure_app.py   # Same app, each vulnerability fixed
scanner/
  scanner.py      # Black-box scanner that finds SQLi, XSS, and command injection
requirements.txt  # requests (only the scanner needs a dependency)
```

## The vulnerabilities

| # | Vulnerability | Endpoint | Root cause |
|---|---|---|---|
| 1 | SQL injection — auth bypass | `POST /login` | Username/password string-formatted directly into the SQL query |
| 2 | SQL injection — error-based | `GET /search` | Same: raw string concatenation into a `LIKE` clause |
| 3 | SQL injection — UNION-based data exfiltration | `GET /search` | Same query, exploited with a `UNION SELECT` to pull other rows |
| 4 | Stored XSS | `POST /comment` | User comments rendered into HTML with no escaping |
| 5 | OS command injection | `GET /ping` | User-supplied host passed straight into a shell string via `os.popen` |

Each one is fixed in `secure_app.py` using the standard mitigation: parameterized
queries, output escaping (`html.escape`), and `subprocess.run([...])` with a
strict input allowlist instead of shell string-building.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt   # only needed for the scanner (requests)
```

`VulnShop` itself has zero dependencies — it's built on Python's built-in
`http.server`, so it runs with just `python3 app.py`.

## Running it

**Terminal 1 — start the vulnerable app:**
```bash
cd vulnerable_app
python3 app.py
# VulnShop running on http://127.0.0.1:5000
```

**Terminal 2 — run the scanner against it:**
```bash
cd scanner
python3 scanner.py --url http://127.0.0.1:5000
```

### Actual output from a real run against `app.py`:

```
Scanning http://127.0.0.1:5000 ...

Found 5 vulnerabilities:

[1] SQL Injection (Authentication Bypass)  (Severity: Critical)
    Endpoint: POST /login
    Payload:  ' OR '1'='1' --
    Evidence: Welcome admin! (logged in)
    Fix:      Use parameterized queries instead of string-formatting user input into SQL.

[2] SQL Injection (Error-based)  (Severity: High)
    Endpoint: GET /search
    Payload:  '
    Evidence: DB error: unrecognized token: "'"
    Fix:      Use parameterized queries; never return raw DB errors to the client.

[3] SQL Injection (UNION-based data exfiltration)  (Severity: Critical)
    Endpoint: GET /search
    Payload:  ' UNION SELECT username, password FROM users --
    Evidence: {'results': [('admin', 'S3cretPass!'), ('admin', 'admin@example.com'), ('alice', 'alice123'), ('alice', 'alice@example.com')]}
    Fix:      Use parameterized queries; validate/limit column exposure.

[4] Stored Cross-Site Scripting (XSS)  (Severity: High)
    Endpoint: POST /comment
    Payload:  <script>alert('xss-test-12345')</script>
    Evidence: Payload reflected unescaped in the response HTML.
    Fix:      HTML-escape all user input before rendering (e.g. Python's html.escape).

[5] OS Command Injection  (Severity: Critical)
    Endpoint: GET /ping
    Payload:  127.0.0.1; echo CMDINJ_MARKER
    Evidence: Injected marker string appeared in command output.
    Fix:      Never build shell strings from user input. Use subprocess with an
              argument list (no shell=True) and validate input against a strict allowlist.
```

**Now try it against the fixed version** (`python3 secure_app.py`, runs on port
5001) — the scanner reports `No vulnerabilities found.`, proving the fixes work
against the same tests that caught the original flaws.

## How the scanner works

Black-box, response-based detection — no source code access assumed, same as
how a real external scanner would probe an app:

- **SQL injection**: sends known-bad syntax (`'`) and checks for a raw DB
  error message, then sends boolean/UNION payloads and checks for either an
  auth bypass or unexpected data (like another user's password) in the response.
- **XSS**: submits a unique `<script>` payload and checks whether it comes
  back unescaped in the HTML.
- **Command injection**: submits a payload with a shell metacharacter
  (`;` / `&&`) followed by a unique marker string, and checks whether the
  marker appears in the response — which would only happen if the shell
  actually executed the injected command.

## Extending this for your CV

- Add more vulnerability classes: path traversal, insecure deserialization, SSRF
- Add a severity-weighted score and export findings as JSON/HTML report
- Turn the scanner into a GitHub Action that fails CI if new vulnerabilities appear
- Add authenticated scanning (crawl behind a login)
- Compare against a real tool like `sqlmap` or OWASP ZAP and write up the differences
