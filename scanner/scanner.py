#!/usr/bin/env python3
"""
VulnScan -- a small automated vulnerability scanner built to test VulnShop
(see ../vulnerable_app). Checks for SQL injection, XSS, and OS command
injection using black-box, response-based detection.

Educational tool: only run against applications you own or have explicit
permission to test.
"""

import argparse
import sys

import requests

SQLI_SEARCH_PAYLOADS = ["'", "' OR '1'='1", "' OR '1'='1' --", "' UNION SELECT username, password FROM users --"]
SQLI_LOGIN_PAYLOADS = ["' OR '1'='1' --", "admin' --"]
XSS_PAYLOAD = "<script>alert('xss-test-12345')</script>"
CMD_INJ_PAYLOADS = ["127.0.0.1; echo CMDINJ_MARKER", "127.0.0.1 && echo CMDINJ_MARKER"]

findings = []


def check_login_sqli(base_url):
    for payload in SQLI_LOGIN_PAYLOADS:
        r = requests.post(f"{base_url}/login", data={"username": payload, "password": "anything"})
        if r.status_code == 200 and "Welcome" in r.text:
            findings.append({
                "vuln": "SQL Injection (Authentication Bypass)",
                "endpoint": "POST /login",
                "payload": payload,
                "evidence": r.text.strip()[:200],
                "severity": "Critical",
                "fix": "Use parameterized queries instead of string-formatting user input into SQL.",
            })
            return


def check_search_sqli(base_url):
    for payload in SQLI_SEARCH_PAYLOADS:
        r = requests.get(f"{base_url}/search", params={"q": payload})
        if r.status_code == 500 or "DB error" in r.text:
            findings.append({
                "vuln": "SQL Injection (Error-based)",
                "endpoint": "GET /search",
                "payload": payload,
                "evidence": r.text.strip()[:200],
                "severity": "High",
                "fix": "Use parameterized queries; never return raw DB errors to the client.",
            })
        elif "S3cretPass" in r.text:
            findings.append({
                "vuln": "SQL Injection (UNION-based data exfiltration)",
                "endpoint": "GET /search",
                "payload": payload,
                "evidence": r.text.strip()[:200],
                "severity": "Critical",
                "fix": "Use parameterized queries; validate/limit column exposure.",
            })


def check_xss(base_url):
    r = requests.post(f"{base_url}/comment", data={"text": XSS_PAYLOAD})
    if XSS_PAYLOAD in r.text:
        findings.append({
            "vuln": "Stored Cross-Site Scripting (XSS)",
            "endpoint": "POST /comment",
            "payload": XSS_PAYLOAD,
            "evidence": "Payload reflected unescaped in the response HTML.",
            "severity": "High",
            "fix": "HTML-escape all user input before rendering (e.g. Python's html.escape).",
        })


def check_command_injection(base_url):
    for payload in CMD_INJ_PAYLOADS:
        r = requests.get(f"{base_url}/ping", params={"host": payload})
        if "CMDINJ_MARKER" in r.text:
            findings.append({
                "vuln": "OS Command Injection",
                "endpoint": "GET /ping",
                "payload": payload,
                "evidence": "Injected marker string appeared in command output.",
                "severity": "Critical",
                "fix": "Never build shell strings from user input. Use subprocess with an argument "
                       "list (no shell=True) and validate input against a strict allowlist.",
            })
            return


def main():
    parser = argparse.ArgumentParser(description="Vulnerability scanner for VulnShop demo app")
    parser.add_argument("--url", default="http://127.0.0.1:5000", help="Base URL of the target app")
    args = parser.parse_args()

    print(f"Scanning {args.url} ...\n")
    check_login_sqli(args.url)
    check_search_sqli(args.url)
    check_xss(args.url)
    check_command_injection(args.url)

    if not findings:
        print("No vulnerabilities found.")
        sys.exit(0)

    print(f"Found {len(findings)} vulnerabilities:\n")
    for i, f in enumerate(findings, 1):
        print(f"[{i}] {f['vuln']}  (Severity: {f['severity']})")
        print(f"    Endpoint: {f['endpoint']}")
        print(f"    Payload:  {f['payload']}")
        print(f"    Evidence: {f['evidence']}")
        print(f"    Fix:      {f['fix']}")
        print()

    sys.exit(1)


if __name__ == "__main__":
    main()
