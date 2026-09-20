#!/usr/bin/env python3
"""CTF Attack-Defense Advanced Micro-WAF for Python (Flask / WSGI).

INSTALL untuk Flask:
    from ctf_waf import install_waf
    install_waf(app)

INSTALL untuk WSGI generik:
    from ctf_waf import WafMiddleware
    app = WafMiddleware(app)
"""

import json
import os
import re
import urllib.parse
from datetime import datetime
import os
import re
import urllib.parse
from datetime import datetime

LOG_FILE = "/tmp/waf_blocked.log"
CAPTURE_FILE = "/tmp/waf_captured.jsonl"

# Whitelist SLA Checker — tambahkan IP panitia
WHITELIST_IPS = set([
    # "10.0.0.1",      # contoh IP SLA checker
])
WHITELIST_UA_KEYWORDS = ["SLA", "Checker", "Monitor", "Health", "Uptime"]

# ══════════════════════════════════════════════════════════════════════
#  OWASP TOP 10 DETECTION RULES
# ══════════════════════════════════════════════════════════════════════
RULES = [
    # A01: BROKEN ACCESS CONTROL — Path Traversal / LFI
    ("A01-LFI",    re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e){2,}", re.I)),
    ("A01-LFI",    re.compile(r"/etc/(?:passwd|shadow|group|sudoers|hosts|crontab)", re.I)),
    ("A01-LFI",    re.compile(r"/proc/(?:self|version|cmdline|environ|net/tcp|\d+/(?:cmdline|environ|exe|fd|maps))", re.I)),
    ("A01-LFI",    re.compile(r"/(?:root|home/\w+)/\.ssh/(?:id_rsa|authorized_keys|id_ed25519)", re.I)),
    ("A01-STREAM", re.compile(r"php://(?:filter|input|data|expect|fd|memory|temp)", re.I)),
    ("A01-STREAM", re.compile(r"(?:zip|phar|rar|jar|bzip2|zlib|glob)://", re.I)),
    ("A01-STREAM", re.compile(r"(?:convert\.base64-(?:encode|decode)|convert\.iconv|string\.rot13)", re.I)),

    # A03: INJECTION — SQL Injection
    ("A03-SQLI",   re.compile(r"\bunion\b[\s/\*]+(?:all[\s/\*]+)?\bselect\b", re.I)),
    ("A03-SQLI",   re.compile(r"\bselect\b[\s/\*]+(?:@@version|version\(\)|user\(\)|current_user|schema_name|table_name|column_name|concat\(|group_concat\(|load_file\()", re.I)),
    ("A03-SQLI",   re.compile(r"\b(?:or|and)\b[\s/\*]+['\"]?\d+['\"]?[\s/\*]*=[\s/\*]*['\"]?\d+", re.I)),
    ("A03-SQLI",   re.compile(r"\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", re.I)),
    ("A03-SQLI",   re.compile(r"\b(?:extractvalue|updatexml|exp)\s*\(", re.I)),
    ("A03-SQLI",   re.compile(r"(?:into\s+(?:out|dump)file|load_file)\s*[\s('\"]", re.I)),
    ("A03-SQLI",   re.compile(r"(?:information_schema|mysql\.|sys\.)\w+", re.I)),
    ("A03-SQLI",   re.compile(r";\s*(?:drop|alter|truncate|create|insert\s+into|update\s+\w+\s+set|delete\s+from)\b", re.I)),

    # A03: INJECTION — NoSQL
    ("A03-NOSQL",  re.compile(r"\$(?:gt|gte|lt|lte|ne|eq|regex|where|exists|nin|in|or|and|not)\b", re.I)),

    # A03: INJECTION — Command Injection / RCE
    ("A03-RCE",    re.compile(r"(?:;|\|\||&&|`|\$\()\s*(?:cat|tac|head|tail|more|less|nl|od|xxd|strings|base64|rev)\b", re.I)),
    ("A03-RCE",    re.compile(r"(?:;|\|\||&&|`|\$\()\s*(?:ls|dir|find|locate|which|whereis|file|stat)\b", re.I)),
    ("A03-RCE",    re.compile(r"(?:;|\|\||&&|`|\$\()\s*(?:id|whoami|uname|hostname|ifconfig|ip\s+a|pwd|env|printenv)\b", re.I)),
    ("A03-RCE",    re.compile(r"(?:;|\|\||&&|`|\$\()\s*(?:wget|curl|fetch|nc|ncat|socat|telnet|ssh|scp|ftp)\b", re.I)),
    ("A03-RCE",    re.compile(r"(?:;|\|\||&&|`|\$\()\s*(?:bash|sh|zsh|dash|csh|ksh|python[23]?|perl|ruby|php|node)\b", re.I)),
    ("A03-RCE",    re.compile(r"(?:;|\|\||&&|`|\$\()\s*(?:rm|mv|cp|chmod|chown|kill|pkill|killall)\b", re.I)),

    # A03: Direct flag reads
    ("A03-FLAG",   re.compile(r"(?:cat|tac|head|tail|more|less|strings|xxd|od|nl|rev|base64)\s+[^\s;&|]*(?:flag|token|secret|key)\b", re.I)),

    # A03: Reverse shells
    ("A03-RSHELL", re.compile(r"/dev/(?:tcp|udp)/\d", re.I)),
    ("A03-RSHELL", re.compile(r"(?:bash\s+-i|sh\s+-i)\s+[>&]+\s*/dev/", re.I)),
    ("A03-RSHELL", re.compile(r"\bmkfifo\s+/tmp/", re.I)),
    ("A03-RSHELL", re.compile(r"\b(?:nc|ncat|netcat)\s+(?:-[a-z]*e|-[a-z]*c)\s", re.I)),

    # A03: PHP exec functions
    ("A03-PHPEXEC",re.compile(r"\b(?:eval|assert|create_function|call_user_func|call_user_func_array)\s*\(", re.I)),
    ("A03-PHPEXEC",re.compile(r"\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(", re.I)),

    # A05: Webshell / backdoor access
    ("A05-SHELL",  re.compile(r"/(?:c99|r57|wso|b374k|alfa|mini|shell|cmd|backdoor|webshell|phpinfo|adminer)\.php", re.I)),
    ("A05-SHELL",  re.compile(r"[?&](?:cmd|exec|command|run|execute|shell|code|eval|input)=", re.I)),
    ("A05-CONFIG", re.compile(r"(?:\.env|\.git/|\.svn/|\.htpasswd|\.htaccess|wp-config\.php|config\.php\.bak)", re.I)),

    # A07: XSS
    ("A07-XSS",    re.compile(r"<\s*script[\s>]", re.I)),
    ("A07-XSS",    re.compile(r"\bon\w+\s*=\s*[\"']?(?:javascript|alert|confirm|prompt|eval|document|window)", re.I)),
    ("A07-XSS",    re.compile(r"javascript\s*:", re.I)),

    # A08: Insecure Deserialization
    ("A08-DESER",  re.compile(r'O:\d+:"[^"]+"\s*:\d+:\s*\{')),
    ("A08-DESER",  re.compile(r"(?:rO0ABX|aced0005)", re.I)),

    # A10: SSRF
    ("A10-SSRF",   re.compile(r"(?:https?|ftp|gopher|dict|ldap|tftp)://(?:127\.|0\.|localhost|0x7f|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|::1)", re.I)),
]


def _deep_decode(s):
    """Multi-layer URL + HTML entity decode."""
    prev = ""
    decoded = s
    for _ in range(4):
        if decoded == prev:
            break
        prev = decoded
        decoded = urllib.parse.unquote(decoded)
    decoded = decoded.replace("\x00", "").replace("\\", "/")
    return decoded


def _check_payload(combined):
    """Check payload against all rules. Returns (rule_id, pattern) or None."""
    for rule_id, rx in RULES:
        if rx.search(combined):
            return rule_id, rx.pattern
    return None


def _log_block(rule_id, ip, method, path, payload, body="", ua=""):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] BLOCKED rule={rule_id} ip={ip} method={method} uri={path[:200]}\n")
    except Exception:
        pass
    try:
        with open(CAPTURE_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "timestamp": ts, "rule": rule_id, "ip": ip,
                "method": method, "uri": path,
                "payload": payload[:2048], "body": body[:1024], "ua": ua[:256],
            }, ensure_ascii=False) + "\n")
    except Exception:
        pass


def install_waf(app):
    """Install WAF sebagai Flask before_request hook."""
    @app.before_request
    def _waf_filter():
        from flask import request, abort

        ip = request.remote_addr or "0.0.0.0"
        if ip in WHITELIST_IPS:
            return None

        ua = request.headers.get("User-Agent", "")
        for kw in WHITELIST_UA_KEYWORDS:
            if kw.lower() in ua.lower():
                return None

        raw_path = request.full_path or "/"
        query = request.query_string.decode("utf-8", errors="ignore")
        body = request.get_data(as_text=True)[:65536]
        cookie = request.headers.get("Cookie", "")
        referer = request.headers.get("Referer", "")

        raw_all = f"{raw_path}\n{query}\n{body}\n{cookie}\n{referer}"
        decoded = _deep_decode(raw_all)
        combined = f"{raw_all}\n{decoded}"

        result = _check_payload(combined)
        if result:
            rule_id, _ = result
            _log_block(rule_id, ip, request.method, raw_path, decoded, body, ua)
            abort(403)

        return None


class WafMiddleware:
    """Generic WSGI middleware WAF."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        ip = environ.get("REMOTE_ADDR", "0.0.0.0")
        if ip in WHITELIST_IPS:
            return self.app(environ, start_response)

        ua = environ.get("HTTP_USER_AGENT", "")
        for kw in WHITELIST_UA_KEYWORDS:
            if kw.lower() in ua.lower():
                return self.app(environ, start_response)

        path = environ.get("PATH_INFO", "/")
        query = environ.get("QUERY_STRING", "")
        cookie = environ.get("HTTP_COOKIE", "")
        referer = environ.get("HTTP_REFERER", "")
        method = environ.get("REQUEST_METHOD", "GET")

        body = ""
        if method in ("POST", "PUT", "PATCH"):
            try:
                length = int(environ.get("CONTENT_LENGTH", 0) or 0)
                body = environ["wsgi.input"].read(min(length, 65536)).decode("utf-8", errors="ignore")
            except Exception:
                pass

        raw_all = f"{path}\n{query}\n{body}\n{cookie}\n{referer}"
        decoded = _deep_decode(raw_all)
        combined = f"{raw_all}\n{decoded}"

        result = _check_payload(combined)
        if result:
            rule_id, _ = result
            _log_block(rule_id, ip, method, path, decoded, body, ua)
            start_response("403 Forbidden", [("Content-Type", "text/plain")])
            return [b"403 Forbidden\n"]

        return self.app(environ, start_response)
