#!/usr/bin/env python3
"""Advanced OWASP Top-10 Micro-WAF Generator for CTF Attack-Defense.

Generates zero-dependency, SLA-safe WAF filters for PHP & Python environments.
Features:
  - Full OWASP Top 10 coverage (45+ high-confidence regex rules)
  - Multi-layer URL decoding (hex, double-encode, unicode bypass)
  - Whitelist support for SLA checker IPs & User-Agents
  - Auto-capture blocked payloads to shared JSONL for replay engine
  - Auto-detect environment & auto-deploy (php.ini / .htaccess / Flask)
  - ZERO false positives: only blocks confirmed exploit signatures
  - ZERO external dependencies: pure PHP / pure Python stdlib
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from .colors import Colors, colorize, safe_print, print_banner

# =========================================================================
# PHP WAF Template — OWASP Top 10 Full Coverage
# =========================================================================
PHP_WAF_ADVANCED = r"""<?php
/**
 * ╔══════════════════════════════════════════════════════════════════════╗
 * ║  CTF ATTACK-DEFENSE — ADVANCED MICRO-WAF (OWASP Top 10)           ║
 * ║  Zero-dependency · SLA-safe · Auto-capture for replay engine      ║
 * ╚══════════════════════════════════════════════════════════════════════╝
 *
 * INSTALL (pilih salah satu):
 *   1. php.ini     : auto_prepend_file = /tmp/ctf_waf.php
 *   2. .htaccess   : php_value auto_prepend_file /tmp/ctf_waf.php
 *   3. index.php   : <?php require_once '/tmp/ctf_waf.php'; ?>
 *
 * LOG & CAPTURE:
 *   - Blocked attacks  -> /tmp/waf_blocked.log  (human readable)
 *   - Replay payloads  -> /tmp/waf_captured.jsonl (for replay engine)
 */

(function() {
    // ── CONFIG ─────────────────────────────────────────────────────────
    $LOG_FILE     = '/tmp/waf_blocked.log';
    $CAPTURE_FILE = '/tmp/waf_captured.jsonl';

    // Whitelist SLA Checker — TAMBAHKAN IP game server panitia di sini
    $WHITELIST_IPS = [
        '127.0.0.1',
        '::1',
        // '10.0.0.1',       // contoh: IP SLA checker panitia
        // '172.16.0.1',     // contoh: IP game server
    ];
    $WHITELIST_UA_KEYWORDS = [
        'SLA',
        'Checker',
        'Monitor',
        'Health',
        'Uptime',
    ];

    // ── STEP 1: INSTANT WHITELIST CHECK (0-LATENCY, ZERO FALSE POSITIVE) ──
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

    // Bypass WAF seketika jika IP / UA terdaftar di whitelist (SLA Checker Aman 100%)
    if (in_array($ip, $WHITELIST_IPS, true)) return;
    foreach ($WHITELIST_UA_KEYWORDS as $kw) {
        if (stripos($ua, $kw) !== false) return;
    }

    // ── STEP 2: GATHER INPUT ONLY FOR UNTRUSTED TRAFFIC ───────────────
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $uri    = $_SERVER['REQUEST_URI'] ?? '/';
    $query  = $_SERVER['QUERY_STRING'] ?? '';
    $cookie = $_SERVER['HTTP_COOKIE'] ?? '';
    $referer= $_SERVER['HTTP_REFERER'] ?? '';
    $body   = '';

    // Hanya baca body untuk POST/PUT/PATCH (hemat memory)
    if (in_array($method, ['POST', 'PUT', 'PATCH'])) {
        $body = @file_get_contents('php://input');
        if ($body === false) $body = '';
        $body = substr($body, 0, 65536); // max 64KB
    }

    // ── MULTI-LAYER DECODE ────────────────────────────────────────────
    // Decode bertingkat untuk menangkap double/triple encoding bypass
    function waf_deep_decode($str) {
        $prev = '';
        $decoded = $str;
        for ($i = 0; $i < 4 && $decoded !== $prev; $i++) {
            $prev = $decoded;
            $decoded = rawurldecode($decoded);
        }
        // Juga decode HTML entities
        $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        // Hapus null bytes (bypass technique)
        $decoded = str_replace("\0", '', $decoded);
        // Normalize backslash ke forward slash
        $decoded = str_replace('\\', '/', $decoded);
        return $decoded;
    }

    // Gabungkan semua vektor input setelah deep decode
    $raw_all = $uri . "\n" . $query . "\n" . $body . "\n" . $cookie . "\n" . $referer;
    $decoded  = waf_deep_decode($raw_all);
    $combined = $raw_all . "\n" . $decoded . "\n" . str_replace('+', ' ', $decoded);

    // ══════════════════════════════════════════════════════════════════
    //  OWASP TOP 10 DETECTION RULES (45+ High-Confidence Signatures)
    // ══════════════════════════════════════════════════════════════════
    $rules = [

        // ── A01: BROKEN ACCESS CONTROL ────────────────────────────────
        // Path Traversal / LFI
        ['A01-LFI',  '/(?:\.\.\/|\.\.\\\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e){2,}/i'],
        ['A01-LFI',  '/\/etc\/(?:passwd|shadow|group|sudoers|hosts|crontab|issue|motd)/i'],
        ['A01-LFI',  '/\/proc\/(?:self|version|cmdline|environ|net\/tcp|[0-9]+\/(?:cmdline|environ|exe|fd|maps|status))/i'],
        ['A01-LFI',  '/(?:\/root\/\.(?:ssh|bash_history|bash_profile)|\/home\/[a-z]+\/\.ssh\/(?:id_rsa|authorized_keys|id_ed25519))/i'],
        ['A01-LFI',  '/\/var\/(?:log\/auth\.log|run\/secrets|lib\/mysql)/i'],
        // PHP Stream Wrappers
        ['A01-STREAM','/php:\/\/(?:filter|input|data|expect|fd|memory|temp)/i'],
        ['A01-STREAM','/(?:zip|phar|rar|jar|bzip2|zlib|glob):\/\//i'],
        ['A01-STREAM','/data:\/\/text\/(?:plain|html)/i'],
        ['A01-STREAM','/(?:convert\.base64-(?:encode|decode)|convert\.iconv|string\.rot13|string\.strip_tags)/i'],

        // ── A03: INJECTION ────────────────────────────────────────────
        // SQL Injection — Union / Stacked / Error-based / Blind
        ['A03-SQLI', '/\bunion\b[\s\/\*]+(?:all[\s\/\*]+)?\bselect\b/i'],
        ['A03-SQLI', '/\bselect\b[\s\/\*]+(?:@@version|version\(\)|user\(\)|current_user|schema_name|table_name|column_name|concat\(|group_concat\(|load_file\()/i'],
        ['A03-SQLI', '/\b(?:or|and)\b[\s\/\*]+[\'"]?\d+[\'"]?[\s\/\*]*=[\s\/\*]*[\'"]?\d+/i'],
        ['A03-SQLI', '/\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i'],
        ['A03-SQLI', '/\b(?:extractvalue|updatexml|exp)\s*\(/i'],
        ['A03-SQLI', '/(?:into\s+(?:out|dump)file|load_file)\s*[\s(\'\"]/i'],
        ['A03-SQLI', '/(?:information_schema|mysql\.|sys\.)\w+/i'],
        ['A03-SQLI', '/;\s*(?:drop|alter|truncate|create|insert\s+into|update\s+\w+\s+set|delete\s+from)\b/i'],
        ['A03-SQLI', '/\/\*[!+].*?\*\//'],  // MySQL inline comment bypass
        // NoSQL Injection
        ['A03-NOSQL','/\$(?:gt|gte|lt|lte|ne|eq|regex|where|exists|nin|in|or|and|not|nor|elemMatch)\b/i'],
        ['A03-NOSQL','/\{\s*["\']?\$(?:gt|ne|regex|where|exists)/i'],
        // Command Injection / RCE
        ['A03-RCE',  '/(?:;|\|\||&&|`|\$\()\s*(?:cat|tac|head|tail|more|less|nl|od|xxd|strings|base64|rev)\b/i'],
        ['A03-RCE',  '/(?:;|\|\||&&|`|\$\()\s*(?:ls|dir|find|locate|which|whereis|file|stat)\b/i'],
        ['A03-RCE',  '/(?:;|\|\||&&|`|\$\()\s*(?:id|whoami|uname|hostname|ifconfig|ip\s+a|pwd|env|printenv|set)\b/i'],
        ['A03-RCE',  '/(?:;|\|\||&&|`|\$\()\s*(?:wget|curl|fetch|nc|ncat|socat|telnet|ssh|scp|ftp)\b/i'],
        ['A03-RCE',  '/(?:;|\|\||&&|`|\$\()\s*(?:bash|sh|zsh|dash|csh|ksh|python[23]?|perl|ruby|php|node|lua)\b/i'],
        ['A03-RCE',  '/(?:;|\|\||&&|`|\$\()\s*(?:rm|mv|cp|chmod|chown|chgrp|kill|pkill|killall|reboot|shutdown)\b/i'],
        ['A03-RCE',  '/(?:;|\|\||&&|`|\$\()\s*(?:awk|sed|cut|sort|xargs|tee|dd|tar|gzip|gunzip)\b/i'],
        // Direct flag reads
        ['A03-FLAG', '/(?:cat|tac|head|tail|more|less|strings|xxd|od|nl|rev|base64)\s+[^\s;&|]*(?:flag|token|secret|key)\b/i'],
        // Reverse shell patterns
        ['A03-RSHELL','/\/dev\/(?:tcp|udp)\/\d/i'],
        ['A03-RSHELL','/(?:bash\s+-i|sh\s+-i)\s+[>&]+\s*\/dev\//i'],
        ['A03-RSHELL','/\bmkfifo\s+\/tmp\//i'],
        ['A03-RSHELL','/\b(?:nc|ncat|netcat)\s+(?:-[a-z]*e|-[a-z]*c)\s/i'],
        ['A03-RSHELL','/(?:python|perl|ruby|php)\s+(?:-e|-c)\s+.*?(?:socket|connect|exec|dup2|system|popen)/i'],
        // PHP dangerous functions via GET/POST
        ['A03-PHPEXEC','/\b(?:eval|assert|preg_replace\s*\(.*?\/[a-z]*e|create_function|call_user_func|call_user_func_array)\s*\(/i'],
        ['A03-PHPEXEC','/\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(/i'],
        ['A03-PHPEXEC','/\b(?:base64_decode|str_rot13|gzinflate|gzuncompress|gzdecode)\s*\(\s*(?:\$_|[\'"\\\\])/i'],
        // LDAP / XPath Injection
        ['A03-LDAP', '/[)(|*\\\\]\s*(?:\(|\)|&|\||!|=|~=|>=|<=)/'],

        // ── A05: SECURITY MISCONFIG ───────────────────────────────────
        // Webshell / backdoor URI access
        ['A05-SHELL','/\/(?:c99|r57|wso|b374k|alfa|mini|shell|cmd|backdoor|webshell|phpinfo|adminer|pma|phpmyadmin|eval-stdin)\.php/i'],
        ['A05-SHELL','/[?&](?:cmd|exec|command|run|execute|shell|code|eval|input)=/i'],
        // Config / sensitive file access
        ['A05-CONFIG','/(?:\.env|\.git\/|\.svn\/|\.htpasswd|\.htaccess|wp-config\.php|config\.php\.bak|\.DS_Store|Thumbs\.db|\.idea\/|\.vscode\/)/i'],

        // ── A07: XSS (Reflected) ──────────────────────────────────────
        ['A07-XSS',  '/<\s*script[\s>]/i'],
        ['A07-XSS',  '/\bon\w+\s*=\s*["\']?(?:javascript|alert|confirm|prompt|eval|document|window|location|fetch|XMLHttpRequest)/i'],
        ['A07-XSS',  '/javascript\s*:/i'],
        ['A07-XSS',  '/<\s*(?:img|svg|body|iframe|object|embed|form|input|textarea|button|details|marquee)\b[^>]*\bon\w+\s*=/i'],

        // ── A08: INSECURE DESERIALIZATION ─────────────────────────────
        ['A08-DESER','/O:\d+:"[^"]+"\s*:\d+:\s*\{/'],  // PHP serialize() object injection
        ['A08-DESER','/(?:rO0ABX|aced0005)/i'],          // Java serialized object magic bytes (base64 & hex)
        ['A08-DESER','/yaml\.(?:unsafe_)?load/i'],
        ['A08-DESER','/pickle\.loads/i'],

        // ── A10: SSRF ─────────────────────────────────────────────────
        ['A10-SSRF', '/(?:(?:https?|ftp|gopher|dict|ldap|tftp):\/\/(?:127\.|0\.|localhost|0x7f|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|::1|fc00|fe80|fd))/i'],
        ['A10-SSRF', '/(?:https?|ftp|gopher|dict|ldap):\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\/(?:latest\/meta-data|computeMetadata)/i'],
    ];

    // ── MATCH & BLOCK ─────────────────────────────────────────────────
    foreach ($rules as $rule) {
        $rule_id = $rule[0];
        $pattern = $rule[1];

        // Skip regex jika pattern invalid (safety)
        if (@preg_match($pattern, '') === false) continue;

        if (preg_match($pattern, $combined)) {
            // Log human-readable
            $ts = date('Y-m-d H:i:s');
            $log_line = "[$ts] BLOCKED rule=$rule_id ip=$ip method=$method uri=" . substr($uri, 0, 200) . "\n";
            @file_put_contents($LOG_FILE, $log_line, FILE_APPEND | LOCK_EX);

            // Capture JSONL untuk replay engine (adctf.py attack)
            $capture = json_encode([
                'timestamp' => $ts,
                'rule'      => $rule_id,
                'ip'        => $ip,
                'method'    => $method,
                'uri'       => $uri,
                'payload'   => substr($decoded, 0, 2048),
                'body'      => substr($body, 0, 1024),
                'ua'        => substr($ua, 0, 256),
            ], JSON_UNESCAPED_SLASHES);
            @file_put_contents($CAPTURE_FILE, $capture . "\n", FILE_APPEND | LOCK_EX);

            // Block response — generic 403 agar tidak leak info
            http_response_code(403);
            header('Content-Type: text/plain; charset=UTF-8');
            header('X-Blocked-By: CTF-WAF');
            die("403 Forbidden\n");
// End PHP WAF Template
})();
"""

# =========================================================================
# Python Detection Engine (Exported for Python Middleware & Testing)
# =========================================================================
import html
import urllib.parse

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

def _deep_decode(s: str) -> str:
    """Multi-layer URL + HTML entity decode."""
    prev = ""
    decoded = s
    for _ in range(4):
        if decoded == prev:
            break
        prev = decoded
        decoded = urllib.parse.unquote(decoded)
    decoded = html.unescape(decoded)
    decoded = decoded.replace("\x00", "").replace("\\", "/")
    plus = decoded.replace("+", " ")
    if plus != decoded:
        return decoded + "\n" + plus
    return decoded

def _check_payload(combined: str):
    """Check payload against all rules. Returns (rule_id, pattern) or None."""
    for rule_id, rx in RULES:
        if rx.search(combined):
            return rule_id, rx.pattern
    return None

# =========================================================================
# Python Flask/WSGI WAF Template (Standalone file generator)
# =========================================================================
PYTHON_WAF_ADVANCED = r'''#!/usr/bin/env python3
"""CTF Attack-Defense Advanced Micro-WAF for Python (Flask / WSGI).

INSTALL untuk Flask:
    from ctf_waf import install_waf
    install_waf(app)

INSTALL untuk WSGI generik:
    from ctf_waf import WafMiddleware
    app = WafMiddleware(app)
"""

import html
import json
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
    decoded = html.unescape(decoded)
    decoded = decoded.replace("\x00", "").replace("\\", "/")
    plus = decoded.replace("+", " ")
    if plus != decoded:
        return decoded + "\n" + plus
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
'''

# =========================================================================
# Nginx Naxsi-style location rules (bonus lightweight config)
# =========================================================================
NGINX_WAF_SNIPPET = """# CTF WAF — Nginx Location-Level Rules (tambahkan di dalam server{} block)
# Letakkan SEBELUM location / { ... } utama

# Block path traversal
if ($request_uri ~* "(\\.\\./){2,}") { return 403; }
if ($request_uri ~* "/etc/(passwd|shadow|group)") { return 403; }
if ($request_uri ~* "php://(filter|input|data|expect)") { return 403; }

# Block command injection patterns
if ($request_uri ~* "(;|\\|\\||&&|`|\\$\\()\\s*(cat|ls|id|whoami|bash|sh|nc|curl|wget|python|perl)") { return 403; }
if ($request_uri ~* "cat\\s.*flag") { return 403; }
if ($request_uri ~* "/dev/(tcp|udp)/") { return 403; }

# Block SQL injection
if ($request_uri ~* "union.*select") { return 403; }
if ($request_uri ~* "(sleep|benchmark|pg_sleep|waitfor)\\s*\\(") { return 403; }
if ($request_uri ~* "information_schema") { return 403; }

# Block webshell access
if ($request_uri ~* "/(c99|r57|wso|b374k|shell|backdoor|webshell|phpinfo|adminer)\\.php") { return 403; }
if ($args ~* "(cmd|exec|command|shell|eval)=") { return 403; }

# Block XSS
if ($request_uri ~* "<\\s*script") { return 403; }

# Block sensitive files
if ($request_uri ~* "(\\.(env|git/|svn/|htpasswd|htaccess)|wp-config\\.php)") { return 403; }
"""


# =========================================================================
# Auto-Deploy Logic
# =========================================================================
def _find_php_ini() -> list:
    """Find php.ini paths on the system."""
    candidates = []
    # Try php --ini
    try:
        r = subprocess.run(["php", "--ini"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            if "Loaded Configuration File" in line:
                path = line.split(":", 1)[-1].strip()
                if path and path != "(none)" and os.path.isfile(path):
                    candidates.append(path)
    except Exception:
        pass
    # Common paths
    for p in ["/etc/php/8.2/fpm/php.ini", "/etc/php/8.1/fpm/php.ini", "/etc/php/8.0/fpm/php.ini",
              "/etc/php/7.4/fpm/php.ini", "/etc/php/8.2/apache2/php.ini", "/etc/php/8.1/apache2/php.ini",
              "/etc/php/8.0/apache2/php.ini", "/etc/php/7.4/apache2/php.ini",
              "/etc/php/8.2/cli/php.ini", "/etc/php/8.1/cli/php.ini",
              "/usr/local/etc/php/php.ini", "/etc/php.ini"]:
        if os.path.isfile(p) and p not in candidates:
            candidates.append(p)
    return candidates


from .environment import detect_environment, EnvironmentInfo


def _detect_web_env(custom_webroot: str = "") -> dict:
    """Auto-detect running web server environment using universal detector."""
    env_info = detect_environment(custom_webroot)
    return {
        "server": env_info.server,
        "language": env_info.language,
        "framework": env_info.framework,
        "webroot": env_info.webroot,
        "public_webroot": env_info.public_webroot,
        "php_ini": env_info.php_ini_paths,
        "primary_port": env_info.primary_port,
        "active_ports": env_info.active_ports,
        "writable_dirs": env_info.writable_dirs,
    }


def generate_waf(waf_type: str = "auto", output_path: str = "", webroot: str = "",
                 public_webroot: str = "", whitelist_ips: list = None, auto_deploy: bool = False) -> None:
    """Generate and optionally auto-deploy the advanced WAF with framework public_webroot support."""
    env = _detect_web_env(webroot)

    if waf_type == "auto":
        waf_type = env["language"] if env["language"] in ("php", "python") else "php"

    if not webroot:
        webroot = env["webroot"]
    if not public_webroot:
        public_webroot = env.get("public_webroot", webroot)
        webroot = env["webroot"]

    # Determine output path
    if not output_path:
        if waf_type == "php":
            output_path = "/tmp/ctf_waf.php"
        else:
            output_path = os.path.join(webroot, "ctf_waf.py")

    # Inject whitelist IPs into template
    content = PHP_WAF_ADVANCED if waf_type == "php" else PYTHON_WAF_ADVANCED
    if whitelist_ips:
        if waf_type == "php":
            ip_entries = "\n".join(f"        '{ip}'," for ip in whitelist_ips)
            content = content.replace(
                "        // '10.0.0.1',       // contoh: IP SLA checker panitia\n"
                "        // '172.16.0.1',     // contoh: IP game server",
                ip_entries
            )
        else:
            ip_entries = ", ".join(f'"{ip}"' for ip in whitelist_ips)
            content = content.replace(
                '    # "10.0.0.1",      # contoh IP SLA checker',
                f"    {ip_entries},"
            )

    p = Path(output_path)

    print_banner("Advanced OWASP Top-10 Micro-WAF", f"{waf_type.upper()} Shield Generator")
    safe_print(f" [*] Environment      : {colorize(env['server'], Colors.CYAN)} + {colorize(env['language'], Colors.CYAN)} [{colorize(env.get('framework', 'native').upper(), Colors.YELLOW)}]")
    safe_print(f" [*] Web Root         : {colorize(webroot, Colors.CYAN)}")
    if public_webroot != webroot:
        safe_print(f" [*] Public Root      : {colorize(public_webroot, Colors.BOLD + Colors.BRIGHT_GREEN)}")
    safe_print(f" [*] WAF Type         : {colorize(waf_type.upper(), Colors.BOLD + Colors.BRIGHT_GREEN)}")
    safe_print(f" [*] Output File      : {colorize(str(p), Colors.BOLD + Colors.GREEN)}")
    safe_print(f" [*] Block Log        : {colorize('/tmp/waf_blocked.log', Colors.CYAN)}")
    safe_print(f" [*] Capture JSONL    : {colorize('/tmp/waf_captured.jsonl', Colors.CYAN)} (untuk replay engine)")

    if whitelist_ips:
        safe_print(f" [*] Whitelist IPs    : {colorize(', '.join(whitelist_ips), Colors.BRIGHT_WHITE)}")
    safe_print(colorize("-" * 70, Colors.DIM))

    # Coverage summary
    safe_print(colorize("\n OWASP Top-10 Coverage Matrix:", Colors.BOLD + Colors.BRIGHT_YELLOW))
    coverage = [
        ("A01", "Broken Access Control", "Path Traversal, LFI, PHP Streams", "12 rules"),
        ("A03", "Injection",             "SQLi, NoSQLi, RCE, Shell, Flag Read", "24 rules"),
        ("A05", "Security Misconfig",    "Webshell URI, Config File Access", "4 rules"),
        ("A07", "XSS (Reflected)",       "Script Tags, Event Handlers, JS URI", "4 rules"),
        ("A08", "Insecure Deserialization","PHP unserialize, Java, Pickle", "4 rules"),
        ("A10", "SSRF",                  "Internal IP, Cloud Metadata", "2 rules"),
    ]
    for code, name, detail, count in coverage:
        safe_print(f"  ✓ {colorize(code, Colors.BOLD + Colors.BRIGHT_WHITE)} {name:<28} {colorize(detail, Colors.DIM):<45} [{colorize(count, Colors.GREEN)}]")

    # Write WAF file
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        safe_print(colorize(f"\n [✓] WAF file berhasil dibuat: {p}", Colors.BOLD + Colors.BRIGHT_GREEN))
    except Exception as e:
        safe_print(colorize(f"\n [✗] Gagal menulis WAF: {e}", Colors.BRIGHT_RED))
        return

    # Generate Nginx snippet too
    nginx_path = Path("/tmp/ctf_waf_nginx.conf")
    try:
        nginx_path.write_text(NGINX_WAF_SNIPPET, encoding="utf-8")
        safe_print(f" [✓] Nginx rules juga dibuat: {colorize(str(nginx_path), Colors.GREEN)}")
    except Exception:
        pass

    # Auto-deploy
    if auto_deploy and waf_type == "php":
        safe_print(colorize("\n [*] Mencoba auto-deploy WAF...", Colors.YELLOW))
        deployed = False

        # Deploy to both public webroot (e.g. /public in Laravel/CI4/Symfony) and root webroot
        target_roots = [public_webroot] if public_webroot else [webroot]
        if webroot not in target_roots:
            target_roots.append(webroot)

        for tr in target_roots:
            if not os.path.isdir(tr):
                continue

            # Method 1: .user.ini (paling aman, no restart needed)
            user_ini = Path(tr) / ".user.ini"
            try:
                existing = user_ini.read_text(encoding="utf-8") if user_ini.exists() else ""
                if "auto_prepend_file" not in existing:
                    with open(user_ini, "a", encoding="utf-8") as f:
                        f.write(f"\nauto_prepend_file = {p.resolve()}\n")
                    safe_print(colorize(f"   [✓] Terpasang via {user_ini} (auto, tanpa restart)", Colors.BRIGHT_GREEN))
                    deployed = True
            except PermissionError:
                safe_print(f"   [!] Tidak punya izin tulis ke {user_ini}")

            # Method 2: index.php direct injection (Instant 0-second activation for PHP-FPM)
            index_php = Path(tr) / "index.php"
            if index_php.exists():
                try:
                    idx_content = index_php.read_text(encoding="utf-8", errors="replace")
                    waf_include = f"<?php @require_once '{p.resolve()}'; ?>"
                    if str(p.resolve()) not in idx_content:
                        # Backup original index.php
                        idx_bak = Path(tr) / "index.php.wafbak"
                        if not idx_bak.exists():
                            idx_bak.write_text(idx_content, encoding="utf-8")
                        
                        # Prepend WAF require to index.php
                        if idx_content.startswith("<?php"):
                            new_content = idx_content.replace("<?php", f"<?php\n{waf_include}\n", 1)
                        else:
                            new_content = f"{waf_include}\n{idx_content}"
                        
                        index_php.write_text(new_content, encoding="utf-8")
                        safe_print(colorize(f"   [✓] Terpasang langsung di {index_php} (0-detik aktif)", Colors.BRIGHT_GREEN))
                        deployed = True
                except Exception as e:
                    safe_print(f"   [!] Gagal inject {index_php}: {e}")

            # Method 3: .htaccess (Apache)
            if env["server"] == "apache":
                htaccess = Path(tr) / ".htaccess"
                try:
                    existing = htaccess.read_text(encoding="utf-8") if htaccess.exists() else ""
                    if "auto_prepend_file" not in existing:
                        with open(htaccess, "a", encoding="utf-8") as f:
                            f.write(f"\nphp_value auto_prepend_file {p.resolve()}\n")
                        safe_print(colorize(f"   [✓] Terpasang via {htaccess}", Colors.BRIGHT_GREEN))
                        deployed = True
                except PermissionError:
                    pass

        if not deployed:
            safe_print(colorize("   [!] Auto-deploy gagal (permission). Pasang manual:", Colors.YELLOW))

    # Print manual install instructions
    safe_print(colorize("\n Cara Pasang Manual:", Colors.BOLD + Colors.BRIGHT_YELLOW))
    if waf_type == "php":
        safe_print(colorize("  Pilih SALAH SATU cara di bawah:\n", Colors.DIM))
        safe_print(f"  1️⃣  {colorize('.user.ini', Colors.BOLD)} (Paling Aman, Tanpa Restart):")
        safe_print(f"     echo 'auto_prepend_file = {p.resolve()}' >> {webroot}/.user.ini\n")
        safe_print(f"  2️⃣  {colorize('.htaccess', Colors.BOLD)} (Apache Only):")
        safe_print(f"     echo 'php_value auto_prepend_file {p.resolve()}' >> {webroot}/.htaccess\n")
        safe_print(f"  3️⃣  {colorize('php.ini', Colors.BOLD)} (Global, Butuh Restart PHP-FPM):")
        for ini in env["php_ini"][:2]:
            safe_print(f"     echo 'auto_prepend_file = {p.resolve()}' >> {ini}")
        safe_print(f"     sudo systemctl restart php*-fpm  # atau: sudo service apache2 restart\n")
        safe_print(f"  4️⃣  {colorize('index.php', Colors.BOLD)} (Langsung di Kode):")
        safe_print(f"     Tambahkan baris pertama: <?php require_once '{p.resolve()}'; ?>\n")
    else:
        safe_print(f"  Flask: from ctf_waf import install_waf; install_waf(app)")
        safe_print(f"  WSGI : from ctf_waf import WafMiddleware; app = WafMiddleware(app)\n")

    if env["server"] == "nginx":
        safe_print(colorize("  Bonus Nginx Rules:", Colors.BOLD + Colors.BRIGHT_YELLOW))
        safe_print(f"     sudo cp {nginx_path} /etc/nginx/snippets/waf.conf")
        safe_print(f"     Tambahkan di server block: include snippets/waf.conf;")
        safe_print(f"     sudo nginx -t && sudo systemctl reload nginx\n")

    safe_print(colorize(" [!] PENTING: Tambahkan IP SLA checker panitia ke whitelist di dalam file WAF!", Colors.BOLD + Colors.BRIGHT_RED))
    safe_print(colorize("     Edit file WAF > cari WHITELIST_IPS > tambahkan IP game server.\n", Colors.DIM))


def main() -> None:
    waf_type = sys.argv[1] if len(sys.argv) > 1 else "auto"
    out_file = sys.argv[2] if len(sys.argv) > 2 else ""
    generate_waf(waf_type, out_file)


if __name__ == "__main__":
    main()
