#!/usr/bin/env python3
"""Attack detection signatures, regex patterns, and severity classification for CTF Attack-Defense."""

import re
from typing import NamedTuple, Pattern, List, Dict


class AttackSignature(NamedTuple):
    id: str
    name: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    pattern: Pattern
    description: str


# Pre-compiled high-efficiency regex patterns for real-time traffic analysis
SIGNATURES: List[AttackSignature] = [
    # -------------------------------------------------------------
    # 1. COMMAND INJECTION & RCE (CRITICAL)
    # -------------------------------------------------------------
    AttackSignature(
        id="RCE_SHELL_PIPE",
        name="Command Injection via Shell Separators",
        category="RCE",
        severity="CRITICAL",
        pattern=re.compile(
            r"(?:;|\|\||\||&&|`|\$\()(?:\s)*(?:cat|ls|id|whoami|uname|nc|ncat|netcat|bash|sh|zsh|dash|python|python3|perl|ruby|php|curl|wget|socat|find|busybox|grep|head|tail|less|more|cp|mv|chmod|chown|kill|pkill|env|export|ps|tar|zip)\b",
            re.IGNORECASE,
        ),
        description="Shell command execution chained via ;, |, &&, or backticks.",
    ),
    AttackSignature(
        id="RCE_FLAG_READ",
        name="Direct Flag Access Probe",
        category="RCE",
        severity="CRITICAL",
        pattern=re.compile(
            r"(?:cat|head|tail|more|less|grep|strings|od|nl|dd|xxd)\s+[^\s;&|]*flag[^\s;&|]*",
            re.IGNORECASE,
        ),
        description="Attempt to directly read flag files (/flag, flag.txt, etc.).",
    ),
    AttackSignature(
        id="RCE_REVERSE_SHELL",
        name="Reverse Shell / Network Pivot Probe",
        category="RCE",
        severity="CRITICAL",
        pattern=re.compile(
            r"(?:/dev/tcp/|/dev/udp/|bash\s+-i|sh\s+-i|nc\s+(?:-[a-z]*e\s+|\d+\.\d+\.\d+\.\d+)|ncat\s+|socat\s+exec|mkfifo\s+/tmp/|python.*pty\.spawn|perl.*socket|curl\s+https?://\S+\|\s*(?:sh|bash)|wget\s+https?://\S+-O-\s*\|\s*(?:sh|bash))",
            re.IGNORECASE,
        ),
        description="Interactive or background reverse shell payload invocation.",
    ),
    AttackSignature(
        id="RCE_PHP_EVAL",
        name="PHP Code Execution Injection",
        category="RCE",
        severity="CRITICAL",
        pattern=re.compile(
            r"(?:\b(?:eval|assert|passthru|shell_exec|system|popen|proc_open|pcntl_exec|create_function|include_once|require_once)\s*\(|preg_replace\s*\(.*?/[a-z]*e[a-z]*\))",
            re.IGNORECASE,
        ),
        description="Dangerous PHP execution functions in query parameter or request body.",
    ),

    # -------------------------------------------------------------
    # 2. LOCAL FILE INCLUSION & PATH TRAVERSAL (HIGH)
    # -------------------------------------------------------------
    AttackSignature(
        id="LFI_PATH_TRAVERSAL",
        name="Directory Path Traversal",
        category="LFI",
        severity="HIGH",
        pattern=re.compile(
            r"(?:\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e%2f|%2e%2e/|\.\.%252f|%252e%252e%252f){2,}",
            re.IGNORECASE,
        ),
        description="Directory traversal sequences (../../) escaping webroot.",
    ),
    AttackSignature(
        id="LFI_SYSTEM_FILES",
        name="Sensitive Linux File Probe",
        category="LFI",
        severity="HIGH",
        pattern=re.compile(
            r"(?:/etc/(?:passwd|shadow|group|hosts|issue|os-release|crontab|nginx|apache2)|/proc/(?:self|version|cpuinfo|cmdline|environ|net/tcp|mounts)|/var/log/(?:apache2|nginx|auth\.log|syslog)|/root/\.bash_history|/home/\w+/\.bash_history|/root/\.ssh/id_rsa|id_rsa|id_ed25519|authorized_keys)",
            re.IGNORECASE,
        ),
        description="Targeting known sensitive system files or SSH keys.",
    ),
    AttackSignature(
        id="LFI_PHP_WRAPPERS",
        name="PHP Wrapper Exploit",
        category="LFI",
        severity="HIGH",
        pattern=re.compile(
            r"(?:php://filter|php://input|php://fd|php://memory|data://text/plain|expect://|zip://|phar://|glob://)",
            re.IGNORECASE,
        ),
        description="Abuse of PHP stream wrappers (php://filter/convert.base64-encode, etc.).",
    ),

    # -------------------------------------------------------------
    # 3. SQL INJECTION (HIGH)
    # -------------------------------------------------------------
    AttackSignature(
        id="SQLI_UNION_SELECT",
        name="SQLi UNION SELECT Injection",
        category="SQLI",
        severity="HIGH",
        pattern=re.compile(
            r"(?:\bunion\b\s+(?:all\s+)?\bselect\b|\bselect\b\s+.*?concat|\bselect\b\s+.*?group_concat|\bselect\b\s+.*?schema_name|\bselect\b\s+.*?table_name)",
            re.IGNORECASE,
        ),
        description="UNION SELECT injection seeking table schema or extracted data.",
    ),
    AttackSignature(
        id="SQLI_BOOLEAN_AUTH_BYPASS",
        name="SQLi Boolean Authentication Bypass",
        category="SQLI",
        severity="HIGH",
        pattern=re.compile(
            r"(?:'\s*or\s*'?1'?\s*=\s*'?1|admin'\s*--|'\s*or\s*''\s*=\s*'|1'\s*or\s*'1'='1'|\"\s*or\s*\"?1\"?\s*=\s*\"?1|admin\"\s*--|\bunion\b\s+\bselect\b|'\s*or\s*true\b|\"\s*or\s*true\b)",
            re.IGNORECASE,
        ),
        description="Classic tautology auth bypass patterns (' OR '1'='1).",
    ),
    AttackSignature(
        id="SQLI_BLIND_TIME_SLEEP",
        name="SQLi Time-Based / Blind Injection",
        category="SQLI",
        severity="HIGH",
        pattern=re.compile(
            r"(?:\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(\s*\d+|\bpg_sleep\s*\(\s*\d+|\bwaitfor\s+delay\s+'\d+|\bdbms_pipe\.receive_message|\bctxsys\.drithsx\.sn\b)",
            re.IGNORECASE,
        ),
        description="Time-based blind SQLi functions (sleep, benchmark, pg_sleep).",
    ),
    AttackSignature(
        id="SQLI_ERROR_BASED",
        name="SQLi Error-Based Extraction",
        category="SQLI",
        severity="HIGH",
        pattern=re.compile(
            r"(?:\bextractvalue\s*\(|\bupdatexml\s*\(|\bexp\s*\(~\s*\(select|\bpolygon\s*\(|\bgeometrycollection\s*\(|\bload_file\s*\(|\binto\s+outfile\b|\binto\s+dumpfile\b)",
            re.IGNORECASE,
        ),
        description="Error-based SQL injection or filesystem read/write (load_file, into outfile).",
    ),

    # -------------------------------------------------------------
    # 4. WEBSHELL & BACKDOOR PROBES (HIGH)
    # -------------------------------------------------------------
    AttackSignature(
        id="WEBSHELL_PROBE",
        name="Known Webshell / Backdoor URI Probe",
        category="BACKDOOR",
        severity="HIGH",
        pattern=re.compile(
            r"(?:/(?:c99|r57|wso|b374k|alfa|shell|cmd|backdoor|webshell|mini|up|upload|eval-stdin|pma|phpmyadmin|adminer)\.php|cmd=(?:cat|ls|id|whoami|dir|ipconfig|pwd|curl)|act=(?:cmd|upload|eval)|pass=(?:admin|root|123456))",
            re.IGNORECASE,
        ),
        description="Access to well-known webshell scripts or backdoor parameter names.",
    ),

    # -------------------------------------------------------------
    # 5. SERVER-SIDE TEMPLATE INJECTION & DESERIALIZATION (MEDIUM)
    # -------------------------------------------------------------
    AttackSignature(
        id="SSTI_PROBE",
        name="Template Injection Probe (SSTI)",
        category="SSTI",
        severity="MEDIUM",
        pattern=re.compile(
            r"(?:\{\{.*?\}\}|\$\{.*?\}|<%=.*?%>|\{%-?.*?-?%\}|\$\{T\(java\.lang\.Runtime\)|\{\{config\.items\(\)\}|\{\{lipsum\.__globals__|\{\{cycler\.__init__)",
            re.IGNORECASE,
        ),
        description="Template syntax probing expressions (Jinja2, Twig, Spring EL, FreeMarker).",
    ),
    AttackSignature(
        id="DESERIALIZATION_PROBE",
        name="PHP / Python Insecure Deserialization",
        category="DESERIALIZATION",
        severity="HIGH",
        pattern=re.compile(
            r"(?:O:\d+:\"[A-Za-z0-9_]+\":\d+:\{|a:\d+:\{|gASV|cos\nsystem|\(dp0\n|\bpickle\.loads\b)",
            re.IGNORECASE,
        ),
        description="Serialized PHP object (O:...) or Python pickle stream in HTTP parameters.",
    ),

    # -------------------------------------------------------------
    # 6. CROSS-SITE SCRIPTING (LOW/MEDIUM)
    # -------------------------------------------------------------
    AttackSignature(
        id="XSS_TAG_INJECTION",
        name="Cross-Site Scripting (XSS) Tag Injection",
        category="XSS",
        severity="LOW",
        pattern=re.compile(
            r"(?:<script\b[^>]*>|javascript:[^\s\"'>]+|<img\b[^>]*onerror\s*=|onload\s*=|alert\s*\(|prompt\s*\(|confirm\s*\(|document\.cookie|window\.location)",
            re.IGNORECASE,
        ),
        description="Client-side script execution or cookie exfiltration tags.",
    ),

    # -------------------------------------------------------------
    # 7. SERVER-SIDE REQUEST FORGERY & CLOUD METADATA (HIGH)
    # -------------------------------------------------------------
    AttackSignature(
        id="SSRF_PROBE",
        name="Server-Side Request Forgery (SSRF) Probe",
        category="SSRF",
        severity="HIGH",
        pattern=re.compile(
            r"(?:https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|\[::1\])|gopher://|dict://|file:///[a-z0-9_/]+)",
            re.IGNORECASE,
        ),
        description="SSRF targeting internal network interfaces, loopback, or cloud metadata endpoints.",
    ),

    # -------------------------------------------------------------
    # 8. XML EXTERNAL ENTITY INJECTION (HIGH)
    # -------------------------------------------------------------
    AttackSignature(
        id="XXE_PROBE",
        name="XML External Entity (XXE) Injection",
        category="XXE",
        severity="HIGH",
        pattern=re.compile(
            r"(?:<!ENTITY\s+\w+\s+SYSTEM\s+['\"](?:file|http|php|expect)://|<!DOCTYPE\s+\w+\s+\[|%[a-zA-Z0-9_]+;\s*\]>)",
            re.IGNORECASE,
        ),
        description="XXE injection targeting local files (/etc/passwd, /flag) via XML entities.",
    ),

    # -------------------------------------------------------------
    # 9. NOSQL INJECTION & MONGODB (HIGH)
    # -------------------------------------------------------------
    AttackSignature(
        id="NOSQLI_PROBE",
        name="NoSQL Injection (MongoDB/CouchDB)",
        category="NOSQLI",
        severity="HIGH",
        pattern=re.compile(
            r"(?:\[\$(?:ne|gt|gte|lt|lte|regex|in|nin|where|exists)\]|[\"']\$(?:ne|gt|gte|lt|lte|regex|in|nin|where|exists)[\"']\s*:)",
            re.IGNORECASE,
        ),
        description="NoSQL operator injection bypassing authentication or dumping collections.",
    ),

    # -------------------------------------------------------------
    # 10. TYPE JUGGLING & ARRAY PARAMETER INJECTION (MEDIUM)
    # -------------------------------------------------------------
    AttackSignature(
        id="TYPE_JUGGLING_PROBE",
        name="PHP Type Juggling / Array Parameter Injection",
        category="AUTH",
        severity="MEDIUM",
        pattern=re.compile(
            r"(?:(?:password|token|hash|secret|pin|otp)\[\]=|0e\d{10,}|strcmp\s*\(.*?\[\])",
            re.IGNORECASE,
        ),
        description="Array parameter injection exploiting PHP loose comparison (==) or strcmp bypass.",
    ),
]

# Static assets extensions that are generally benign unless accompanied by explicit malicious payload
BENIGN_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webm", ".webp"
}


def is_benign_static(uri: str) -> bool:
    """Return True if URI is purely a request for a static asset without query parameters."""
    clean_uri = uri.split("?")[0].lower()
    for ext in BENIGN_EXTENSIONS:
        if clean_uri.endswith(ext):
            return True
    return False


# Web Log Format Matchers
COMBINED_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Za-z]+)\s+(?P<uri>[^\s"]+)(?:\s+HTTP/\d\.\d)?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
COMMON_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Za-z]+)\s+(?P<uri>[^\s"]+)(?:\s+HTTP/\d\.\d)?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
)
# Universal CTF Flag Format Matcher (Matches FLAG{...}, JCSC{...}, CTF{...}, etc.)
# Known CTF flag prefixes saja - wildcard [A-Za-z0-9_]{3,10} dihapus (sumber FP besar:
# men-match teks seperti test{...} / data{...} di JSON & HTML biasa)
KNOWN_FLAG_PREFIXES = r"(?:FLAG|flag|CTF|ctf|JCSC|jcsc|HTB|picoCTF|SKR|COMPFEST|JOINTS|CF|UTCTF|ictf|CYBER|cyber)"
FLAG_REGEX = re.compile(KNOWN_FLAG_PREFIXES + r"\{[A-Za-z0-9_\-\.\=\+\$!@#%]{8,96}\}")


def compile_flag_regex(custom_pattern: str = None) -> re.Pattern:
    """Compile custom flag regex or return universal default CTF flag regex."""
    if custom_pattern:
        try:
            return re.compile(custom_pattern, re.IGNORECASE)
        except re.error:
            pass
    return FLAG_REGEX


# Tuple format of rules for fast iteration
ATTACK_RULES = [
    (sig.category, sig.severity, sig.pattern, sig.description) for sig in SIGNATURES
]
