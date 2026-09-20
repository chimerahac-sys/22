#!/usr/bin/env python3
"""Deep Webshell & Backdoor Finder for CTF Attack-Defense.

Scans webroot and system directories for:
  - Obfuscated PHP execution (eval, assert, base64_decode, gzinflate, str_rot13, $$variable)
  - Known webshell signatures (c99, r57, wso, b374k, alfa, alibaba, pass, cmd)
  - Hidden or double-extension files (.backdoor.php, shell.php.jpg, .ico containing <?php)
  - Files modified within recent time windows (e.g. last 10, 30, 60 minutes)
  - Quarantine / safe backup action
"""

import os
import re
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .colors import Colors, colorize, print_banner, safe_print

ROOT_DEFAULT = "/var/www/html"

WEBSHELL_PATTERNS = [
    ("HIGH",   re.compile(r"(?i)(eval|assert|passthru|shell_exec|system|popen|proc_open)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\("), "Obfuscated code execution wrapper"),
    ("CRITICAL", re.compile(r"(?i)(eval|assert|system|exec|shell_exec|passthru)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)\["), "Direct parameter execution / one-liner backdoor"),
    ("HIGH",   re.compile(r"(?i)\$\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\("), "Variable function backdoor ($$x())"),
    ("HIGH",   re.compile(r"(?i)(preg_replace|mb_ereg_replace)\s*\(\s*['\"][^'\"]*\/e['\"]"), "Preg_replace /e code execution modifier"),
    ("MEDIUM", re.compile(r"(?i)(c99shell|r57shell|WSOset|b374k|Alfa\s+Team|FilesMan|Sec-WSO|bypass_waf)"), "Known public webshell title/signature"),
    ("MEDIUM", re.compile(r"(?i)(create_function|call_user_func|call_user_func_array)\s*\(\s*['\"\$].*?\b(eval|assert|system|exec)\b"), "Dynamic callback code execution"),
    ("MEDIUM", re.compile(r"<\?php\s+.*?(?:system|exec|shell_exec|eval|passthru)\s*\(", re.DOTALL), "PHP tag with system execution inside non-standard file"),
]


CORE_FILE_NAMES = {
    "index.php", "config.php", "wp-config.php", "app.py", "main.py", "wsgi.py",
    "settings.py", "urls.py", "db.php", "database.php", "connect.php",
    "manage.py", "server.js", "app.js",
}


def _shannon_entropy(data: str) -> float:
    """Entropi Shannon (bit/karakter) untuk deteksi blob obfuscated."""
    if not data:
        return 0.0
    import math
    from collections import Counter
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _has_obfuscated_blob(content: str, min_len: int = 120) -> bool:
    """Deteksi blob base64/hex panjang berentropi tinggi (indikasi kode obfuscated)."""
    for blob in re.findall(r"[A-Za-z0-9+/=]{%d,}" % min_len, content):
        if _shannon_entropy(blob) >= 4.2:
            return True
    for blob in re.findall(r"[0-9a-fA-F]{%d,}" % (min_len + 40), content):
        if _shannon_entropy(blob) >= 3.9:
            return True
    return False


def find_webshells(
    target_dir: str = ROOT_DEFAULT,
    max_modified_mins: Optional[int] = None,
    quarantine_dir: Optional[str] = None,
) -> List[Dict]:
    """Scan directory recursively for webshells and backdoors."""
    findings = []
    now = time.time()

    SKIP_DIRS = {".git", ".svn", "ctf_defense", "docs", "tests", "vendor", "node_modules", ".adctf", "__pycache__"}
    SKIP_FILES = {"ctf_waf.py", "ctf_waf.php", "adctf.py"}
    VALID_EXTS = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".inc", ".py", ".pl", ".cgi", ".sh", ".jsp", ".asp", ".aspx", ".jpg", ".png", ".gif", ".ico", ".txt", ".bak"}

    for base, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in files:
            if fname in SKIP_FILES:
                continue

            path = os.path.join(base, fname)
            ext = os.path.splitext(fname)[1].lower()

            # Ignore markdown and documentation
            if ext in {".md", ".json", ".lock", ".yml", ".yaml"}:
                continue
            if ext not in VALID_EXTS and not fname.startswith("."):
                continue

            # 1. Hidden file or suspicious double extension (.shell.php, .image.php, ...php)
            is_hidden = fname.startswith(".") and ext == ".php"
            is_suspicious_name = bool(re.search(r"(?i)(\.php\.\w+|\.phtml|\.php3|\.php4|\.php5|\.php7|\.inc|\.suspected)$", fname))

            # 2. Time filter
            try:
                mtime = os.path.getmtime(path)
                mins_ago = (now - mtime) / 60.0
                if max_modified_mins and mins_ago > max_modified_mins:
                    continue
            except Exception:
                mins_ago = 999.0

            # 3. Content inspection
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read(262144)  # read max 256KB
            except Exception:
                continue

            matches = []
            score = 0
            for sev, rx, desc in WEBSHELL_PATTERNS:
                m = rx.search(content)
                if m:
                    matches.append((sev, desc, m.group(0)[:60]))
                    score += {"CRITICAL": 4, "HIGH": 2, "MEDIUM": 1}.get(sev, 1)

            has_critical = any(x[0] == "CRITICAL" for x in matches)

            # Anti-FP multi-signal scoring:
            #   sinyal lemah (hidden / nama aneh / baru diubah / blob obfuscated)
            #   TIDAK PERNAH cukup sendirian untuk mengonfirmasi.
            n_signals = len(matches)
            if is_hidden:
                score += 1
                n_signals += 1
            if is_suspicious_name:
                score += 1
                n_signals += 1
            if mins_ago < 10:
                score += 1
                n_signals += 1
            if _has_obfuscated_blob(content):
                score += 1
                n_signals += 1

            # File inti framework tidak di-flag tanpa bukti CRITICAL (proteksi SLA)
            if fname.lower() in CORE_FILE_NAMES and not has_critical:
                score = 0

            # Konfirmasi: bukti CRITICAL langsung, atau skor >= 3 DENGAN >= 2 sinyal independen
            if has_critical or (score >= 3 and n_signals >= 2):
                sev = "CRITICAL" if has_critical else ("HIGH" if score >= 5 else "MEDIUM")
                findings.append({
                    "path": path,
                    "filename": fname,
                    "severity": sev,
                    "score": score,
                    "is_hidden": is_hidden,
                    "mins_ago": mins_ago,
                    "matches": matches,
                    "snippet": matches[0][2] if matches else (fname if is_hidden else "Suspicious extension"),
                })

    # Protected core files that should NEVER be quarantined automatically (to protect SLA)
    PROTECTED_CORE_FILES = {
        "index.php", "config.php", "wp-config.php", "app.py", "main.py", "wsgi.py",
        "settings.py", "urls.py", "db.php", "database.php", "connect.php",
        "ctf_waf.php", "ctf_waf.py", "manage.py", "server.js", "app.js"
    }

    # Optional quarantine
    if quarantine_dir and findings:
        os.makedirs(quarantine_dir, exist_ok=True)
        for item in findings:
            src = item["path"]
            fname = os.path.basename(src).lower()

            # Anti-FP: hanya karantina temuan yang yakin (CRITICAL / skor >= 5)
            if item.get("severity") != "CRITICAL" and (item.get("score") or 0) < 5:
                item["quarantined"] = "SKIPPED (Confidence insufficient - manual review)"
                continue

            # Skip core files from automatic quarantine to prevent SLA disaster
            if fname in PROTECTED_CORE_FILES:
                item["quarantined"] = "SKIPPED (Core Framework File - Manual Review Only)"
                continue

            dst = os.path.join(quarantine_dir, os.path.basename(src) + ".quarantine")
            try:
                shutil.move(src, dst)
                item["quarantined"] = dst
            except Exception:
                item["quarantined"] = None

    return findings


def run_webshell_hunter(
    target_dir: str = ROOT_DEFAULT,
    recent_mins: Optional[int] = None,
    quarantine: bool = False,
) -> int:
    """CLI execution for webshell hunter."""
    print_banner("Deep Webshell & Backdoor Hunter", f"Target: {target_dir}")
    if recent_mins:
        safe_print(f"[*] Filter Waktu : File yang diubah dalam {recent_mins} menit terakhir")

    qdir = os.path.expanduser("~/.adctf/quarantine") if quarantine else None
    findings = find_webshells(target_dir, max_modified_mins=recent_mins, quarantine_dir=qdir)

    if not findings:
        safe_print(colorize("\n[✓] BERSIH: Tidak ditemukan webshell atau backdoor terdeteksi!", Colors.BOLD + Colors.BRIGHT_GREEN))
        return 0

    safe_print(colorize(f"\n[!] DITEMUKAN {len(findings)} POTENSI WEBSHELL / BACKDOOR:", Colors.BOLD + Colors.BRIGHT_RED))
    for f in findings:
        badge = colorize(f"[{f['severity']}]", Colors.BG_RED + Colors.BOLD + Colors.WHITE if f['severity'] == "CRITICAL" else Colors.BRIGHT_RED)
        safe_print(f"\n {badge} {colorize(f['path'], Colors.BOLD + Colors.BRIGHT_WHITE)} (Diubah {f['mins_ago']:.1f} mnt lalu | Skor {f.get('score', '?')})")
        for _, desc, snip in f["matches"]:
            safe_print(f"   └─ Indikasi: {colorize(desc, Colors.YELLOW)} -> {colorize(snip, Colors.CYAN)}")
        if f.get("is_hidden"):
            safe_print(f"   └─ File tersembunyi: {f['filename']}")
        if f.get("quarantined"):
            safe_print(f"   └─ {colorize('Di-Karantina ke:', Colors.GREEN)} {f['quarantined']}")

    safe_print(colorize("\n" + "=" * 75, Colors.DIM))
    if not quarantine:
        safe_print(colorize("Untuk memindahkan file berbahaya ke karantina otomatis:", Colors.YELLOW))
        safe_print(f"  {colorize('python adctf.py webshell --quarantine', Colors.BOLD + Colors.BRIGHT_GREEN)}\n")
    return 0
