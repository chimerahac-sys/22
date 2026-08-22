#!/usr/bin/env python3
"""Source code static vulnerability scanner, patch state tracking, and guided patcher."""

import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List, Optional, Tuple

from .colors import Colors, colorize, print_banner, safe_print
from .backup import file_sha256

DB_DEFAULT = os.path.expanduser("~/.adctf/state.db")
ROOT_DEFAULT = "/var/www/html"
SKIP_DIRS = {"vendor", "node_modules", ".git", ".svn", "cache", "dist", "build", "framework", "tests", "fixtures", "storage", "third_party"}
SRC_EXTS = {".php", ".phtml", ".inc", ".py", ".js", ".mjs", ".cjs"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db(path: str = DB_DEFAULT) -> sqlite3.Connection:
    """Initialize SQLite database for state management."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS traffic_logs(
        id INTEGER PRIMARY KEY,
        source_ip TEXT,
        method TEXT,
        uri TEXT,
        query_string TEXT,
        category TEXT,
        severity TEXT,
        timestamp TEXT NOT NULL,
        hash_id TEXT UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tokens(
        id INTEGER PRIMARY KEY,
        ip TEXT NOT NULL,
        token_value TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        UNIQUE(ip, token_value)
    );
    CREATE TABLE IF NOT EXISTS patch_state(
        id INTEGER PRIMARY KEY,
        file_path TEXT NOT NULL,
        line_num INTEGER NOT NULL,
        vuln_type TEXT NOT NULL,
        status_patched INTEGER NOT NULL DEFAULT 0,
        file_hash TEXT,
        last_scan_hash TEXT,
        confidence TEXT,
        verified_at TEXT,
        UNIQUE(file_path, line_num, vuln_type)
    );
    CREATE TABLE IF NOT EXISTS health_checks(
        id INTEGER PRIMARY KEY,
        timestamp TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        status INTEGER NOT NULL,
        healthy INTEGER NOT NULL,
        latency_ms REAL,
        body_hash TEXT
    );
    """)
    return conn


# Language-specific vulnerability regex patterns
CODE_RULES = {
    ".php": [
        ("SQLi", re.compile(r"(?i)(mysql_query|mysqli_query|->query|->prepare)\s*\(.*(\$_GET|\$_POST|\$_REQUEST|\$_(GET|POST|REQUEST)\[)"), "Gunakan PDO Prepared Statement dengan parameter binding."),
        ("RCE", re.compile(r"(?i)(system|exec|shell_exec|passthru|popen|proc_open|eval|assert)\s*\(.*(\$_GET|\$_POST|\$_REQUEST|\$_(GET|POST|REQUEST)\[)"), "Hindari shell function; gunakan escapeshellarg() atau whitelist argumen."),
        ("LFI", re.compile(r"(?i)(include|include_once|require|require_once|readfile|file_get_contents)\s*\(.*(\$_GET|\$_POST|\$_REQUEST|\.\.)"), "Gunakan whitelist array nama file & basename($_GET['page'])."),
        ("XSS", re.compile(r"(?i)(echo|print)\s+.*(\$_GET|\$_POST|\$_REQUEST)"), "Gunakan htmlspecialchars($input, ENT_QUOTES, 'UTF-8')."),
    ],
    ".py": [
        ("SQLi", re.compile(r"(?i)(cursor\.execute|session\.execute|raw)\s*\(.*(request\.|input\(|args\[|form\[|f[\\\"'])"), "Gunakan parameterized query cursor.execute(query, (params,))."),
        ("RCE", re.compile(r"(?i)(subprocess\.(run|Popen|call)|os\.system|os\.popen)\s*\(.*(request\.|input\(|args\[|form\[).*(shell\s*=\s*True|\+|%|\.format|f[\\\"'])"), "Gunakan argument list subprocess.run(['cmd', arg]) dengan shell=False."),
        ("LFI", re.compile(r"(?i)(open|send_file|send_from_directory)\s*\(.*(request\.|input\(|args\[|form\[|\.\.)"), "Gunakan werkzeug secure_filename() dan verifikasi path.resolve()."),
        ("SSTI", re.compile(r"(?i)render_template_string\s*\(.*(request\.|input\(|args\[|form\[)"), "Gunakan render_template statis dengan context variable terpisah."),
    ],
    ".js": [
        ("SQLi", re.compile(r"(?i)(query|execute|raw)\s*\(.*(req\.(query|body|params))"), "Gunakan parameterized query dari database driver."),
        ("RCE", re.compile(r"(?i)(child_process|exec|execSync|spawn)\s*\(.*(req\.|request\.).*(\+|`|shell\s*:\s*true)"), "Gunakan spawn dengan array argument tanpa shell."),
        ("LFI", re.compile(r"(?i)(readFile|sendFile|require)\s*\(.*(req\.|request\.).*(\+|`|\.\.)"), "Gunakan whitelist nama file dan path.resolve containment check."),
    ],
}
CODE_RULES[".phtml"] = CODE_RULES[".php"]
CODE_RULES[".inc"] = CODE_RULES[".php"]
CODE_RULES[".mjs"] = CODE_RULES[".js"]
CODE_RULES[".cjs"] = CODE_RULES[".js"]


def get_source_files(root: str) -> Generator[str, None, None]:
    """Iterate over all source code files skipping vendor/libraries."""
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if os.path.splitext(f)[1].lower() in SRC_EXTS:
                yield os.path.join(base, f)


def run_scan(web_root: str = ROOT_DEFAULT, db_path: str = DB_DEFAULT) -> int:
    """Scan source code for high-risk vulnerabilities and record to database."""
    root = os.path.abspath(web_root)
    if not os.path.isdir(root):
        safe_print(colorize(f"[ERROR] Web root tidak ditemukan: {root}", Colors.BRIGHT_RED))
        return 1

    conn = get_db(db_path)
    total = 0
    print_banner("Source Code Vulnerability Scanner", f"Target: {root}")

    for path in get_source_files(root):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError:
            continue

        digest = file_sha256(path)
        ext = os.path.splitext(path)[1].lower()
        rules = CODE_RULES.get(ext, [])

        for n, line in enumerate(lines, 1):
            s = line.strip()
            if not s or s.startswith(("#", "//", "/*", "*")):
                continue

            for typ, rx, advice in rules:
                if rx.search(line):
                    if typ == "RCE" and ("shell=False" in line or "subprocess.run([" in line):
                        continue

                    confidence = "HIGH" if typ in ("SQLi", "RCE") else "MEDIUM"
                    conn.execute("""
                    INSERT OR REPLACE INTO patch_state(file_path, line_num, vuln_type, file_hash, last_scan_hash, confidence)
                    VALUES(?, ?, ?, ?, ?, ?)
                    """, (path, n, typ, digest, digest, confidence))

                    lo = max(0, n - 2)
                    hi = min(len(lines), n + 2)
                    safe_print(f"\n[{colorize(confidence, Colors.BRIGHT_RED)}][{colorize(typ, Colors.BRIGHT_YELLOW)}] {colorize(path, Colors.CYAN)}:{n}")
                    for idx, ctx in enumerate(lines[lo:hi], lo + 1):
                        marker = ">>" if idx == n else "  "
                        color = Colors.BRIGHT_RED if idx == n else Colors.DIM
                        safe_print(f"  {marker} {idx:4d} | {colorize(ctx[:200], color)}")
                    safe_print(f"  └─ Fix: {colorize(advice, Colors.GREEN)}")
                    total += 1
                    break

    conn.commit()
    conn.close()
    safe_print(colorize("\n" + "=" * 75, Colors.DIM))
    safe_print(colorize(f"[*] Scan selesai. Total {total} potensi celah dicatat di database.", Colors.BOLD + Colors.BRIGHT_WHITE))
    safe_print(colorize("[*] Jalankan 'python adctf.py next' untuk melihat prioritas perbaikan.", Colors.CYAN))
    return 0


def run_next_patch(db_path: str = DB_DEFAULT) -> int:
    """Show the next highest priority vulnerability to patch with code context."""
    conn = get_db(db_path)
    r = conn.execute("SELECT * FROM patch_state WHERE status_patched=0 ORDER BY CASE confidence WHEN 'HIGH' THEN 0 ELSE 1 END, id LIMIT 1").fetchone()
    if not r:
        safe_print(colorize("[✓] Semua temuan celah sudah dipatch atau database bersih!", Colors.BOLD + Colors.BRIGHT_GREEN))
        return 0

    print_banner("Guided Patch Step-By-Step", f"Target: {r['file_path']}:{r['line_num']}")
    safe_print(f"[*] File   : {colorize(r['file_path'], Colors.BOLD + Colors.CYAN)}")
    safe_print(f"[*] Line   : {r['line_num']}")
    safe_print(f"[*] Type   : {colorize(r['vuln_type'], Colors.BRIGHT_RED)}")
    safe_print(f"[*] Status : {colorize('UNPATCHED', Colors.YELLOW)}")
    safe_print(colorize("-" * 75, Colors.DIM))

    try:
        with open(r["file_path"], "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        lo = max(0, r["line_num"] - 3)
        hi = min(len(lines), r["line_num"] + 3)
        for idx, l in enumerate(lines[lo:hi], lo + 1):
            marker = ">>" if idx == r["line_num"] else "  "
            color = Colors.BRIGHT_RED if idx == r["line_num"] else Colors.WHITE
            safe_print(f"  {marker} {idx:4d} | {colorize(l[:200], color)}")
    except Exception:
        pass

    safe_print(colorize("-" * 75, Colors.DIM))
    safe_print("Langkah:")
    safe_print(f" 1. Buka file: nano +{r['line_num']} {r['file_path']}")
    safe_print(" 2. Lakukan patch aman (gunakan prepared statement / basename / argument list)")
    safe_print(" 3. Uji web lalu jalankan: python adctf.py done")
    return 0


def run_done_patch(db_path: str = DB_DEFAULT) -> int:
    """Verify that file was modified and mark current vulnerability as completed."""
    conn = get_db(db_path)
    r = conn.execute("SELECT * FROM patch_state WHERE status_patched=0 ORDER BY id LIMIT 1").fetchone()
    if not r:
        safe_print("[INFO] Tidak ada temuan aktif.")
        return 0

    try:
        current_hash = file_sha256(r["file_path"])
    except Exception:
        safe_print(colorize("[ERROR] File tidak ditemukan.", Colors.BRIGHT_RED))
        return 1

    if current_hash == r["file_hash"]:
        safe_print(colorize("[ERROR] Done ditolak: File belum diubah. Edit kode dulu!", Colors.BRIGHT_RED))
        return 1

    conn.execute("UPDATE patch_state SET status_patched=1, verified_at=? WHERE id=?", (now_iso(), r["id"]))
    conn.commit()
    conn.close()
    safe_print(colorize(f"[✓] Berhasil! Bug {r['vuln_type']} pada {r['file_path']}:{r['line_num']} ditandai SELESAI.", Colors.BOLD + Colors.BRIGHT_GREEN))
    safe_print("Jalankan 'python adctf.py next' untuk temuan berikutnya.")
    return 0


def run_list_patches(db_path: str = DB_DEFAULT) -> int:
    """List all vulnerability patch items and completion status."""
    conn = get_db(db_path)
    rows = conn.execute("SELECT * FROM patch_state ORDER BY id").fetchall()
    print_banner("Vulnerability Patch Checklist", f"{len(rows)} Total Items")
    for r in rows:
        badge = colorize("[✓ PATCHED]", Colors.GREEN) if r["status_patched"] else colorize("[X OPEN   ]", Colors.BRIGHT_RED)
        safe_print(f" {badge} {colorize(r['vuln_type'], Colors.YELLOW):<12} | {r['file_path']}:{r['line_num']}")
    conn.close()
    return 0


def print_patch_guides():
    """Print quick code patching snippets for common web bugs."""
    print_banner("Emergency Code Patching Cheatsheet", "PHP & Python Vulnerability Fixes")
    safe_print(colorize("\n[1] SQL INJECTION (SQLi) PATCH:", Colors.BOLD + Colors.BRIGHT_YELLOW))
    safe_print("  PHP:    $stmt = $pdo->prepare('SELECT * FROM u WHERE id = :id'); $stmt->execute([':id' => (int)$_GET['id']]);")
    safe_print("  Python: cursor.execute('SELECT * FROM u WHERE username = %s', (user,))")

    safe_print(colorize("\n[2] LOCAL FILE INCLUSION (LFI) PATCH:", Colors.BOLD + Colors.BRIGHT_YELLOW))
    safe_print("  PHP:    $allowed = ['home', 'login']; $page = basename($_GET['page'] ?? 'home'); if (!in_array($page, $allowed, true)) die('403');")
    safe_print("  Python: req = (Path('/app/uploads') / secure_filename(fname)).resolve(); if not str(req).startswith('/app/uploads'): abort(403)")

    safe_print(colorize("\n[3] REMOTE CODE EXECUTION (RCE) PATCH:", Colors.BOLD + Colors.BRIGHT_YELLOW))
    safe_print("  PHP:    if (!filter_var($ip, FILTER_VALIDATE_IP)) die('Invalid'); exec('ping -c 1 ' . escapeshellarg($ip), $out);")
    safe_print("  Python: subprocess.run(['ping', '-c', '1', host], check=True, shell=False)")
    safe_print("")
    return 0
