#!/usr/bin/env python3
"""Source code static vulnerability scanner, patch state tracking, and guided patcher."""

import os
import re
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List, Optional, Set, Tuple

from .colors import Colors, colorize, print_banner, safe_print
from .backup import file_sha256
from .smart_patcher import generate_smart_patch, SmartPatch, test_php_syntax, test_python_syntax


DB_DEFAULT = os.path.expanduser("~/.adctf/state.db")
ROOT_DEFAULT = "/var/www/html"
SKIP_DIRS = {
    "vendor", "node_modules", ".git", ".svn", "cache", "dist", "build",
    "framework", "tests", "fixtures", "storage", "third_party",
    "ctf_defense", "docs", ".adctf", ".venv", "venv", "__pycache__",
}
SRC_EXTS = {".php", ".phtml", ".inc", ".py", ".js", ".mjs", ".cjs"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db(path: str = DB_DEFAULT) -> sqlite3.Connection:
    """Initialize SQLite database for state management with WAL mode for concurrency."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
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
        notes TEXT,
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
        ("SQLi", re.compile(r"(?i)(mysql_query|mysqli_query|->query|->prepare|->exec)\s*\(.*(\$_GET|\$_POST|\$_REQUEST|\$_(GET|POST|REQUEST)\[|['\"].*?\b(SELECT|INSERT|UPDATE|DELETE|UNION)\b.*?\.\s*\$)"), "Gunakan PDO Prepared Statement dengan parameter binding."),
        ("RCE", re.compile(r"(?i)(system|exec|shell_exec|passthru|popen|proc_open|eval|assert|pcntl_exec)\s*\(.*(\$_GET|\$_POST|\$_REQUEST|\$_(GET|POST|REQUEST)\[|\$cmd|\$command|\$input)"), "Hindari shell function; gunakan escapeshellarg() atau whitelist argumen eksplisit."),
        ("RCE_VAR", re.compile(r"(?i)\$_(GET|POST|REQUEST)\[['\"]\w+['\"]\]\s*\("), "Variable function call rentan RCE; gunakan switch-case atau router terstruktur."),
        ("LFI", re.compile(r"(?i)(include|include_once|require|require_once|readfile|file_get_contents|highlight_file|show_source|fopen)\s*\(.*(\$_GET|\$_POST|\$_REQUEST|\.\.)"), "Gunakan whitelist array nama file & basename($_GET['page'])."),
        ("DESER", re.compile(r"(?i)\bunserialize\s*\(.*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|base64_decode)"), "Gunakan json_decode() bukan unserialize() untuk mencegah PHP Object Injection."),
        ("UPLOAD", re.compile(r"(?i)move_uploaded_file\s*\("), "Validasi ekstensi dengan in_array($ext, $allowed, true) dan rename ke random hash."),
        ("TYPE_JUGGLE", re.compile(r"(?i)(strcmp\s*\(.*?\)\s*==\s*0|\$_(GET|POST|REQUEST|COOKIE)\[[^\]]+\]\s*==\s*['\"]0e\d+)"), "Gunakan strict comparison === dan is_string() atau hash_equals()."),
        ("SSRF", re.compile(r"(?i)(curl_init|file_get_contents|fopen)\s*\(.*(\$_GET|\$_POST|\$_REQUEST)"), "Validasi protocol http/https dan blokir private IP (127.0.0.1, 10.0.0.0/8, 169.254.0.0/16)."),
        ("XXE", re.compile(r"(?i)(simplexml_load_string|simplexml_load_file|DOMDocument::loadXML)\s*\("), "Matikan entity loader: libxml_disable_entity_loader(true);"),
        ("XSS", re.compile(r"(?i)(echo|print|printf)\s+.*(\$_GET|\$_POST|\$_REQUEST)"), "Gunakan htmlspecialchars($input, ENT_QUOTES, 'UTF-8')."),
    ],
    ".py": [
        ("SQLi", re.compile(r"""(?i)(?:(?:\b(?:cursor|db|conn|session|engine|g\.db)\.execute\s*\(.*(?:f["']|%|\.format|\+|request\.|args\[|form\[))|(?:query|sql|stmt)\s*=\s*\(?.*f["'].*?\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b)"""), "Gunakan parameterized query (?, (params,))."),
        ("RCE", re.compile(r"""(?i)(?:subprocess\.(?:run|Popen|call)|os\.(?:system|popen))\s*\(.*(?:shell\s*=\s*True|f["']|%|\.format|\+|cmd\b|command\b|host\b|ip\b)"""), "Gunakan argument list tanpa shell=True atau isolasi argumen."),
        ("EVAL", re.compile(r"(?i)\b(eval|exec)\s*\(.*(request\.|input\(|args\[|form\[)"), "Hindari eval/exec pada input pengguna; gunakan parser terstruktur seperti json.loads()."),
        ("LFI", re.compile(r"(?i)(?:open|send_file|send_from_directory)\s*\(.*(?:request\.|args\[|form\[|\bname\b|\btarget\b|\bpath\b|\.\.)"), "Gunakan os.path.basename() atau werkzeug secure_filename()."),
        ("SSTI", re.compile(r"(?i)(render_template_string|Template|jinja2\.Template)\s*\(.*(request\.|input\(|args\[|form\[|f[\\\"'])"), "Gunakan context parameter Jinja2 terpisah."),
        ("PICKLE", re.compile(r"(?i)\b(pickle|cPickle|_pickle)\.loads?\s*\("), "Ganti pickle.loads() dengan json.loads() untuk mencegah Python deserialization RCE."),
        ("YAML", re.compile(r"(?i)\byaml\.load\s*\("), "Gunakan yaml.safe_load() bukan yaml.load()."),
        ("SSRF", re.compile(r"(?i)(requests\.(get|post)|urllib\.request\.urlopen)\s*\(.*(request\.|input\(|args\[|form\[)"), "Validasi skema URL dan filter IP private/loopback sebelum request."),
    ],
    ".js": [
        ("SQLi", re.compile(r"(?i)(query|execute|raw)\s*\(.*(req\.(query|body|params)|\$\{.*?\})"), "Gunakan parameterized query dari database driver (db.query('SELECT ... $1', [val]))."),
        ("RCE", re.compile(r"(?i)(child_process|exec|execSync|spawn)\s*\(.*(req\.|request\.).*(shell\s*:\s*true|\+|`)"), "Gunakan spawn dengan array argument tanpa shell option."),
        ("EVAL", re.compile(r"(?i)\b(eval|new Function)\s*\(.*(req\.|request\.)"), "Hindari eval/new Function; gunakan JSON.parse()."),
        ("LFI", re.compile(r"(?i)(readFile|readFileSync|sendFile|require)\s*\(.*(req\.|request\.).*(\+|`|\.\.)"), "Gunakan path.normalize() dan whitelist nama file yang diizinkan."),
    ],
}
CODE_RULES[".phtml"] = CODE_RULES[".php"]
CODE_RULES[".inc"]   = CODE_RULES[".php"]
CODE_RULES[".mjs"]   = CODE_RULES[".js"]
CODE_RULES[".cjs"]   = CODE_RULES[".js"]
CODE_RULES[".ts"]    = CODE_RULES[".js"]


def get_source_files(root: str) -> Generator[str, None, None]:
    """Iterate over all source code files skipping vendor/libraries and defense framework files."""
    skip_dirs_lower  = {d.lower() for d in SKIP_DIRS}
    skip_files_lower = {"adctf.py", "ctf_waf.py", "ctf_waf.php", "test_suite.py"}
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in skip_dirs_lower]
        parts = {p.lower() for p in Path(base).parts}
        if any(sd in parts for sd in skip_dirs_lower):
            continue
        for f in files:
            if f.lower() in skip_files_lower:
                continue
            if os.path.splitext(f)[1].lower() in SRC_EXTS:
                yield os.path.join(base, f)


def _line_window(lines: List[str], n: int, radius: int = 3) -> str:
    """Ambil jendela konteks beberapa baris di sekitar baris ke-n (1-indexed)."""
    lo = max(0, n - 1 - radius)
    hi = min(len(lines), n + radius)
    return "\n".join(lines[lo:hi])


def _is_false_positive(typ: str, line: str, window: str) -> bool:
    """Anti false-positive: abaikan temuan jika mitigasi sudah ada di dekatnya."""
    low = (line + "\n" + window).lower()
    if typ == "UPLOAD" and any(k in low for k in
            ("in_array", "pathinfo", "mime_content_type", "finfo_file", "getimagesize", "exif_imagetype")):
        return True
    if typ == "XSS" and "htmlspecialchars" in low:
        return True
    if typ == "SQLi" and any(k in low for k in
            ("prepare(", "bind_param", "bindvalue", "quote(", "addslashes(", "intval(", "(int)$_", "parameterized")):
        return True
    if typ == "RCE" and any(k in low for k in ("escapeshellarg(", "escapeshellcmd(", "shell=false")):
        return True
    if typ == "LFI" and "basename(" in low:
        return True
    if typ == "DESER" and "allowed_classes" in low:
        return True
    if typ == "SSRF" and any(k in low for k in ("filter_var(", "parse_url(", "allowlist", "whitelist", "is_private")):
        return True
    if typ == "EVAL" and "ast.literal_eval" in low:
        return True
    if typ == "XXE" and ("libxml_disable_entity_loader" in low or "LIBXML_NONET" in low):
        return True
    if typ == "YAML" and "safe_load" in low:
        return True
    return False


def run_scan(web_root: str = ROOT_DEFAULT, db_path: str = DB_DEFAULT) -> int:
    """Scan source code for high-risk vulnerabilities and record to database."""
    root = os.path.abspath(web_root)
    if not os.path.isdir(root):
        safe_print(colorize(f"[ERROR] Web root tidak ditemukan: {root}", Colors.BRIGHT_RED))
        return 1

    conn = get_db(db_path)
    conn.execute(
        "DELETE FROM patch_state WHERE file_path LIKE '%ctf_defense%' "
        "OR file_path LIKE '%adctf.py%' OR file_path LIKE '%tests%';"
    )
    conn.commit()
    total = 0
    print_banner("Source Code Vulnerability Scanner", f"Target: {root}")

    for path in get_source_files(root):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError:
            continue

        digest = file_sha256(path)
        ext    = os.path.splitext(path)[1].lower()
        rules  = CODE_RULES.get(ext, [])

        for n, line in enumerate(lines, 1):
            s = line.strip()
            if not s or s.startswith(("#", "//", "/*", "*")):
                continue

            for typ, rx, advice in rules:
                if rx.search(line):
                    if typ == "RCE" and ("shell=False" in line or "subprocess.run([" in line):
                        continue
                    if _is_false_positive(typ, line, _line_window(lines, n)):
                        continue  # Anti-FP: mitigasi sudah ada di sekitar baris ini

                    confidence = "HIGH" if typ in ("SQLi", "RCE") else "MEDIUM"
                    conn.execute("""
                    INSERT OR REPLACE INTO patch_state(file_path, line_num, vuln_type, file_hash, last_scan_hash, confidence)
                    VALUES(?, ?, ?, ?, ?, ?)
                    """, (path, n, typ, digest, digest, confidence))

                    lo = max(0, n - 2)
                    hi = min(len(lines), n + 2)
                    safe_print(
                        f"\n[{colorize(confidence, Colors.BRIGHT_RED)}]"
                        f"[{colorize(typ, Colors.BRIGHT_YELLOW)}] "
                        f"{colorize(path, Colors.CYAN)}:{n}"
                    )
                    for idx, ctx in enumerate(lines[lo:hi], lo + 1):
                        marker = ">>" if idx == n else "  "
                        color  = Colors.BRIGHT_RED if idx == n else Colors.DIM
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
    """Guided patch cerdas: menampilkan kode nyata dari file server kamu + opsi 1-klik auto-apply."""
    conn = get_db(db_path)
    conn.execute(
        "DELETE FROM patch_state WHERE file_path LIKE '%ctf_defense%' "
        "OR file_path LIKE '%adctf.py%' OR file_path LIKE '%tests%';"
    )
    conn.commit()

    skipped_ids: Set[int] = set()

    while True:
        if skipped_ids:
            ph  = ",".join("?" * len(skipped_ids))
            row = conn.execute(
                f"SELECT * FROM patch_state WHERE status_patched=0 AND id NOT IN ({ph})"
                " ORDER BY CASE confidence WHEN 'HIGH' THEN 0 ELSE 1 END, id LIMIT 1",
                tuple(skipped_ids),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM patch_state WHERE status_patched=0"
                " ORDER BY CASE confidence WHEN 'HIGH' THEN 0 ELSE 1 END, id LIMIT 1"
            ).fetchone()

        if not row:
            if skipped_ids:
                safe_print(colorize(
                    f"\n[✓] Selesai review. {len(skipped_ids)} celah dilewati untuk sesi ini.",
                    Colors.BOLD + Colors.BRIGHT_GREEN,
                ))
            else:
                safe_print(colorize("\n[✓] Luar biasa! Semua celah di database sudah berhasil dipatch!", Colors.BOLD + Colors.BRIGHT_GREEN))
            conn.close()
            return 0

        file_path  = row["file_path"]
        line_num   = row["line_num"]
        vuln_type  = row["vuln_type"]
        confidence = row["confidence"] or "MEDIUM"
        ext        = os.path.splitext(file_path)[1].lower()

        # ── Header ────────────────────────────────────────────────────────────
        print_banner(
            f"Guided Patch — {vuln_type} ({confidence} Confidence)",
            f"Target: {os.path.basename(file_path)} : Baris {line_num}",
        )
        safe_print(f"[*] File       : {colorize(file_path, Colors.BOLD + Colors.CYAN)}")
        safe_print(f"[*] Baris Celah: {colorize(str(line_num), Colors.BOLD + Colors.BRIGHT_WHITE)}")
        safe_print(f"[*] Kategori   : {colorize(vuln_type, Colors.BOLD + Colors.BRIGHT_RED)}")
        safe_print(colorize("-" * 75, Colors.DIM))

        # ── Read actual file lines ────────────────────────────────────────────
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                original_lines = f.read().splitlines()
        except Exception as e:
            safe_print(colorize(f"[ERROR] Gagal membaca file: {e}", Colors.BRIGHT_RED))
            skipped_ids.add(row["id"])
            continue

        # ── Tampilkan Snippet Kode Asli di Server ──────────────────────────────
        lo = max(0, line_num - 4)
        hi = min(len(original_lines), line_num + 5)
        safe_print(colorize("📍 KODE ASLI DI SERVER KAMU SAAT INI:", Colors.BOLD + Colors.WHITE))
        for i in range(lo, hi):
            marker = ">>" if (i + 1) == line_num else "  "
            color  = Colors.BRIGHT_RED if (i + 1) == line_num else Colors.DIM
            safe_print(f"  {marker} {i+1:4d} | {colorize(original_lines[i][:200], color)}")
        safe_print(colorize("-" * 75, Colors.DIM))

        # ── Generate Concrete Patch dari Kode Aktual ──────────────────────────
        smart_patch = generate_smart_patch(file_path, line_num, vuln_type)

        if smart_patch and smart_patch.can_auto_apply:
            safe_print(colorize("🛠️  RESEP PERBAIKAN SPESIFIK UNTUK KODE KAMU (0% TEMPLATE DUMMY):", Colors.BOLD + Colors.BRIGHT_GREEN))
            safe_print(colorize("-" * 75, Colors.DIM))

            safe_print(colorize("❌ KODE RENTAN DI SERVER (HAPUS / GANTI INI):", Colors.BRIGHT_RED))
            for l in smart_patch.before_code.splitlines():
                safe_print(f"   {colorize(l, Colors.BRIGHT_RED)}")

            safe_print(colorize("\n✅ KODE AMAN (SIAP COPY-PASTE ATAU 1-KLIK APPLY):", Colors.BRIGHT_GREEN))
            for l in smart_patch.after_code.splitlines():
                safe_print(f"   {colorize(l, Colors.BOLD + Colors.BRIGHT_GREEN)}")

            safe_print(f"\n💡 {colorize('Penjelasan:', Colors.BOLD + Colors.CYAN)} {smart_patch.explanation}")
            if smart_patch.why_safe:
                safe_print(f"🛡️  {colorize('Kenapa Aman:', Colors.GREEN)} {smart_patch.why_safe}")
            safe_print(colorize("-" * 75, Colors.DIM))

            safe_print(colorize("Pilih aksi:", Colors.BOLD + Colors.WHITE))
            safe_print(f"  {colorize('[ENTER / 1]', Colors.BOLD + Colors.BRIGHT_GREEN)} ⚡ Auto-Apply patch ini sekarang (backup .bak + validasi sintaks)")
            safe_print(f"  {colorize('[2]', Colors.CYAN)}         📝 Salin manual / Buka nano ({smart_patch.manual_command})")
            safe_print(f"  {colorize('[3]', Colors.YELLOW)}         ⏭️  Lewati celah ini (Skip)")
            safe_print(f"  {colorize('[0]', Colors.DIM)}         Kembali / Keluar")

            try:
                choice = input(f"\nPilihan [{colorize('1', Colors.BRIGHT_GREEN)}]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                safe_print("\n[STOP] Dibatalkan.")
                conn.close()
                return 0

            if choice in ("", "1", "a", "apply", "y", "yes"):
                bak = file_path + ".bak"
                if not os.path.exists(bak):
                    shutil.copy2(file_path, bak)
                    safe_print(colorize(f"  [✓] Backup aman dibuat: {bak}", Colors.DIM))

                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(smart_patch.full_patched_content)
                except Exception as e:
                    safe_print(colorize(f"  [✗] Gagal menulis patch ke file: {e}", Colors.BRIGHT_RED))
                    skipped_ids.add(row["id"])
                    continue

                # Validasi sintaks
                is_php = ext in (".php", ".phtml", ".inc")
                is_py  = ext == ".py"
                if is_php and not test_php_syntax(file_path):
                    safe_print(colorize("  [!] Syntax error terdeteksi pada PHP! Melakukan rollback...", Colors.BG_RED + Colors.BOLD))
                    shutil.copy2(bak, file_path)
                    skipped_ids.add(row["id"])
                    continue
                if is_py and not test_python_syntax(file_path):
                    safe_print(colorize("  [!] Syntax error terdeteksi pada Python! Melakukan rollback...", Colors.BG_RED + Colors.BOLD))
                    shutil.copy2(bak, file_path)
                    skipped_ids.add(row["id"])
                    continue

                conn.execute(
                    "UPDATE patch_state SET status_patched=1, verified_at=? WHERE id=?",
                    (now_iso(), row["id"]),
                )
                conn.commit()
                safe_print(colorize(
                    f"\n  [✓] BERHASIL DIPATCH! Celah {vuln_type} pada {os.path.basename(file_path)}:{line_num} telah aman.",
                    Colors.BOLD + Colors.BRIGHT_GREEN,
                ))

            elif choice == "2":
                safe_print(colorize(f"\n  [INFO] Silakan edit manual: {smart_patch.manual_command}", Colors.CYAN))
                safe_print(colorize("  Setelah disimpan, jalankan 'python adctf.py done' untuk menandai selesai.\n", Colors.DIM))
                skipped_ids.add(row["id"])

            elif choice in ("3", "s", "skip"):
                skipped_ids.add(row["id"])
                safe_print(colorize("  [→] Celah dilewati.", Colors.DIM))

            elif choice in ("0", "q", "quit", "exit"):
                safe_print("[STOP] Keluar ke menu utama.")
                conn.close()
                return 0

            else:
                skipped_ids.add(row["id"])

        else:
            # ── Fallback Panduan Kontekstual Manual ───────────────────────────
            safe_print(colorize("📝 PANDUAN PERBAIKAN BERDASARKAN KODE INI:", Colors.BOLD + Colors.YELLOW))
            actual_line = original_lines[line_num - 1] if line_num <= len(original_lines) else ""
            safe_print(f"  Baris rentan: {colorize(actual_line.strip()[:180], Colors.BRIGHT_RED)}")
            safe_print(colorize("-" * 75, Colors.DIM))
            safe_print(f"  {colorize('[D]', Colors.BOLD + Colors.BRIGHT_GREEN)} Sudah saya perbaiki manual — tandai SELESAI")
            safe_print(f"  {colorize('[S]', Colors.YELLOW)} Lewati celah ini")
            safe_print(f"  {colorize('[0]', Colors.DIM)} Keluar")

            try:
                choice = input(f"\nPilihan [{colorize('S', Colors.YELLOW)}]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                conn.close()
                return 0

            if choice in ("d", "done"):
                conn.execute(
                    "UPDATE patch_state SET status_patched=1, verified_at=? WHERE id=?",
                    (now_iso(), row["id"]),
                )
                conn.commit()
                safe_print(colorize(f"  [✓] {vuln_type} @ {os.path.basename(file_path)}:{line_num} ditandai SELESAI.", Colors.BRIGHT_GREEN))
            elif choice in ("0", "q"):
                conn.close()
                return 0
            else:
                skipped_ids.add(row["id"])


def run_done_patch(db_path: str = DB_DEFAULT) -> int:
    """Verify that file was modified and mark current vulnerability as completed."""
    conn = get_db(db_path)
    r = conn.execute(
        "SELECT * FROM patch_state WHERE status_patched=0 ORDER BY id LIMIT 1"
    ).fetchone()
    if not r:
        safe_print("[INFO] Tidak ada temuan aktif di database.")
        return 0

    try:
        current_hash = file_sha256(r["file_path"])
    except Exception:
        safe_print(colorize("[ERROR] File target tidak ditemukan di disk.", Colors.BRIGHT_RED))
        return 1

    if current_hash == r["file_hash"]:
        safe_print(colorize("[ERROR] Done ditolak: File belum diubah. Silakan edit kode terlebih dahulu!", Colors.BRIGHT_RED))
        return 1

    conn.execute(
        "UPDATE patch_state SET status_patched=1, verified_at=? WHERE id=?",
        (now_iso(), r["id"]),
    )
    conn.commit()
    conn.close()
    safe_print(colorize(
        f"[✓] Berhasil! Bug {r['vuln_type']} pada {r['file_path']}:{r['line_num']} ditandai SELESAI.",
        Colors.BOLD + Colors.BRIGHT_GREEN,
    ))
    safe_print("Jalankan 'python adctf.py next' untuk temuan berikutnya.")
    return 0


def run_list_patches(db_path: str = DB_DEFAULT) -> int:
    """List all vulnerability patch items and completion status."""
    conn = get_db(db_path)
    rows = conn.execute("SELECT * FROM patch_state ORDER BY id").fetchall()
    print_banner("Vulnerability Patch Checklist", f"{len(rows)} Total Items")
    for r in rows:
        badge = (
            colorize("[✓ PATCHED]", Colors.GREEN)
            if r["status_patched"]
            else colorize("[X OPEN   ]", Colors.BRIGHT_RED)
        )
        safe_print(f" {badge} {colorize(r['vuln_type'], Colors.YELLOW):<12} | {r['file_path']}:{r['line_num']}")
    conn.close()
    return 0


def print_patch_guides() -> int:
    """Print quick code patching snippets for common web bugs."""
    from .patch_guides import show_all_patch_guides
    return show_all_patch_guides()
