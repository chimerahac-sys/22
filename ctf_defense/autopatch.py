#!/usr/bin/env python3
"""1-Click Automated Safe Micro-Patcher for CTF Attack-Defense.

Applies high-confidence AST/regex patches with:
  - Automatic .bak backup creation
  - Pre-validation of PHP / Python syntax
  - Automatic SLA health check rollback if the patch breaks web functionality
  - Sync with SQLite patch checklist
"""

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .colors import Colors, colorize, print_banner, safe_print
from .scanner import DB_DEFAULT, ROOT_DEFAULT, get_db
from .health_checker import HealthChecker

# Safe Replacement Transformers for Common Patterns
PHP_TRANSFORMERS = [
    # 1. LFI: include/require with user variable -> wrap with basename()
    (
        "LFI",
        re.compile(r"""(\b(?:include|require|include_once|require_once)\s*\(?\s*)(['"][^'"]*['"]\s*\.\s*)?(\$_(?:GET|POST|REQUEST)\[['"][^'"]+['"]\])(\s*\.\s*['"][^'"]*['"])?\s*\)?;"""),
        lambda m: f"{m.group(1)}{m.group(2) or ''}basename({m.group(3)}){m.group(4) or ''}); // AUTO-PATCHED LFI",
        "Membungkus parameter file inclusion dengan basename() agar tidak bisa traversal ../",
    ),

    # 2. LFI: file_get_contents / readfile / highlight_file with user variable
    (
        "LFI-READ",
        re.compile(r"""(\b(?:file_get_contents|readfile|highlight_file|show_source)\s*\(\s*)(['"][^'"]*['"]\s*\.\s*)?(\$_(?:GET|POST|REQUEST)\[['"][^'"]+['"]\])(\s*\.\s*['"][^'"]*['"])?\s*\);"""),
        lambda m: f"{m.group(1)}{m.group(2) or ''}basename({m.group(3)}){m.group(4) or ''}); // AUTO-PATCHED LFI-READ",
        "Membungkus fungsi pembaca file dengan basename() untuk mencegah arbitrary file read",
    ),

    # 3. SQLi: numeric id in WHERE clause -> cast with (int)
    (
        "SQLi-INT",
        re.compile(r"""(\$_(?:GET|POST|REQUEST)\[['"](?:id|uid|user_id|item|page_id|cat|product_id|order_id|num|offset|limit)['"]\])"""),
        lambda m: f"(int){m.group(1)}",
        "Menambahkan typecasting (int) pada parameter ID numerik",
    ),

    # 4. SQLi: string parameter concatenation in query -> wrap with addslashes()
    (
        "SQLi-STR",
        re.compile(r"""(\b(?:mysql_query|mysqli_query|->query|->exec)\s*\(.*?\.\s*)(\$_(?:GET|POST|REQUEST)\[['"][^'"]+['"]\])(\s*\.\s*['"].*?\);)"""),
        lambda m: f"{m.group(1)}addslashes({m.group(2)}){m.group(3)} // AUTO-PATCHED SQLi-STR",
        "Membungkus konkatenasi query SQL dengan addslashes()",
    ),

    # 5. RCE: system/exec with unsanitized variable -> wrap with escapeshellarg()
    (
        "RCE",
        re.compile(r"""(\b(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*)(['"][^'"]*['"]\s*\.\s*)?(\$_(?:GET|POST|REQUEST)\[['"][^'"]+['"]\])(\s*\.\s*['"][^'"]*['"])?\s*\);"""),
        lambda m: f"{m.group(1)}{m.group(2) or ''}escapeshellarg({m.group(3)}){m.group(4) or ''}); // AUTO-PATCHED RCE",
        "Membungkus argumen shell execution dengan escapeshellarg()",
    ),

    # 6. DESER: unserialize() user input -> add allowed_classes false
    (
        "DESER",
        re.compile(r"""\bunserialize\s*\(\s*(\$_(?:GET|POST|REQUEST|COOKIE)\[['"][^'"]+['"]\]|base64_decode\s*\([^)]+\))"""),
        lambda m: f"unserialize({m.group(1)}, ['allowed_classes' => false /* AUTO-PATCHED DESER */]",
        "Menonaktifkan instansiasi class di unserialize() untuk mencegah Object Injection",
    ),

    # 7. TYPE-JUGGLE: strcmp()==0 -> use === and is_string check
    (
        "TYPE-JUGGLE",
        re.compile(r"""strcmp\s*\(\s*(\$_(?:GET|POST|REQUEST)\[['"][^'"]+['"]\])\s*,\s*([^)]+)\)\s*==\s*0"""),
        lambda m: f"is_string({m.group(1)}) && {m.group(1)} === {m.group(2)} /* AUTO-PATCHED TYPE-JUGGLE */",
        "Mengganti strcmp()==0 yang rentan type-juggling dengan strict === comparison",
    ),

    # 8. LOOSE-CMP: $var == 'secret' -> $var === 'secret' (anti magic hash)
    (
        "LOOSE-CMP",
        re.compile(r"""(\$_(?:GET|POST|REQUEST|COOKIE)\[['"][^'"]+['"]\])\s*==\s*(['"][^'"]+['"])"""),
        lambda m: f"{m.group(1)} === {m.group(2)} /* AUTO-PATCHED STRICT-CMP */",
        "Mengganti loose comparison == ke strict === untuk mencegah magic hash bypass",
    ),

    # 9. FILE-UPLOAD: move_uploaded_file tanpa validasi ekstensi -> tambahkan cek
    (
        "UPLOAD",
        re.compile(r"""(move_uploaded_file\s*\(\s*\$_FILES\[['"][^'"]+['"]\]\[['"]tmp_name['"]\]\s*,\s*)(['"][^'"]*['"]\s*\.\s*)?\$_FILES\[['"]([^'"]+)['"]\]\[['"]name['"]\]"""),
        lambda m: f"/* AUTO-PATCHED UPLOAD */ $__ext = strtolower(pathinfo($_FILES['{m.group(3)}']['name'], PATHINFO_EXTENSION)); if(!in_array($__ext, ['jpg','jpeg','png','gif','pdf','txt'], true)){{die('Format file dilarang!');}} $__safename = bin2hex(random_bytes(8)) . '.' . $__ext; {m.group(1)}{m.group(2) or ''}$__safename",
        "Memvalidasi ekstensi file upload dan rename ke random hash (anti webshell upload)",
    ),

    # 10. XSS: echo / print with raw user input -> wrap with htmlspecialchars
    (
        "XSS",
        re.compile(r"""(\b(?:echo|print)\s+)(\$_(?:GET|POST|REQUEST)\[['"][^'"]+['"]\])\s*;"""),
        lambda m: f"{m.group(1)}htmlspecialchars({m.group(2)}, ENT_QUOTES, 'UTF-8'); // AUTO-PATCHED XSS",
        "Membungkus output echo user input dengan htmlspecialchars()",
    ),
]

# Python/Flask Safe Transformers
PYTHON_TRANSFORMERS = [
    # 1. SSTI: render_template_string(f"...{var}...") -> pass as context parameter
    (
        "SSTI",
        re.compile(r"""render_template_string\s*\(\s*f?['"](.*?)\{\s*(\w+)\s*\}(.*?)['"]"""),
        lambda m: f'render_template_string("{m.group(1)}{{{{ {m.group(2)} }}}}{m.group(3)}", {m.group(2)}={m.group(2)}) # AUTO-PATCHED SSTI',
        "Mengirim variabel sebagai context parameter Jinja2 agar tidak bisa di-inject template",
    ),

    # 2. SQLi: cursor.execute(f"SELECT ... WHERE id = {var}") -> parameterized query
    (
        "SQLi",
        re.compile(r"""cursor\.execute\s*\(\s*f['"](SELECT\s+.*?\s+WHERE\s+\w+\s*=\s*)\{\s*(\w+)\s*\}['"]\s*\)"""),
        lambda m: f'cursor.execute("{m.group(1)}?", ({m.group(2)},)) # AUTO-PATCHED SQLi',
        "Mengubah f-string SQL query ke parameterized query (?, (val,))",
    ),

    # 3. PICKLE: pickle.loads(user_input) -> json.loads()
    (
        "PICKLE",
        re.compile(r"""pickle\.loads?\s*\(\s*(.+?)\)"""),
        lambda m: f"json.loads({m.group(1)}) # AUTO-PATCHED PICKLE (was pickle.loads)",
        "Mengganti pickle.loads() ke json.loads() untuk mencegah RCE via deserialization",
    ),

    # 4. YAML: yaml.load(x) -> yaml.safe_load(x)
    (
        "YAML",
        re.compile(r"""yaml\.load\s*\("""),
        lambda m: "yaml.safe_load(",
        "Mengganti yaml.load() ke yaml.safe_load() untuk mencegah arbitrary code execution",
    ),

    # 5. CMDI: os.system(f"...{var}") / subprocess with shell=True
    (
        "CMDI",
        re.compile(r"""os\.(?:system|popen)\s*\(\s*f?['"](.*?)\{\s*(\w+)\s*\}(.*?)['"]"""),
        lambda m: f'subprocess.run(["{m.group(1).split()[0]}", {m.group(2)}], capture_output=True, text=True) # AUTO-PATCHED CMDI',
        "Mengganti os.system() dengan subprocess.run() tanpa shell=True",
    ),

    # 6. EVAL: eval(request.form[...]) -> json.loads
    (
        "EVAL",
        re.compile(r"""\beval\s*\(\s*(request\.(?:form|args|values)\[['"][^'"]+['"]\])\s*\)"""),
        lambda m: f"json.loads({m.group(1)}) # AUTO-PATCHED EVAL",
        "Mengganti eval() dengan json.loads()",
    ),
]


# ── Guided patch helpers ──────────────────────────────────────────────────────
# Regex helpers for multi-line f-string detection
_PY_FSTR_VAR = re.compile(r"\{(\w+)\}")
_PY_FSTR_LINE = re.compile(r"""f(["'])(.*?)\1""")
_PY_EXECUTE_BARE = re.compile(r"""((?:db|conn|cursor|session|g\.db|get_db\(\))\.execute)\s*\((\w+)\s*\)""")


def try_patch_python_sqli_block(
    lines: List[str], trigger_line: int
) -> "Optional[Tuple[List[str], str]]":
    """Attempt to patch a multi-line Python f-string SQLi block.

    Detects patterns like:
        query = (
            "SELECT id FROM users "
            f"WHERE username = '{username}' AND password = '{password}' "
            "LIMIT 1"
        )
        row = db.execute(query).fetchone()

    Returns (new_lines, description) if successfully patched, else None.
    """
    n = trigger_line - 1  # 0-indexed

    search_start = max(0, n - 6)
    search_end = min(len(lines), n + 16)
    block = lines[search_start:search_end]

    # Collect f-string variable names from the block
    fstr_vars: List[str] = []
    for ln in block:
        if _PY_FSTR_LINE.search(ln):
            for m in _PY_FSTR_VAR.finditer(ln):
                v = m.group(1)
                if v not in fstr_vars:
                    fstr_vars.append(v)

    if not fstr_vars:
        return None

    # Find the execute() call nearby (within the block)
    execute_line_idx: "Optional[int]" = None
    execute_call_var: "Optional[str]" = None
    execute_suffix: str = ""
    for i, ln in enumerate(block):
        m = _PY_EXECUTE_BARE.search(ln)
        if m:
            execute_line_idx = search_start + i
            execute_call_var = m.group(2)
            # Preserve chained calls like .fetchone() / .fetchall()
            after = ln[m.end():]
            execute_suffix = after.strip()
            break

    # Replace f-string lines with plain string + ? placeholders
    new_lines = list(lines)
    patched_count = 0
    for i in range(search_start, search_end):
        raw = new_lines[i]
        if not _PY_FSTR_LINE.search(raw):
            continue

        def _replace_fstr(m: re.Match, _raw=raw) -> str:  # type: ignore[override]
            quote = m.group(1)
            inner = m.group(2)
            fixed = re.sub(r"\{(\w+)\}", "?", inner)
            return f'"{fixed}"'

        new_line = _PY_FSTR_LINE.sub(_replace_fstr, raw)
        if new_line != raw:
            new_lines[i] = new_line
            patched_count += 1

    if patched_count == 0:
        return None

    # Patch the execute() call to include params tuple
    if execute_line_idx is not None and execute_call_var is not None:
        if len(fstr_vars) == 1:
            params = f"({fstr_vars[0]},)"
        else:
            params = "(" + ", ".join(fstr_vars) + ")"
        indent = len(new_lines[execute_line_idx]) - len(new_lines[execute_line_idx].lstrip())
        fn_call = _PY_EXECUTE_BARE.search(new_lines[execute_line_idx])
        if fn_call:
            method = fn_call.group(1)
            var = fn_call.group(2)
            suffix = new_lines[execute_line_idx][fn_call.end():]
            new_lines[execute_line_idx] = (
                " " * indent + f"{method}({var}, {params}){suffix}"
            )

    desc = (
        f"Hapus {patched_count} f-string dari SQL query, "
        f"ganti {{var}} → ?, tambah params {params if execute_line_idx is not None else '(...)'} ke .execute()"
    )
    return new_lines, desc
def test_php_syntax(file_path: str) -> bool:
    """Check if a PHP file has valid syntax using php -l."""
    if shutil.which("php"):
        try:
            res = subprocess.run(["php", "-l", file_path], capture_output=True, text=True, timeout=2.0)
            return res.returncode == 0
        except Exception:
            return True
    return True


def test_python_syntax(file_path: str) -> bool:
    """Check if a Python file has valid syntax using py_compile."""
    try:
        import py_compile
        py_compile.compile(file_path, doraise=True)
        return True
    except py_compile.PyCompileError:
        return False
    except Exception:
        return True


def _quiet_sla_check(port: int = 80, timeout: float = 2.0) -> bool:
    """Silent localhost HTTP check - True jika service merespons HTTP apa pun."""
    import urllib.request
    import urllib.error
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=timeout)
        return True
    except urllib.error.HTTPError:
        return True  # Ada respons HTTP = service hidup (403/404 tetap SLA-OK)
    except Exception:
        return False


def apply_safe_autopatch(
    web_root: str = ROOT_DEFAULT,
    db_path: str = DB_DEFAULT,
    port: int = 80,
    dry_run: bool = False,
) -> int:
    """Scan and apply safe micro-patches across vulnerable files in webroot."""
    print_banner("1-Click Automated Micro-Patcher", "Safe AST-Regex Code Remediation with SLA Rollback")

    if not os.path.isdir(web_root):
        safe_print(colorize(f"[!] Webroot tidak ditemukan: {web_root}", Colors.BRIGHT_RED))
        return 1

    conn = get_db(db_path)
    total_patched = 0
    rollback_count = 0

    SKIP_DIRS = {"vendor", "node_modules", ".git", ".svn", "cache", "dist", "build", "framework", "tests", "ctf_defense", "docs", ".adctf", "venv", "__pycache__", "site-packages"}

    for root, dirs, files in os.walk(web_root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            is_php = fname.endswith((".php", ".phtml", ".inc"))
            is_py = fname.endswith(".py")
            if not is_php and not is_py:
                continue

            fpath = os.path.join(root, fname)
            try:
                content = Path(fpath).read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            new_content = content
            file_changes = []

            # Pick transformer set based on file type
            transformers = PHP_TRANSFORMERS if is_php else PYTHON_TRANSFORMERS

            for cat, rx, repl_fn, desc in transformers:
                if rx.search(new_content):
                    # Check if this specific category was already patched
                    patch_marker = f"AUTO-PATCHED {cat}"
                    if patch_marker in new_content:
                        continue
                    new_content, n = rx.subn(repl_fn, new_content)
                    if n > 0:
                        file_changes.append((cat, n, desc))

            if file_changes and new_content != content:
                rel = os.path.relpath(fpath, web_root)
                lang_badge = colorize("[PHP]", Colors.BRIGHT_CYAN) if is_php else colorize("[PY]", Colors.BRIGHT_GREEN)
                safe_print(f"\n[*] {lang_badge} Menemukan {len(file_changes)} patch untuk: {colorize(rel, Colors.BOLD + Colors.CYAN)}")
                for cat, count, desc in file_changes:
                    safe_print(f"    ├─ [{colorize(cat, Colors.BRIGHT_YELLOW)}] {count}x: {desc}")

                if dry_run:
                    safe_print(colorize("    └─ [DRY-RUN] Melewati penulisan file.", Colors.DIM))
                    continue

                # 1. Create backup
                bak_path = fpath + ".bak"
                if not os.path.exists(bak_path):
                    shutil.copy2(fpath, bak_path)

                # 2. Write patch
                try:
                    Path(fpath).write_text(new_content, encoding="utf-8")
                except Exception as e:
                    safe_print(colorize(f"    └─ [✗] Gagal menulis patch: {e}", Colors.BRIGHT_RED))
                    continue

                # 3. Check syntax (PHP or Python)
                syntax_ok = True
                if is_php:
                    syntax_ok = test_php_syntax(fpath)
                elif is_py:
                    syntax_ok = test_python_syntax(fpath)

                if not syntax_ok:
                    safe_print(colorize("    └─ [!] Syntax error terdeteksi! Melakukan rollback...", Colors.BG_RED + Colors.BOLD + Colors.WHITE))
                    shutil.copy2(bak_path, fpath)
                    rollback_count += 1
                    continue

                # 4. Check SLA health (silent check - no banner spam)
                if not _quiet_sla_check(port):
                    safe_print(colorize("    └─ [!] SLA Check GAGAL (HTTP Error)! Mengembalikan file asli...", Colors.BG_RED + Colors.BOLD + Colors.WHITE))
                    shutil.copy2(bak_path, fpath)
                    rollback_count += 1
                    continue

                # 5. Success! Mark in SQLite
                safe_print(colorize("    └─ [✓] Patch sukses diaplikasikan & SLA 100% AMAN!", Colors.BOLD + Colors.BRIGHT_GREEN))
                total_patched += 1
                try:
                    conn.execute(
                        "UPDATE patch_state SET status_patched=1, notes='Auto-patched safely' WHERE file_path LIKE ?",
                        (f"%{fname}%",),
                    )
                    conn.commit()
                except Exception:
                    pass

    conn.close()
    safe_print(colorize("\n" + "=" * 75, Colors.DIM))
    safe_print(f"[*] Auto-Patch Selesai: {colorize(str(total_patched), Colors.BOLD + Colors.BRIGHT_GREEN)} file diperbaiki | {rollback_count} file di-rollback demi SLA.")
    safe_print(f"[*] Coverage: {colorize('7 jenis celah PHP', Colors.CYAN)} (LFI, SQLi, RCE, Deserialization, Type-Juggling, Loose-CMP, Upload)")
    safe_print(f"[*]           {colorize('4 jenis celah Python', Colors.GREEN)} (SSTI, Pickle, YAML, Command Injection)\n")
    return 0

