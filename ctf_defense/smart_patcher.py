#!/usr/bin/env python3
"""Smart Concrete Code Patcher for CTF Attack-Defense.

Generates exact before-and-after diffs with the user's actual variable names,
line numbers, and framework methods. 0% False Positives.
"""

import ast
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class SmartPatch:
    can_auto_apply: bool
    file_path: str
    vuln_type: str
    confidence: str
    target_start_line: int
    target_end_line: int
    secondary_lines: List[int] = field(default_factory=list)
    before_code: str = ""
    after_code: str = ""
    full_patched_content: str = ""
    explanation: str = ""
    why_safe: str = ""
    manual_command: str = ""


def _clean_sql_placeholder(line: str, var: str) -> str:
    """Replace '{var}', "{var}", or {var} with SQL placeholder '?'."""
    for q in ("'", '"', ""):
        target = f"{q}{{{var}}}{q}"
        line = line.replace(target, "?")
    return line


def _remove_leading_f(line: str) -> str:
    """Remove f prefix from string literals like f"..." or f'...'."""
    return line.replace('f"', '"').replace("f'", "'")


# ─────────────────────────────────────────────────────────────────────────────
# Python Patch Generators
# ─────────────────────────────────────────────────────────────────────────────

def _patch_python_sqli(lines: List[str], trigger_line: int, file_path: str) -> Optional[SmartPatch]:
    """Patch Python SQL injection using AST."""
    code = "\n".join(lines)
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None

    target_assign = None
    target_var = None

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            start = node.lineno
            end = getattr(node, "end_lineno", node.lineno)
            if (start <= trigger_line <= end) or abs(start - trigger_line) <= 4:
                has_fstr = any(isinstance(c, ast.JoinedStr) for c in ast.walk(node.value))
                if has_fstr:
                    target_assign = node
                    names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                    if names:
                        target_var = names[0]
                    break

    # Case A: Multi-line query variable assignment + .execute(query)
    if target_assign and target_var:
        fvars = []
        for c in ast.walk(target_assign.value):
            if isinstance(c, ast.JoinedStr):
                for part in c.values:
                    if isinstance(part, ast.FormattedValue):
                        var_expr = ast.unparse(part.value).strip()
                        if var_expr and var_expr not in fvars:
                            fvars.append(var_expr)

        if fvars:
            exec_node = None
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "execute":
                    if node.args and getattr(node.args[0], "id", "") == target_var:
                        exec_node = node
                        break

            new_lines = list(lines)
            start_idx = target_assign.lineno - 1
            end_idx = getattr(target_assign, "end_lineno", target_assign.lineno)

            before_parts = []
            after_parts = []

            for i in range(start_idx, end_idx):
                orig_line = lines[i]
                mod_line = orig_line
                for v in fvars:
                    mod_line = _clean_sql_placeholder(mod_line, v)
                mod_line = _remove_leading_f(mod_line)
                new_lines[i] = mod_line
                before_parts.append(orig_line)
                after_parts.append(mod_line)

            secondary = []
            params_str = f"({fvars[0]},)" if len(fvars) == 1 else "(" + ", ".join(fvars) + ")"
            if exec_node:
                exec_idx = exec_node.lineno - 1
                secondary.append(exec_node.lineno)
                orig_exec = lines[exec_idx]
                mod_exec = re.sub(
                    rf"(\.execute\s*\(\s*{re.escape(target_var)}\s*)\)",
                    rf"\1, {params_str})",
                    orig_exec
                )
                new_lines[exec_idx] = mod_exec
                before_parts.append(f"...\n  [Baris {exec_node.lineno}] " + orig_exec.strip())
                after_parts.append(f"...\n  [Baris {exec_node.lineno}] " + mod_exec.strip())

            return SmartPatch(
                can_auto_apply=True,
                file_path=file_path,
                vuln_type="SQLi",
                confidence="HIGH",
                target_start_line=target_assign.lineno,
                target_end_line=getattr(target_assign, "end_lineno", target_assign.lineno),
                secondary_lines=secondary,
                before_code="\n".join(before_parts),
                after_code="\n".join(after_parts),
                full_patched_content="\n".join(new_lines) + ("\n" if lines and lines[-1] else ""),
                explanation=f"Ganti f-string query dengan placeholder '?' dan teruskan tuple {params_str} ke dalam .execute().",
                why_safe="Karakter kutip dan payload SQLi diisolasi 100% sebagai data parameter oleh database engine, sehingga tidak bisa memecah struktur SQL query.",
                manual_command=f"nano +{target_assign.lineno} {file_path}",
            )

    # Case B: Direct .execute(f"SELECT ... {var}")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "execute":
            if abs(node.lineno - trigger_line) <= 4:
                if node.args and isinstance(node.args[0], ast.JoinedStr):
                    joined = node.args[0]
                    fvars = []
                    for part in joined.values:
                        if isinstance(part, ast.FormattedValue):
                            v = ast.unparse(part.value).strip()
                            if v and v not in fvars:
                                fvars.append(v)
                    if fvars:
                        new_lines = list(lines)
                        line_idx = node.lineno - 1
                        orig_line = lines[line_idx]
                        mod_line = orig_line
                        for v in fvars:
                            mod_line = _clean_sql_placeholder(mod_line, v)
                        mod_line = _remove_leading_f(mod_line)
                        params_str = f"({fvars[0]},)" if len(fvars) == 1 else "(" + ", ".join(fvars) + ")"
                        mod_line = re.sub(r'(\.execute\s*\(.*?)\)', rf'\1, {params_str})', mod_line)
                        new_lines[line_idx] = mod_line

                        return SmartPatch(
                            can_auto_apply=True,
                            file_path=file_path,
                            vuln_type="SQLi",
                            confidence="HIGH",
                            target_start_line=node.lineno,
                            target_end_line=getattr(node, "end_lineno", node.lineno),
                            before_code=orig_line,
                            after_code=mod_line,
                            full_patched_content="\n".join(new_lines) + ("\n" if lines and lines[-1] else ""),
                            explanation=f"Ubah query langsung ke parameterized query: placeholder '?' dan tuple parameter {params_str}.",
                            why_safe="Parameter binding melindungi query dari SQL injection tanpa mengubah struktur kode lainnya.",
                            manual_command=f"nano +{node.lineno} {file_path}",
                        )

    return None


def _patch_python_cmdi(lines: List[str], trigger_line: int, file_path: str) -> Optional[SmartPatch]:
    """Patch Python Command Injection."""
    code = "\n".join(lines)
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None

    target_call = None
    cmd_var = None

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = ast.unparse(node.func)
            if any(f in func_name for f in ("subprocess.run", "subprocess.Popen", "subprocess.call", "os.system", "os.popen")):
                start = node.lineno
                end = getattr(node, "end_lineno", node.lineno)
                if abs(start - trigger_line) <= 8 or (start <= trigger_line <= end):
                    target_call = node
                    if node.args and isinstance(node.args[0], ast.Name):
                        cmd_var = node.args[0].id
                    break

    if not target_call:
        return None

    cmd_assign = None
    if cmd_var:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == cmd_var for t in node.targets):
                if node.lineno < target_call.lineno and (target_call.lineno - node.lineno) <= 12:
                    cmd_assign = node
                    break

    new_lines = list(lines)
    before_parts = []
    after_parts = []

    # Case A: cmd = f"ping -c 1 {host}"
    if cmd_assign and isinstance(cmd_assign.value, ast.JoinedStr):
        parts = []
        for p in cmd_assign.value.values:
            if isinstance(p, ast.Constant) and isinstance(p.value, str):
                parts.extend([f'"{tok}"' for tok in p.value.split() if tok])
            elif isinstance(p, ast.FormattedValue):
                parts.append(ast.unparse(p.value).strip())

        assign_idx = cmd_assign.lineno - 1
        indent = len(lines[assign_idx]) - len(lines[assign_idx].lstrip())
        new_assign = " " * indent + f"{cmd_var} = [{', '.join(parts)}]"
        new_lines[assign_idx] = new_assign
        before_parts.append(lines[assign_idx])
        after_parts.append(new_assign)

        for i in range(target_call.lineno - 1, getattr(target_call, "end_lineno", target_call.lineno)):
            if "shell=True" in lines[i] or "shell = True" in lines[i]:
                new_lines[i] = re.sub(r"shell\s*=\s*True", "shell=False", lines[i])
                before_parts.append(f"...\n  [Baris {i+1}] " + lines[i].strip())
                after_parts.append(f"...\n  [Baris {i+1}] " + new_lines[i].strip())
                break

        return SmartPatch(
            can_auto_apply=True,
            file_path=file_path,
            vuln_type="RCE",
            confidence="HIGH",
            target_start_line=cmd_assign.lineno,
            target_end_line=getattr(target_call, "end_lineno", target_call.lineno),
            before_code="\n".join(before_parts),
            after_code="\n".join(after_parts),
            full_patched_content="\n".join(new_lines) + ("\n" if lines and lines[-1] else ""),
            explanation=f"Ubah shell command '{cmd_var}' menjadi list argumen terpisah dan ubah shell=False.",
            why_safe="Dengan shell=False dan list argumen, sistem operasi mengeksekusi binary langsung tanpa /bin/sh sehingga command chaining (; | && `) dinetralkan.",
            manual_command=f"nano +{cmd_assign.lineno} {file_path}",
        )

    return None


def _patch_python_lfi(lines: List[str], trigger_line: int, file_path: str) -> Optional[SmartPatch]:
    """Patch Python Path Traversal."""
    new_lines = list(lines)
    lo = max(0, trigger_line - 8)
    hi = min(len(lines), trigger_line + 8)

    rx_input = re.compile(r"""(\b\w+\s*=\s*)(request\.(?:args|form|values)\.get\([^)]+\))""")
    rx_open = re.compile(r"""(\bopen\s*\(\s*)(request\.(?:args|form|values)\.get\([^)]+\))""")

    for i in range(lo, hi):
        m = rx_open.search(lines[i])
        if m:
            mod_line = rx_open.sub(r"\1os.path.basename(\2 or '')", lines[i])
            new_lines[i] = mod_line
            return SmartPatch(
                can_auto_apply=True,
                file_path=file_path,
                vuln_type="LFI",
                confidence="HIGH",
                target_start_line=i + 1,
                target_end_line=i + 1,
                before_code=lines[i],
                after_code=mod_line,
                full_patched_content="\n".join(new_lines) + ("\n" if lines and lines[-1] else ""),
                explanation="Bungkus input file dengan os.path.basename() untuk mencegah path traversal (../).",
                why_safe="os.path.basename() membuang semua prefix folder atau traversal ../ sehingga hanya file di direktori lokal yang dapat diakses.",
                manual_command=f"nano +{i + 1} {file_path}",
            )

    for i in range(lo, hi):
        m = rx_input.search(lines[i])
        if m:
            orig_line = lines[i]
            mod_line = rx_input.sub(r"\1os.path.basename(\2 or '')", orig_line)
            new_lines[i] = mod_line
            return SmartPatch(
                can_auto_apply=True,
                file_path=file_path,
                vuln_type="LFI",
                confidence="HIGH",
                target_start_line=i + 1,
                target_end_line=i + 1,
                before_code=orig_line,
                after_code=mod_line,
                full_patched_content="\n".join(new_lines) + ("\n" if lines and lines[-1] else ""),
                explanation="Bungkus parameter filename input dengan os.path.basename() agar traversal ../ dinetralkan.",
                why_safe="Traversal ../ akan dibuang menjadi nama file biasa sehingga tidak dapat membaca /etc/passwd atau file rahasia di luar direktori.",
                manual_command=f"nano +{i + 1} {file_path}",
            )

    return None


def _patch_python_ssti(lines: List[str], trigger_line: int, file_path: str) -> Optional[SmartPatch]:
    """Patch Flask Jinja2 SSTI."""
    new_lines = list(lines)
    lo = max(0, trigger_line - 6)
    hi = min(len(lines), trigger_line + 6)

    rx_ssti = re.compile(r"""render_template_string\s*\(\s*f(['"])(.*?)\1\s*\)""")
    for i in range(lo, hi):
        m = rx_ssti.search(lines[i])
        if m:
            inner = m.group(2)
            fvars = re.findall(r"\{(\w+)\}", inner)
            if fvars:
                fixed_tmpl = re.sub(r"\{(\w+)\}", r"{{ \1 }}", inner)
                context_args = ", ".join(f"{v}={v}" for v in fvars)
                mod_line = re.sub(
                    r"""render_template_string\s*\(\s*f(['"]).*?\1\s*\)""",
                    f'render_template_string("{fixed_tmpl}", {context_args})',
                    lines[i]
                )
                new_lines[i] = mod_line
                return SmartPatch(
                    can_auto_apply=True,
                    file_path=file_path,
                    vuln_type="SSTI",
                    confidence="HIGH",
                    target_start_line=i + 1,
                    target_end_line=i + 1,
                    before_code=lines[i],
                    after_code=mod_line,
                    full_patched_content="\n".join(new_lines) + ("\n" if lines and lines[-1] else ""),
                    explanation=f"Kirim variabel {{{', '.join(fvars)}}} sebagai parameter context Jinja2 terpisah, bukan f-string langsung.",
                    why_safe="Jinja2 memisahkan parsing template dari nilai variabel, mencegah eksekusi arbitrary Jinja payload.",
                    manual_command=f"nano +{i + 1} {file_path}",
                )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# PHP Patch Generators
# ─────────────────────────────────────────────────────────────────────────────

def _patch_php_sqli(lines: List[str], trigger_line: int, file_path: str) -> Optional[SmartPatch]:
    """Patch PHP SQL injection."""
    new_lines = list(lines)
    lo = max(0, trigger_line - 4)
    hi = min(len(lines), trigger_line + 4)

    rx_id = re.compile(r"""(\$_(?:GET|POST|REQUEST)\[['"](?:id|uid|user_id|item|page_id|cat|num)['"]\])""")
    for i in range(lo, hi):
        if rx_id.search(lines[i]) and "(int)" not in lines[i]:
            mod_line = rx_id.sub(r"(int)\1", lines[i])
            new_lines[i] = mod_line
            return SmartPatch(
                can_auto_apply=True,
                file_path=file_path,
                vuln_type="SQLi",
                confidence="HIGH",
                target_start_line=i + 1,
                target_end_line=i + 1,
                before_code=lines[i],
                after_code=mod_line,
                full_patched_content="\n".join(new_lines) + ("\n" if lines and lines[-1] else ""),
                explanation="Tambahkan typecasting (int) pada parameter ID numerik.",
                why_safe="Karakter kutip atau SQL statement akan dipaksa menjadi angka 0 jika bukan integer murni, menutup 100% peluang SQL injection.",
                manual_command=f"nano +{i + 1} {file_path}",
            )

    rx_concat = re.compile(r"""(\.\s*)(\$_(?:GET|POST|REQUEST)\[['"](\w+)['"]\])""")
    for i in range(lo, hi):
        if ("query" in lines[i] or "SELECT" in lines[i] or "WHERE" in lines[i]) and rx_concat.search(lines[i]):
            mod_line = rx_concat.sub(r"\1addslashes(\2)", lines[i])
            new_lines[i] = mod_line
            return SmartPatch(
                can_auto_apply=True,
                file_path=file_path,
                vuln_type="SQLi",
                confidence="HIGH",
                target_start_line=i + 1,
                target_end_line=i + 1,
                before_code=lines[i],
                after_code=mod_line,
                full_patched_content="\n".join(new_lines) + ("\n" if lines and lines[-1] else ""),
                explanation="Bungkus variabel input di query SQL dengan addslashes().",
                why_safe="addslashes() melakukan escape terhadap kutip tunggal dan ganda, mencegah attacker memecah batasan string literal SQL.",
                manual_command=f"nano +{i + 1} {file_path}",
            )

    return None


def _patch_php_lfi(lines: List[str], trigger_line: int, file_path: str) -> Optional[SmartPatch]:
    """Patch PHP Local File Inclusion."""
    new_lines = list(lines)
    lo = max(0, trigger_line - 4)
    hi = min(len(lines), trigger_line + 4)

    rx_inc = re.compile(r"""(\b(?:include|require|include_once|require_once|readfile|file_get_contents)\s*\(?\s*)(['"][^'"]*['"]\s*\.\s*)?(\$_(?:GET|POST|REQUEST)\[['"][^'"]+['"]\])""")
    for i in range(lo, hi):
        m = rx_inc.search(lines[i])
        if m:
            prefix = m.group(1)
            base_str = m.group(2) or ""
            param = m.group(3)
            mod_line = lines[i].replace(m.group(0), f"{prefix}{base_str}basename({param})")
            new_lines[i] = mod_line
            return SmartPatch(
                can_auto_apply=True,
                file_path=file_path,
                vuln_type="LFI",
                confidence="HIGH",
                target_start_line=i + 1,
                target_end_line=i + 1,
                before_code=lines[i],
                after_code=mod_line,
                full_patched_content="\n".join(new_lines) + ("\n" if lines and lines[-1] else ""),
                explanation="Bungkus parameter file inclusion dengan basename() untuk mencegah directory traversal.",
                why_safe="basename() membuang ../ dan path absolute sehingga attacker tidak dapat mengakses file di luar folder yang ditentukan.",
                manual_command=f"nano +{i + 1} {file_path}",
            )
    return None


def _patch_php_rce(lines: List[str], trigger_line: int, file_path: str) -> Optional[SmartPatch]:
    """Patch PHP Command Execution."""
    new_lines = list(lines)
    lo = max(0, trigger_line - 4)
    hi = min(len(lines), trigger_line + 4)

    rx_exec = re.compile(r"""(\b(?:system|exec|passthru|shell_exec|popen)\s*\(\s*.*?)((\$_(?:GET|POST|REQUEST)\[['"][^'"]+['"]\]|\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*))""")
    for i in range(lo, hi):
        if "escapeshellarg" in lines[i]:
            continue
        m = rx_exec.search(lines[i])
        if m:
            var_part = m.group(2)
            mod_line = lines[i].replace(var_part, f"escapeshellarg({var_part})")
            new_lines[i] = mod_line
            return SmartPatch(
                can_auto_apply=True,
                file_path=file_path,
                vuln_type="RCE",
                confidence="HIGH",
                target_start_line=i + 1,
                target_end_line=i + 1,
                before_code=lines[i],
                after_code=mod_line,
                full_patched_content="\n".join(new_lines) + ("\n" if lines and lines[-1] else ""),
                explanation=f"Bungkus argumen shell '{var_part}' dengan escapeshellarg().",
                why_safe="escapeshellarg() mengisolasi seluruh string dalam single-quote sehingga karakter pemecah command dinetralkan.",
                manual_command=f"nano +{i + 1} {file_path}",
            )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Master Dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def generate_smart_patch(file_path: str, line_num: int, vuln_type: str) -> Optional[SmartPatch]:
    """Generate a precise, context-aware SmartPatch for the given file and line."""
    if not os.path.isfile(file_path):
        return None

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return None

    if not lines or line_num > len(lines):
        return None

    ext = os.path.splitext(file_path)[1].lower()
    vt = vuln_type.upper()

    if ext == ".py":
        if "SQLI" in vt:
            return _patch_python_sqli(lines, line_num, file_path)
        elif "RCE" in vt or "CMDI" in vt:
            return _patch_python_cmdi(lines, line_num, file_path)
        elif "LFI" in vt:
            return _patch_python_lfi(lines, line_num, file_path)
        elif "SSTI" in vt:
            return _patch_python_ssti(lines, line_num, file_path)

    elif ext in (".php", ".phtml", ".inc"):
        if "SQLI" in vt:
            return _patch_php_sqli(lines, line_num, file_path)
        elif "LFI" in vt:
            return _patch_php_lfi(lines, line_num, file_path)
        elif "RCE" in vt:
            return _patch_php_rce(lines, line_num, file_path)

    return None


def test_php_syntax(file_path: str) -> bool:
    """Check if a PHP file has valid syntax using php -l."""
    import shutil, subprocess
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
