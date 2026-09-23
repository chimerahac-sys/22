#!/usr/bin/env python3
# recon_pro.py - accurate vuln detector: AST taint analysis + C stateful parse
import os, re, ast, subprocess, json, sys, glob
from collections import defaultdict

REPORT_TXT  = "recon.txt"
REPORT_JSON = "recon.json"

# ====================================================================
# PYTHON — AST-BASED TAINT ANALYSIS
# ====================================================================
PY_SOURCES = {
    # cara user input masuk
    "request.form", "request.args", "request.json", "request.values",
    "request.data", "request.cookies", "request.headers", "request.files",
    "request.get_json", "request.form.get", "request.args.get",
    "input", "sys.argv", "os.environ.get", "os.getenv",
}

PY_SINKS = {
    # nama fungsi -> kategori
    "render_template_string": "SSTI",
    "render_template": "SSTI (partial)",
    "Template": "SSTI (jinja2.Template)",
    "from_string": "SSTI (jinja2)",
    "eval": "RCE (eval)",
    "exec": "RCE (exec)",
    "compile": "RCE (compile)",
    "os.system": "CMDi",
    "os.popen": "CMDi",
    "subprocess.call": "CMDi",
    "subprocess.run": "CMDi",
    "subprocess.Popen": "CMDi",
    "subprocess.check_output": "CMDi",
    "pickle.loads": "Deserial",
    "yaml.load": "Deserial (unsafe)",
    "marshal.loads": "Deserial",
    "open": "LFI (open)",
    "send_file": "LFI (send_file)",
    "send_from_directory": "LFI",
    "requests.get": "SSRF",
    "requests.post": "SSRF",
    "urlopen": "SSRF",
    "cursor.execute": "SQLi (cursor)",
    "execute": "SQLi (execute)",
    "executemany": "SQLi",
    "raw": "SQLi (raw)",
}

def _func_name(node):
    """Ekstrak nama fungsi dari ast.Call."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""

def _is_source(node):
    """Cek apakah node = user input source."""
    name = _func_name(node)
    if not name:
        return False
    for src in PY_SOURCES:
        if src in name:
            return True
    return False

def _is_literal(node):
    """Cek apakah node literal (string/num) — bukan tainted."""
    return isinstance(node, (ast.Constant, ast.Str, ast.Num, ast.List, ast.Tuple, ast.Dict, ast.Set))

class PyTaint(ast.NodeVisitor):
    """Taint analysis: source → var → sink."""
    def __init__(self, src):
        self.src = src
        self.src_lines = src.split("\n")
        self.tainted = set()
        self.findings = []
        self.assigns = {}
        self.funcs = []
        self.imports = set()

    def _get_code(self, node):
        try:
            seg = ast.get_source_segment(self.src, node)
            return (seg or "").strip().replace("\n", " ")[:200]
        except:
            return ""

    def visit_Import(self, node):
        for n in node.names:
            self.imports.add(n.name)

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.add(node.module)

    def visit_FunctionDef(self, node):
        self.funcs.append({
            "name": node.name,
            "line": node.lineno,
            "args": [a.arg for a in node.args.args],
        })
        self.generic_visit(node)

    def visit_Assign(self, node):
        # Cek apakah RHS tainted
        tainted = self._expr_tainted(node.value)

        # Kalau assign value = KEY/SECRET hardcoded string
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id
                if any(k in name.upper() for k in ["KEY", "SECRET", "SALT", "IV", "NONCE", "PASSWORD", "TOKEN"]):
                    val_code = self._get_code(node.value)
                    is_hardcoded = isinstance(node.value, (ast.Constant, ast.Str, ast.Bytes))
                    is_hash = "hashlib" in val_code or "sha256" in val_code or "md5" in val_code
                    self.assigns[name] = {
                        "line": node.lineno,
                        "value": val_code,
                        "hardcoded": is_hardcoded,
                        "hash": is_hash,
                    }
                    # Flag: hardcoded KEY = derivable
                    if is_hardcoded or (is_hash and "b'" in val_code or 'b"' in val_code):
                        self.findings.append({
                            "cat": "CRYPTO",
                            "desc": f"KEY/SECRET hardcoded (derivable)",
                            "line": node.lineno,
                            "code": self._get_code(node),
                            "confidence": "high",
                        })

                if tainted:
                    self.tainted.add(name)
        self.generic_visit(node)

    def visit_Call(self, node):
        fname = _func_name(node.func)

        # Cek sink
        for sink_name, cat in PY_SINKS.items():
            if fname == sink_name or fname.endswith("." + sink_name) or sink_name in fname:
                # Cek arg tainted?
                for arg in node.args:
                    if self._expr_tainted(arg):
                        self.findings.append({
                            "cat": cat,
                            "desc": f"{fname}() dipanggil dengan user input",
                            "line": node.lineno,
                            "code": self._get_code(node),
                            "confidence": "high",
                        })
                        break
        self.generic_visit(node)

    def _expr_tainted(self, node):
        """Rekursif cek apakah expression tainted."""
        if node is None: return False
        if _is_literal(node): return False

        # Direct source call
        if isinstance(node, ast.Call) and _is_source(node):
            return True

        # Name → cek apakah di tainted set
        if isinstance(node, ast.Name):
            return node.id in self.tainted

        # BinOp: cek kedua sisi
        if isinstance(node, ast.BinOp):
            return self._expr_tainted(node.left) or self._expr_tainted(node.right)

        # f-string / JoinedStr
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    if self._expr_tainted(v.value):
                        return True

        # .format() call
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "format":
                if self._expr_tainted(node.func.value):
                    return True
                for a in node.args:
                    if self._expr_tainted(a):
                        return True

        # % formatting
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return self._expr_tainted(node.left) or self._expr_tainted(node.right)

        # Attribute access — e.g. request.form.get('x')['y']
        if isinstance(node, ast.Attribute):
            return self._expr_tainted(node.value)

        # Subscript — e.g. request.form['x']
        if isinstance(node, ast.Subscript):
            return self._expr_tainted(node.value)

        return False

def analyze_python(path):
    try:
        src = open(path, errors="ignore").read()
    except Exception as e:
        return {"error": str(e)}

    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return {"error": f"syntax: {e}"}

    t = PyTaint(src)
    t.visit(tree)

    # Flask endpoints
    endpoints = re.findall(r"@app\.(?:get|post|route|put|delete)\s*\(\s*['\"]([^'\"]+)", src)
    endpoints += re.findall(r"@(?:bp|blueprint)\.route\s*\(\s*['\"]([^'\"]+)", src)

    # Fields — filter valid
    fields = set()
    for m in re.finditer(r"request\.(?:form|args|json|values)\.get\s*\(\s*['\"]([^'\"]+)['\"]", src):
        fields.add(m.group(1))
    for m in re.finditer(r"request\.(?:form|args|values)\[['\"]([^'\"]+)['\"]\]", src):
        fields.add(m.group(1))

    return {
        "src": src,
        "findings": t.findings,
        "funcs": t.funcs,
        "assigns": t.assigns,
        "imports": sorted(t.imports),
        "endpoints": sorted(set(endpoints)),
        "fields": sorted(fields),
        "tainted_vars": sorted(t.tainted),
        "size": len(src),
    }

# ====================================================================
# C — STATEFUL PARSE (function-scope aware)
# ====================================================================
C_UNSAFE_READ = {
    "read": 2, "fread": 2, "recv": 2, "recvfrom": 2,
    "memcpy": 2, "memmove": 2, "strncpy": 2,
}
C_UNSAFE_FUNC = {
    "gets": "buffer overflow — no bounds",
    "strcpy": "buffer overflow — no bounds",
    "strcat": "buffer overflow — no bounds",
    "sprintf": "buffer overflow — no bounds",
    "scanf": "buffer overflow — %s no width",
}
C_FORMAT_FUNCS = {"printf", "fprintf", "sprintf", "snprintf", "syslog", "vprintf"}
C_CMD_FUNCS = {"system", "popen", "execve", "execl", "execlp", "execvp", "execv"}

def c_parse(path):
    try:
        src = open(path, errors="ignore").read()
    except Exception as e:
        return {"error": str(e)}

    lines = src.split("\n")
    findings = []

    # ---- Stage 1: find all function boundaries ----
    funcs = []   # {"name": str, "start_line": int, "end_line": int, "body": str}
    current = None
    brace_depth = 0
    func_re = re.compile(r"^\s*(?:static\s+)?(?:void|int|char\s*\*|unsigned\s+\w+|long|short|size_t)\s+(\w+)\s*\(([^)]*)\)\s*\{")

    for i, line in enumerate(lines, 1):
        m = func_re.match(line)
        if m and not current:
            current = {"name": m.group(1), "args": m.group(2),
                       "start_line": i, "body": line}
            brace_depth = line.count("{") - line.count("}")
            if brace_depth == 0:
                funcs.append(current); current = None
            continue
        if current:
            current["body"] += "\n" + line
            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0:
                current["end_line"] = i
                funcs.append(current)
                current = None

    # ---- Stage 2: per function — buffer + read analysis ----
    for fn in funcs:
        body = fn["body"]

        # Buffers in this function
        buffers = {}   # name -> size
        for m in re.finditer(r"char\s+(\w+)\s*\[\s*(\d+)\s*\]", body):
            buffers[m.group(1)] = int(m.group(2))

        # read/copy calls
        for call_name, arg_idx in C_UNSAFE_READ.items():
            for m in re.finditer(rf"\b{call_name}\s*\(([^;]{{0,300}})\)", body):
                args = m.group(1)
                # parse arg list (simple split by , outside quotes)
                arg_list = re.split(r",(?![^()]*\))", args)
                if len(arg_list) < arg_idx + 1: continue

                dst = arg_list[arg_idx - 1].strip() if call_name in ("read","fread","recv","recvfrom") else arg_list[0].strip()
                size_arg = arg_list[arg_idx].strip() if len(arg_list) > arg_idx else ""

                # Cek buffer
                for buf_name, buf_size in buffers.items():
                    if dst == buf_name or dst.startswith(buf_name + "["):
                        # Size check
                        if size_arg.isdigit():
                            sz = int(size_arg)
                            if sz > buf_size:
                                findings.append({
                                    "cat": "BUFFER_OVERFLOW",
                                    "func": fn["name"],
                                    "line": fn["start_line"] + body[:m.start()].count("\n"),
                                    "desc": f"{call_name}() baca {sz} byte ke {buf_name}[{buf_size}] (OVERFLOW {sz - buf_size})",
                                    "code": m.group(0)[:150],
                                    "confidence": "high",
                                })
                        elif "sizeof" in size_arg and buf_name in size_arg:
                            # sizeof(buf) — overflow!
                            findings.append({
                                "cat": "BUFFER_OVERFLOW",
                                "func": fn["name"],
                                "line": fn["start_line"] + body[:m.start()].count("\n"),
                                "desc": f"{call_name}(..., sizeof({buf_name})) — tidak ada room untuk NUL",
                                "code": m.group(0)[:150],
                                "confidence": "high",
                            })
                        elif "sizeof" in size_arg and "-1" in size_arg:
                            pass  # aman

        # Unsafe functions
        for fname, desc in C_UNSAFE_FUNC.items():
            for m in re.finditer(rf"\b{fname}\s*\(([^;]{{0,200}})\)", body):
                args = m.group(1)
                # Cek apakah ada limit di format string (scanf dengan %Ns)
                if fname == "scanf":
                    if not re.search(r"%\d+s", args):
                        findings.append({
                            "cat": "BUFFER_OVERFLOW",
                            "func": fn["name"],
                            "line": fn["start_line"] + body[:m.start()].count("\n"),
                            "desc": f"scanf tanpa width — overflow",
                            "code": m.group(0)[:150],
                            "confidence": "high",
                        })
                else:
                    # Cek arg pertama (dst) apakah buffer
                    arg1 = args.split(",")[0].strip()
                    for buf_name, buf_size in buffers.items():
                        if arg1 == buf_name:
                            findings.append({
                                "cat": "BUFFER_OVERFLOW",
                                "func": fn["name"],
                                "line": fn["start_line"] + body[:m.start()].count("\n"),
                                "desc": f"{fname}() ke {buf_name}[{buf_size}] — {desc}",
                                "code": m.group(0)[:150],
                                "confidence": "high",
                            })

        # Format string
        for fname in C_FORMAT_FUNCS:
            for m in re.finditer(rf"\b{fname}\s*\(([^;]{{0,200}})\)", body):
                args = m.group(1)
                # Cek arg ke-2 (format) — kalau bukan literal string → vuln
                parts = re.split(r",(?![^()]*\))", args)
                fmt_idx = 1 if fname in ("fprintf", "snprintf", "sprintf") else 0
                if len(parts) > fmt_idx:
                    fmt = parts[fmt_idx].strip()
                    # Literal kalau mulai dengan "
                    if not fmt.startswith('"') and not fmt.startswith("L\""):
                        # Cek kalau variable
                        if re.match(r"^\w+$", fmt):
                            findings.append({
                                "cat": "FORMAT_STRING",
                                "func": fn["name"],
                                "line": fn["start_line"] + body[:m.start()].count("\n"),
                                "desc": f"{fname}({fmt}) — format string dari variable",
                                "code": m.group(0)[:150],
                                "confidence": "high",
                            })

        # CMDi
        for fname in C_CMD_FUNCS:
            for m in re.finditer(rf"\b{fname}\s*\(([^;]{{0,200}})\)", body):
                args = m.group(1)
                arg1 = args.split(",")[0].strip()
                if not arg1.startswith('"'):
                    findings.append({
                        "cat": "CMD_INJECTION",
                        "func": fn["name"],
                        "line": fn["start_line"] + body[:m.start()].count("\n"),
                        "desc": f"{fname}({arg1[:40]}) — command dari variable",
                        "code": m.group(0)[:150],
                        "confidence": "medium",
                    })

    # ---- Win-like functions ----
    win_funcs = [f for f in funcs if any(k in f["name"].lower()
                                          for k in ("win","flag","shell","secret","admin"))]

    return {
        "src": src,
        "funcs": [{"name": f["name"], "args": f["args"], "line": f["start_line"]} for f in funcs],
        "win_funcs": [f["name"] for f in win_funcs],
        "findings": findings,
        "size": len(src),
    }

# ====================================================================
# BINARY ANALYSIS
# ====================================================================
def run(cmd, timeout=8):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL,
                                        timeout=timeout).decode(errors="ignore")
    except:
        return ""

def analyze_binary(path):
    out = {"path": path}
    out["file"]    = run(f"file {path}").strip()
    out["type"]    = run(f"readelf -h {path} 2>/dev/null | grep 'Type:'").strip()
    out["sec"]     = run(f"readelf -l {path} 2>/dev/null | grep -E 'GNU_STACK|GNU_RELRO'").strip()
    out["dynamic"] = "DYN" in out["type"]

    # Symbols
    syms = run(f"readelf -s {path} 2>/dev/null | grep -E 'FUNC\\s+\\w+\\s+\\w+'")
    addrs = {}
    for line in syms.split("\n"):
        m = re.search(r"([0-9a-f]+)\s+\d+\s+FUNC\s+\w+\s+\w+\s+(\w+)", line)
        if m:
            addrs[m.group(2)] = "0x" + m.group(1)
    out["addresses"] = addrs

    # Stack frame vuln
    vuln_disasm = run(f"objdump -d {path} 2>/dev/null | awk '/<vuln>:/{{flag=1}} flag{{print}} /ret/&&flag{{exit}}'")
    out["vuln_disasm"] = vuln_disasm[:2000]

    m = re.search(r"sub\s+\$0x([0-9a-f]+),%rsp", vuln_disasm)
    if m:
        sf = int(m.group(1), 16)
        out["stack_frame"] = sf
        out["offset"] = sf + 8

    # Win disasm
    out["win_disasm"] = run(f"objdump -d {path} 2>/dev/null | grep -A10 '<win>:'")[:800]

    # Security
    out["nx"]     = "GNU_STACK" in out["sec"] and "RWE" in out["sec"]
    out["canary"] = "__stack_chk_fail" in run(f"readelf -s {path} 2>/dev/null")
    out["pie"]    = "DYN" in out["type"]

    # PLT
    out["plt"] = run(f"objdump -d {path} 2>/dev/null | grep '@plt>' | head -15")

    # Gadgets (common)
    gadgets = {}
    for g in ["pop %rdi", "pop %rsi", "pop %rdx", "pop %rax", "syscall", "ret$"]:
        r = run(f"objdump -d {path} 2>/dev/null | grep -E '{g}' | head -1")
        if r.strip():
            m = re.match(r"\s*([0-9a-f]+):", r)
            if m:
                gadgets[g] = "0x" + m.group(1)
    out["gadgets"] = gadgets

    # Strings flag
    out["flag_strings"] = run(f"strings {path} | grep -iE 'flag|/bin/sh' | head -5").strip()

    return out

# ====================================================================
# MAIN
# ====================================================================
def find_files():
    out = {"py": [], "c": [], "elf": []}
    for pat in ["/app/**/*.py", "/srv/**/*.py", "/opt/**/*.py", "/home/**/*.py", "/root/**/*.py"]:
        out["py"] += glob.glob(pat, recursive=True)
    for pat in ["/app/**/*.c", "/srv/**/*.c", "/opt/**/*.c", "/home/**/*.c"]:
        out["c"] += glob.glob(pat, recursive=True)
    for pat in ["/app/chall*", "/srv/chall*", "/opt/chall*", "/chall", "/challenge/chall*"]:
        for f in glob.glob(pat, recursive=True):
            if os.path.isfile(f) and os.access(f, os.X_OK):
                out["elf"].append(f)
    # Dedup
    for k in out:
        out[k] = sorted(set(out[k]))
    return out

def main():
    log = []
    def p(s=""):
        print(s)
        log.append(s)

    p("=" * 70)
    p("  RECON PRO — AST taint analysis + C stateful parse")
    p("=" * 70)

    files = find_files()
    p(f"\n[*] Files:")
    p(f"    Python: {len(files['py'])}")
    p(f"    C:      {len(files['c'])}")
    p(f"    ELF:    {len(files['elf'])}")

    report = {"py": {}, "c": {}, "bin": {}, "raw": {}}
    all_findings = []

    # ---- Python ----
    for path in files["py"]:
        p(f"\n{'='*70}")
        p(f"  PYTHON: {path}")
        p('='*70)
        res = analyze_python(path)
        if "error" in res:
            p(f"[!] {res['error']}"); continue

        report["py"][path] = {k: v for k, v in res.items() if k != "src"}
        report["raw"][path] = res["src"]

        if res["endpoints"]:
            p(f"\n[ENDPOINTS]")
            for e in res["endpoints"]: p(f"  {e}")
        if res["fields"]:
            p(f"\n[FIELDS]")
            for f in res["fields"]: p(f"  {f}")
        if res["imports"]:
            p(f"\n[IMPORTS]")
            p(f"  {', '.join(res['imports'][:15])}")
        if res["assigns"]:
            p(f"\n[KEY/SECRET ASSIGN]")
            for name, info in res["assigns"].items():
                flag = " ⚠️  HARDCODED" if info["hardcoded"] else ""
                p(f"  {name} = {info['value'][:60]}{flag}")

        if res["findings"]:
            p(f"\n[FINDINGS] ({len(res['findings'])})")
            for f in res["findings"]:
                p(f"  [{f['cat']:25}] line {f['line']:4} [{f['confidence']}]")
                p(f"    {f['desc']}")
                p(f"    → {f['code']}")
                all_findings.append({"file": path, **f})
        else:
            p(f"\n[FINDINGS] none")

        p(f"\n[SOURCE] ({res['size']} bytes)")
        for i, line in enumerate(res["src"].split("\n")[:150], 1):
            p(f"  {i:4}| {line}")

    # ---- C ----
    for path in files["c"]:
        p(f"\n{'='*70}")
        p(f"  C: {path}")
        p('='*70)
        res = c_parse(path)
        if "error" in res:
            p(f"[!] {res['error']}"); continue

        report["c"][path] = {k: v for k, v in res.items() if k != "src"}
        report["raw"][path] = res["src"]

        if res["funcs"]:
            p(f"\n[FUNCTIONS]")
            for f in res["funcs"]:
                marker = " 🎯" if f["name"] in res.get("win_funcs", []) else ""
                p(f"  {f['name']}({f['args']})  line {f['line']}{marker}")

        if res["findings"]:
            p(f"\n[FINDINGS] ({len(res['findings'])})")
            for f in res["findings"]:
                p(f"  [{f['cat']:18}] func={f['func']:15} line {f['line']:4} [{f['confidence']}]")
                p(f"    {f['desc']}")
                p(f"    → {f['code']}")
                all_findings.append({"file": path, **f})
        else:
            p(f"\n[FINDINGS] none")

        p(f"\n[SOURCE] ({res['size']} bytes)")
        for i, line in enumerate(res["src"].split("\n")[:150], 1):
            p(f"  {i:4}| {line}")

    # ---- Binary ----
    for path in files["elf"]:
        p(f"\n{'='*70}")
        p(f"  BINARY: {path}")
        p('='*70)
        info = analyze_binary(path)
        report["bin"][path] = info

        p(f"\n[FILE] {info['file']}")
        p(f"[TYPE] {info['type']}  PIE={info['pie']}  NX={'on' if info['nx'] else 'off'}  Canary={info['canary']}")

        if info.get("addresses"):
            p(f"\n[SYMBOLS]")
            for n, a in info["addresses"].items():
                marker = " 🎯" if any(k in n.lower() for k in ("win","flag","shell","admin")) else ""
                p(f"  {n:25} {a}{marker}")

        if info.get("stack_frame"):
            p(f"\n[STACK FRAME]")
            p(f"  buffer: {info['stack_frame']} bytes")
            p(f"  offset: {info['offset']} (+ saved RBP)")

        if info.get("gadgets"):
            p(f"\n[GADGETS]")
            for g, a in info["gadgets"].items():
                p(f"  {g:12} {a}")

        if info.get("flag_strings"):
            p(f"\n[FLAG STRINGS]")
            for l in info["flag_strings"].split("\n")[:5]:
                p(f"  {l}")

        if info.get("vuln_disasm"):
            p(f"\n[VULN DISASM]")
            for l in info["vuln_disasm"].split("\n")[:25]:
                p(f"  {l}")

    # ---- Save ----
    with open(REPORT_TXT, "w") as f:
        f.write("\n".join(log))

    with open(REPORT_JSON, "w") as f:
        json.dump({"report": report, "findings": all_findings, "raw": report["raw"]},
                  f, indent=2, default=str)

    p(f"\n{'='*70}")
    p(f"  SUMMARY")
    p('='*70)
    p(f"  Total findings: {len(all_findings)}")
    for f in all_findings:
        p(f"    [{f['cat']:20}] {f['file']}:{f.get('line','?')} — {f['desc'][:80]}")
    p(f"\n  Saved: {REPORT_TXT}, {REPORT_JSON}")
    p(f"  Kirim file ke AI buat bikin exploit")

if __name__ == "__main__":
    main()
