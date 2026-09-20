#!/usr/bin/env python3
"""Apply all bug-fixes & anti-false-positive upgrades to adctf_fixed project."""
import pathlib

BASE = pathlib.Path("/mnt/agents/output/adctf_fixed")

PATCHES = []

# ══════════════════════════════════════════════════════════════════════════
# 1. firewall.py — BUG: c.split() merusak quoted comment ufw (log terminal temp)
# ══════════════════════════════════════════════════════════════════════════
PATCHES.append(("firewall.py",
r'''import shutil
import subprocess
import sys''',
r'''import shutil
import shlex
import subprocess
import sys''', 1))

PATCHES.append(("firewall.py",
r'''            subprocess.run(c.split(), check=True, capture_output=True, text=True, timeout=5)''',
r'''            subprocess.run(shlex.split(c), check=True, capture_output=True, text=True, timeout=5)''', 1))

# ══════════════════════════════════════════════════════════════════════════
# 2. scanner.py — BUG: koma sebelum WHERE (SQL syntax error) + anti-FP helpers
# ══════════════════════════════════════════════════════════════════════════
PATCHES.append(("scanner.py",
r'''                    "UPDATE patch_state SET status_patched=1, verified_at=?, WHERE id=?",''',
r'''                    "UPDATE patch_state SET status_patched=1, verified_at=? WHERE id=?",''', 1))

PATCHES.append(("scanner.py",
r'''def run_scan(web_root: str = ROOT_DEFAULT, db_path: str = DB_DEFAULT) -> int:''',
r'''def _line_window(lines: List[str], n: int, radius: int = 3) -> str:
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


def run_scan(web_root: str = ROOT_DEFAULT, db_path: str = DB_DEFAULT) -> int:''', 1))

PATCHES.append(("scanner.py",
r'''                if rx.search(line):
                    if typ == "RCE" and ("shell=False" in line or "subprocess.run([" in line):
                        continue

                    confidence = "HIGH" if typ in ("SQLi", "RCE") else "MEDIUM"''',
r'''                if rx.search(line):
                    if typ == "RCE" and ("shell=False" in line or "subprocess.run([" in line):
                        continue
                    if _is_false_positive(typ, line, _line_window(lines, n)):
                        continue  # Anti-FP: mitigasi sudah ada di sekitar baris ini

                    confidence = "HIGH" if typ in ("SQLi", "RCE") else "MEDIUM"''', 1))

# ══════════════════════════════════════════════════════════════════════════
# 3. autopatch.py — BUG: DESER patch kehilangan ')' (PHP syntax error)
#    + SLA check senyap (tanpa banner spam HealthChecker)
# ══════════════════════════════════════════════════════════════════════════
PATCHES.append(("autopatch.py",
r'''        lambda m: f"unserialize({m.group(1)}, ['allowed_classes' => false]",''',
r'''        lambda m: f"unserialize({m.group(1)}, ['allowed_classes' => false]) // AUTO-PATCHED DESER",''', 1))

PATCHES.append(("autopatch.py",
r'''def apply_safe_autopatch(''',
r'''def _quiet_sla_check(port: int = 80, timeout: float = 2.0) -> bool:
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


def apply_safe_autopatch(''', 1))

PATCHES.append(("autopatch.py",
r'''                # 4. Check SLA health (test if server still responds)
                checker = HealthChecker(targets=["127.0.0.1"], port=port, path="/", timeout=2.0)
                res = checker.run_all(continuous=False)
                if res and not res[0].is_healthy:''',
r'''                # 4. Check SLA health (silent check - no banner spam)
                if not _quiet_sla_check(port):''', 1))

# ══════════════════════════════════════════════════════════════════════════
# 4. log_analyzer.py — ANTI-FP: two-stage scoring engine
# ══════════════════════════════════════════════════════════════════════════
PATCHES.append(("log_analyzer.py",
r'''        self.seen_signatures: set = set()
        self.stats = {"total": 0, "attacks": 0, "normal": 0, "critical": 0, "ignored_ips": 0}''',
r'''        self.seen_signatures: set = set()
        self.ip_sig_counts: Dict[str, int] = {}
        self._sig_weights = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 1}
        self.stats = {"total": 0, "attacks": 0, "normal": 0, "critical": 0,
                      "ignored_ips": 0, "suspicious": 0}''', 1))

PATCHES.append(("log_analyzer.py",
r'''        inspect_target = f"{entry.method} {entry.uri} {entry.decoded_uri} {entry.raw_line}"

        matched_signatures = []
        for sig in SIGNATURES:
            if sig.pattern.search(inspect_target):
                matched_signatures.append(sig)

        if matched_signatures:
            entry.matches = matched_signatures
            entry.is_attack = True

            # Determine highest severity
            severities = [s.severity for s in matched_signatures]
            if "CRITICAL" in severities:
                entry.severity = "CRITICAL"
                self.stats["critical"] += 1
            elif "HIGH" in severities:
                entry.severity = "HIGH"
            elif "MEDIUM" in severities:
                entry.severity = "MEDIUM"
            else:
                entry.severity = "LOW"

            self.stats["attacks"] += 1
            self._save_attack_payload(entry)
        else:
            self.stats["normal"] += 1

        return entry''',
r'''        # Anti-FP two-stage detection:
        #   Stage 1: signature match pada PAYLOAD (uri decoded) -> sinyal kuat (1x weight)
        #   Stage 2: signature hanya pada raw_line (UA/referer) -> sinyal lemah (0.5x)
        payload_target = f"{entry.method} {entry.uri} {entry.decoded_uri}"
        matched_payload = [s for s in SIGNATURES if s.pattern.search(payload_target)]
        matched_raw_only = [s for s in SIGNATURES
                            if s not in matched_payload and s.pattern.search(entry.raw_line)]

        score = sum(self._sig_weights[s.severity] for s in matched_payload)
        score += sum(0.5 for s in matched_raw_only)

        matched_signatures = matched_payload + matched_raw_only
        if matched_signatures:
            entry.matches = matched_signatures

            # Konfirmasi serangan (anti false-positive):
            #   (a) ada sinyal HIGH/CRITICAL pada payload, atau
            #   (b) >= 2 kategori berbeda dalam 1 request, atau
            #   (c) skor total >= 2.5, atau
            #   (d) IP yang sama spam sinyal berulang (>= 3 dalam sesi)
            self.ip_sig_counts[entry.ip] = self.ip_sig_counts.get(entry.ip, 0) + 1
            distinct_cats = {s.category for s in matched_payload}
            confirmed = (
                any(s.severity in ("CRITICAL", "HIGH") for s in matched_payload)
                or len(distinct_cats) >= 2
                or score >= 2.5
                or self.ip_sig_counts[entry.ip] >= 3
            )

            if not confirmed:
                # Sinyal lemah: dicatat untuk analis, TIDAK dihitung serangan & TIDAK direplay
                entry.severity = "SUSPICIOUS"
                self.stats["suspicious"] += 1
                self._save_attack_payload(entry)
                return entry

            entry.is_attack = True
            severities = [s.severity for s in matched_payload] or ["MEDIUM"]
            if "CRITICAL" in severities:
                entry.severity = "CRITICAL"
                self.stats["critical"] += 1
            elif "HIGH" in severities:
                entry.severity = "HIGH"
            elif "MEDIUM" in severities:
                entry.severity = "MEDIUM"
            else:
                entry.severity = "LOW"

            self.stats["attacks"] += 1
            self._save_attack_payload(entry)
        else:
            self.stats["normal"] += 1

        return entry''', 1))

PATCHES.append(("log_analyzer.py",
r'''        safe_print(f"   * Critical RCE Exploits    : {colorize(str(analyzer.stats['critical']), Colors.BRIGHT_RED + Colors.BOLD)}")''',
r'''        safe_print(f"   * Critical RCE Exploits    : {colorize(str(analyzer.stats['critical']), Colors.BRIGHT_RED + Colors.BOLD)}")
        safe_print(f"   * Suspicious (Anti-FP Hold): {colorize(str(analyzer.stats.get('suspicious', 0)), Colors.YELLOW)}")''', 1))

# ══════════════════════════════════════════════════════════════════════════
# 5. webshell_finder.py — ANTI-FP: multi-signal scoring (nama saja TIDAK cukup)
# ══════════════════════════════════════════════════════════════════════════
PATCHES.append(("webshell_finder.py",
r''']


def find_webshells(''',
r''']


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


def find_webshells(''', 1))

PATCHES.append(("webshell_finder.py",
r'''            matches = []
            for sev, rx, desc in WEBSHELL_PATTERNS:
                m = rx.search(content)
                if m:
                    matches.append((sev, desc, m.group(0)[:60]))

            if matches or is_hidden or is_suspicious_name:
                sev = "CRITICAL" if any(x[0] == "CRITICAL" for x in matches) else ("HIGH" if any(x[0] == "HIGH" for x in matches) else "MEDIUM")
                findings.append({
                    "path": path,
                    "filename": fname,
                    "severity": sev,
                    "is_hidden": is_hidden,
                    "mins_ago": mins_ago,
                    "matches": matches,
                    "snippet": matches[0][2] if matches else (fname if is_hidden else "Suspicious extension"),
                })''',
r'''            matches = []
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
                })''', 1))

PATCHES.append(("webshell_finder.py",
r'''            # Skip core files from automatic quarantine to prevent SLA disaster
            if fname in PROTECTED_CORE_FILES:''',
r'''            # Anti-FP: hanya karantina temuan yang yakin (CRITICAL / skor >= 5)
            if item.get("severity") != "CRITICAL" and (item.get("score") or 0) < 5:
                item["quarantined"] = "SKIPPED (Confidence insufficient - manual review)"
                continue

            # Skip core files from automatic quarantine to prevent SLA disaster
            if fname in PROTECTED_CORE_FILES:''', 1))

PATCHES.append(("webshell_finder.py",
r'''        safe_print(f"\n {badge} {colorize(f['path'], Colors.BOLD + Colors.BRIGHT_WHITE)} (Diubah {f['mins_ago']:.1f} mnt lalu)")''',
r'''        safe_print(f"\n {badge} {colorize(f['path'], Colors.BOLD + Colors.BRIGHT_WHITE)} (Diubah {f['mins_ago']:.1f} mnt lalu | Skor {f.get('score', '?')})")''', 1))

# ══════════════════════════════════════════════════════════════════════════
# 6. health_checker.py — ANTI-FP: pattern ketat + validasi entropi token
# ══════════════════════════════════════════════════════════════════════════
PATCHES.append(("health_checker.py",
r'''    DEFAULT_FLAG_PATTERNS = [
        r"FLAG\{[A-Za-z0-9_\-]{16,64}\}",
        r"flag\{[A-Za-z0-9_\-]{16,64}\}",
        r"CTF\{[A-Za-z0-9_\-]{16,64}\}",
        r"[A-Za-z0-9]{32}=",
    ]''',
r'''    DEFAULT_FLAG_PATTERNS = [
        # Known CTF prefixes only - broad wildcard dihapus untuk anti false-positive
        r"(?:FLAG|flag|CTF|ctf|JCSC|jcsc|HTB|picoCTF|SKR|COMPFEST|JOINTS|CF|UTCTF|ictf)\{[A-Za-z0-9_\-]{8,96}\}",
    ]

    @staticmethod
    def _token_quality(token: str) -> bool:
        """Anti false-positive: validasi entropi & format sebelum menyimpan token."""
        import math
        from collections import Counter
        if len(token) < 12:
            return False
        low = token.lower()
        if any(x in low for x in ("stylesheet", "javascript", "doctype", "bootstrap", "jquery", "template")):
            return False
        counts = Counter(token)
        n = len(token)
        entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
        return entropy >= 3.2  # token acak = entropi tinggi; teks biasa lebih rendah''', 1))

PATCHES.append(("health_checker.py",
r'''                for m in matches:
                    token_val = m if isinstance(m, str) else m[0]
                    if token_val not in extracted:
                        extracted.append(token_val)''',
r'''                for m in matches:
                    token_val = m if isinstance(m, str) else m[0]
                    if token_val not in extracted and self._token_quality(token_val):
                        extracted.append(token_val)''', 1))

# ══════════════════════════════════════════════════════════════════════════
# 7. patterns.py — ANTI-FP: FLAG_REGEX tanpa wildcard prefix
# ══════════════════════════════════════════════════════════════════════════
PATCHES.append(("patterns.py",
r'''FLAG_REGEX = re.compile(r"(?:FLAG|flag|CTF|ctf|JCSC|jcsc|CYBER|cyber|[A-Za-z0-9_]{3,10})\{[A-Za-z0-9_\-\.\=\+\$]{8,96}\}")''',
r'''# Known CTF flag prefixes saja - wildcard [A-Za-z0-9_]{3,10} dihapus (sumber FP besar:
# men-match teks seperti test{...} / data{...} di JSON & HTML biasa)
KNOWN_FLAG_PREFIXES = r"(?:FLAG|flag|CTF|ctf|JCSC|jcsc|HTB|picoCTF|SKR|COMPFEST|JOINTS|CF|UTCTF|ictf|CYBER|cyber)"
FLAG_REGEX = re.compile(KNOWN_FLAG_PREFIXES + r"\{[A-Za-z0-9_\-\.\=\+\$!@#%]{8,96}\}")''', 1))

# ══════════════════════════════════════════════════════════════════════════
# 8. micro_waf.py — fix duplicate import di template Python + html.unescape
# ══════════════════════════════════════════════════════════════════════════
PATCHES.append(("micro_waf.py",
r'''import urllib.parse

RULES = [''',
r'''import html
import urllib.parse

RULES = [''', 1))

PATCHES.append(("micro_waf.py",
r'''import json
import os
import re
import urllib.parse
from datetime import datetime
import os
import re
import urllib.parse
from datetime import datetime''',
r'''import html
import json
import os
import re
import urllib.parse
from datetime import datetime''', 1))

PATCHES.append(("micro_waf.py",
r'''    decoded = decoded.replace("\x00", "").replace("\\", "/")
    return decoded''',
r'''    decoded = html.unescape(decoded)
    return decoded.replace("\x00", "").replace("\\", "/")''', 2))


def main() -> None:
    applied = 0
    for rel, old, new, expected in PATCHES:
        path = BASE / rel
        text = path.read_text(encoding="utf-8")
        count = text.count(old)
        if count != expected:
            print(f"[FAIL] {rel}: expected {expected}x, found {count}x -- patch skipped!")
            print("---- old snippet ----")
            print(old[:300])
            continue
        path.write_text(text.replace(old, new), encoding="utf-8")
        applied += 1
        print(f"[OK]   {rel}  ({count}x)")
    print(f"\nTotal: {applied}/{len(PATCHES)} patch terpasang.")


if __name__ == "__main__":
    main()
