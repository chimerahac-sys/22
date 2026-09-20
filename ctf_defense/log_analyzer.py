#!/usr/bin/env python3
"""Advanced Log & Traffic Analyzer (Real-Time Monitoring).

Reads Nginx/Apache web server logs in real-time, inspects URIs and payloads with
multi-stage decoding, classifies malicious signatures (RCE, LFI, SQLi, Backdoors),
and outputs structured ANSI color logs while persisting captured attack payloads.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, Generator, List, Optional, Set, Tuple

from .colors import Colors, colorize, safe_print, print_banner
from .patterns import SIGNATURES, is_benign_static, AttackSignature


# Standard Web Server Log Regex Formats
# 1. Nginx / Apache Combined: 127.0.0.1 - - [22/Aug/2026:20:00:00 +0000] "GET /index.php?id=1 HTTP/1.1" 200 1234 "referer" "user-agent"
COMBINED_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Za-z]+)\s+(?P<uri>[^\s"]+)(?:\s+HTTP/\d\.\d)?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# 2. Apache Common: 127.0.0.1 - user [22/Aug/2026:20:00:00 +0000] "GET / HTTP/1.0" 200 452
COMMON_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Za-z]+)\s+(?P<uri>[^\s"]+)(?:\s+HTTP/\d\.\d)?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
)


class LogEntry:
    """Represents a parsed HTTP web server log line."""

    def __init__(
        self,
        raw_line: str,
        ip: str = "-",
        timestamp: str = "",
        method: str = "GET",
        uri: str = "/",
        status: str = "200",
        user_agent: str = "-",
    ):
        self.raw_line = raw_line.strip()
        self.ip = ip
        self.timestamp = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.method = method.upper()
        self.uri = uri
        self.status = status
        self.user_agent = user_agent

        # Decoded payload and query components
        self.decoded_uri, self.extracted_payload = self._decode_and_extract_payload(self.uri)
        self.matches: List[AttackSignature] = []
        self.is_attack = False
        self.severity = "NORMAL"

    def _decode_and_extract_payload(self, uri: str) -> Tuple[str, str]:
        """Perform multi-layer URL decoding to prevent evasion (e.g. double %252e URL encoding)."""
        current = uri[:4096]  # Safe limit to prevent ReDoS on massive URIs
        for _ in range(3):
            try:
                decoded = urllib.parse.unquote(current)
                if decoded == current:
                    break
                current = decoded
            except Exception:
                break

        # Query-string semantics: '+' = spasi (seperti $_GET PHP). Varian
        # plus-decoded ditambahkan agar evasion 'cat+/flag' tetap terdeteksi.
        plus_decoded = current.replace("+", " ")

        # Extract payload part (query string or path parameters)
        variants = [current]
        if plus_decoded != current:
            variants.append(plus_decoded)

        payloads = []
        for variant in variants:
            if "?" in variant:
                payloads.append(variant.split("?", 1)[1])
            else:
                payloads.append(variant)
        payload = "\n".join(payloads)

        return current, payload


class LogAnalyzer:
    """Core log inspection engine."""

    DEFAULT_LOG_CANDIDATES = [
        "/var/log/nginx/access.log",
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
        "/var/log/nginx/host.access.log",
        "access.log",
    ]

    def __init__(
        self,
        log_path: Optional[str] = None,
        save_file: str = "captured_attacks.jsonl",
        alert_only: bool = False,
        ignore_static: bool = True,
        whitelist_ips: Optional[Set[str]] = None,
    ):
        self.log_path = self.resolve_log_path(log_path)
        self.save_file = Path(save_file)
        self.alert_only = alert_only
        self.ignore_static = ignore_static
        self.whitelist_ips = whitelist_ips or {"127.0.0.1", "::1", "localhost"}
        self.seen_signatures: set = set()
        self.ip_sig_counts: Dict[str, int] = {}
        self._sig_weights = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 1}
        self.stats = {"total": 0, "attacks": 0, "normal": 0, "critical": 0,
                      "ignored_ips": 0, "suspicious": 0}

    @classmethod
    def resolve_log_path(cls, custom_path: Optional[str]) -> Optional[Path]:
        """Find active access log file path."""
        if custom_path:
            p = Path(custom_path)
            if p.exists() or custom_path == "-":
                return p
            safe_print(colorize(f"[!] Specified log file '{custom_path}' not found.", Colors.BRIGHT_YELLOW))
            return None

        for candidate in cls.DEFAULT_LOG_CANDIDATES:
            p = Path(candidate)
            if p.exists() and p.is_file():
                return p
        return None

    def parse_line(self, line: str) -> LogEntry:
        """Parse raw log line into structured LogEntry."""
        line_str = line.strip()[:8192]  # Cap maximum line length for defense against ReDoS
        if not line_str:
            return LogEntry(raw_line="")

        m = COMBINED_LOG_REGEX.match(line_str) or COMMON_LOG_REGEX.match(line_str)
        if m:
            data = m.groupdict()
            return LogEntry(
                raw_line=line_str,
                ip=data.get("ip", "-"),
                timestamp=data.get("time", ""),
                method=data.get("method", "GET"),
                uri=data.get("uri", "/"),
                status=data.get("status", "200"),
                user_agent=data.get("ua", "-"),
            )

        # Fallback heuristic parser for non-standard formats
        parts = line_str.split()
        ip = parts[0] if parts else "-"
        method = "GET"
        uri = "/"
        status = "200"

        for idx, part in enumerate(parts):
            if part.upper() in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
                method = part.upper()
                if idx + 1 < len(parts):
                    uri = parts[idx + 1]
            if part.isdigit() and len(part) == 3 and idx > 2:
                status = part

        return LogEntry(raw_line=line_str, ip=ip, method=method, uri=uri, status=status)

    def analyze_entry(self, entry: LogEntry) -> LogEntry:
        """Inspect entry against attack signatures."""
        if not entry.raw_line:
            return entry

        # Skip whitelisted IPs (e.g. self localhost or scoring SLA bot)
        if entry.ip in self.whitelist_ips:
            self.stats["ignored_ips"] += 1
            return entry

        self.stats["total"] += 1

        # Check for static asset bypass
        if self.ignore_static and is_benign_static(entry.uri) and "?" not in entry.uri:
            # Check if URI explicitly has dangerous sequences anyway
            if not any(seq in entry.uri for seq in ["..", "/etc/", "eval", "flag"]):
                self.stats["normal"] += 1
                return entry

        # Anti-FP two-stage detection:
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

        return entry

    def _save_attack_payload(self, entry: LogEntry) -> None:
        """Persist detected attack payload for incident investigation and replay."""
        sig_ids = [s.id for s in entry.matches]
        sig_key = f"{entry.ip}:{entry.method}:{entry.decoded_uri}"

        # Save to JSONL for automated tools / replay engines
        record = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": entry.ip,
            "method": entry.method,
            "uri": entry.uri,
            "decoded_uri": entry.decoded_uri,
            "payload": entry.extracted_payload,
            "status": entry.status,
            "severity": entry.severity,
            "signatures": sig_ids,
            "raw": entry.raw_line,
        }

        try:
            with open(self.save_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            safe_print(colorize(f"[!] Error writing to {self.save_file}: {e}", Colors.RED), file=sys.stderr)

        # Also append to human-readable replay list if unique
        if sig_key not in self.seen_signatures:
            self.seen_signatures.add(sig_key)
            txt_file = self.save_file.with_suffix(".txt")
            try:
                with open(txt_file, "a", encoding="utf-8") as f:
                    f.write(f"# [{datetime.now().strftime('%H:%M:%S')}] {entry.ip} -> [{','.join(sig_ids)}]\n")
                    f.write(f"{entry.method} {entry.uri}\n\n")
            except Exception:
                pass

    def format_terminal_output(self, entry: LogEntry) -> Optional[str]:
        """Generate high-visibility ANSI colored output."""
        if not entry.raw_line:
            return None

        if self.alert_only and not entry.is_attack:
            return None

        ts_formatted = datetime.now().strftime("%H:%M:%S")
        display_uri = entry.uri[:75]
        display_payload = entry.decoded_uri[:75]

        # Formatting
        if entry.is_attack:
            cat_names = ", ".join(dict.fromkeys(s.category for s in entry.matches))
            sev = entry.severity
            box_color = Colors.BRIGHT_RED if sev == "CRITICAL" else Colors.BRIGHT_YELLOW
            header_tag = f"🚨 [SERANGAN TERDETEKSI: {cat_names}]" if sev == "CRITICAL" else f"⚠️  [SERANGAN TERDETEKSI: {cat_names}]"

            # Plain language actionable advice
            clean_endpoint = entry.uri.split("?")[0]
            advice = "Periksa endpoint dan lakukan sanitasi input."
            if "RCE" in cat_names:
                advice = f"Buka file '{clean_endpoint}', hindari system()/eval()/shell=True. Gunakan argument list."
            elif "SQLI" in cat_names:
                advice = f"Buka file '{clean_endpoint}', ganti query concat dengan PDO prepared statement / parameterized query."
            elif "LFI" in cat_names:
                advice = f"Buka file '{clean_endpoint}', tambahkan whitelist array nama file dan gunakan basename()."
            elif "BACKDOOR" in cat_names:
                advice = f"File '{clean_endpoint}' terindikasi webshell! Hapus file ini dari webroot segera."

            card_lines = [
                colorize(f"┌── {header_tag} " + "─" * max(10, 48 - len(cat_names)) + f" [{ts_formatted}] ──", box_color),
                colorize("│", box_color) + f"  🌐 {colorize('Dari IP  :', Colors.BOLD + Colors.WHITE)} {colorize(entry.ip, Colors.BOLD + Colors.BRIGHT_WHITE)} (Lawan)",
                colorize("│", box_color) + f"  🎯 {colorize('Target   :', Colors.BOLD + Colors.WHITE)} {colorize(entry.method, Colors.CYAN)} {colorize(display_uri, Colors.BRIGHT_CYAN)} (HTTP {entry.status})",
                colorize("│", box_color) + f"  💣 {colorize('Payload  :', Colors.BOLD + Colors.WHITE)} {colorize(display_payload, Colors.BRIGHT_RED)}",
            ]
            for sig in entry.matches:
                card_lines.append(colorize("│", box_color) + f"  🔍 {colorize('Deteksi  :', Colors.BOLD + Colors.WHITE)} {sig.name} - {sig.description}")
            card_lines.append(colorize("│", box_color) + f"  💡 {colorize('Tindakan :', Colors.BOLD + Colors.GREEN)} {colorize(advice, Colors.GREEN)}")
            card_lines.append(colorize("└" + "─" * 70, box_color))
            return "\n".join(card_lines)
        else:
            status_color = Colors.GREEN if entry.status.startswith("2") else Colors.DIM
            return f"[{colorize(ts_formatted, Colors.DIM)}] [{colorize('NORMAL', status_color)}] {entry.ip:<15} {entry.method:<4} {display_uri}"

    def tail_stream(self, file_path: Path, follow: bool = True) -> Generator[str, None, None]:
        """Cross-platform zero-dependency real-time file tailing with rotation support."""
        try:
            f = open(file_path, "r", encoding="utf-8", errors="replace")
        except PermissionError:
            safe_print(colorize(f"\n[!] Permission Denied reading {file_path}", Colors.BRIGHT_RED))
            safe_print(colorize("    Fix: Run script with sudo, or run: sudo chmod +r " + str(file_path), Colors.YELLOW))
            return

        try:
            current_inode = os.fstat(f.fileno()).st_ino if hasattr(os, "fstat") else 0
            if follow:
                f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()
                if line:
                    yield line
                else:
                    if not follow:
                        break
                    time.sleep(0.1)

                    # Check for log rotation or truncation
                    try:
                        if file_path.exists():
                            stat_info = file_path.stat()
                            # 1. Check if file was truncated (cleared)
                            if stat_info.st_size < f.tell():
                                f.seek(0, os.SEEK_SET)
                            # 2. Check if file inode changed (logrotate moved old file)
                            elif hasattr(stat_info, "st_ino") and stat_info.st_ino != current_inode:
                                f.close()
                                f = open(file_path, "r", encoding="utf-8", errors="replace")
                                current_inode = os.fstat(f.fileno()).st_ino
                    except Exception:
                        pass
        finally:
            try:
                f.close()
            except Exception:
                pass


def monitor_logs(
    log_path: Optional[str] = None,
    save_file: str = "captured_attacks.jsonl",
    alert_only: bool = False,
    ignore_static: bool = True,
    whitelist_ips: Optional[List[str]] = None,
    follow: bool = True,
) -> None:
    """Run real-time monitoring CLI entrypoint."""
    wl_set = set(whitelist_ips) if whitelist_ips else {"127.0.0.1", "::1", "localhost"}

    analyzer = LogAnalyzer(
        log_path=log_path,
        save_file=save_file,
        alert_only=alert_only,
        ignore_static=ignore_static,
        whitelist_ips=wl_set,
    )

    print_banner("Attack-Defense Real-Time Log Analyzer", "Live Traffic & Attack Signature Monitor")

    if analyzer.log_path is None:
        safe_print(colorize("[!] No valid web server access log found.", Colors.BRIGHT_RED))
        safe_print("    Specify log file path using: --log /path/to/access.log")
        safe_print("    Or feed via standard input: cat access.log | python -m ctf_defense.log_analyzer --stdin")
        sys.exit(1)

    safe_print(f"[*] Target Log File : {colorize(str(analyzer.log_path), Colors.BOLD + Colors.GREEN)}")
    safe_print(f"[*] Payload Dump    : {colorize(str(analyzer.save_file), Colors.BOLD + Colors.CYAN)}")
    safe_print(f"[*] Alert-Only Mode : {colorize('ENABLED' if alert_only else 'DISABLED', Colors.YELLOW)}")
    safe_print(f"[*] Whitelisted IPs : {colorize(', '.join(wl_set), Colors.DIM)}")
    safe_print(f"[*] Signatures Loaded: {colorize(str(len(SIGNATURES)), Colors.BRIGHT_GREEN)} rules active")
    safe_print(colorize("-" * 75, Colors.DIM))
    safe_print(colorize("[*] Listening for incoming requests (Press Ctrl+C to stop)...", Colors.BRIGHT_WHITE))
    safe_print("")

    try:
        if str(analyzer.log_path) == "-":
            for line in sys.stdin:
                entry = analyzer.analyze_entry(analyzer.parse_line(line))
                formatted = analyzer.format_terminal_output(entry)
                if formatted:
                    safe_print(formatted)
                    safe_print("")
        else:
            for line in analyzer.tail_stream(analyzer.log_path, follow=follow):
                entry = analyzer.analyze_entry(analyzer.parse_line(line))
                formatted = analyzer.format_terminal_output(entry)
                if formatted:
                    safe_print(formatted)
                    safe_print("")
    except KeyboardInterrupt:
        safe_print("")
        safe_print(colorize("-" * 75, Colors.DIM))
        safe_print(colorize("[SUMMARY] MONITORING SESSION SUMMARY:", Colors.BOLD + Colors.BRIGHT_CYAN))
        safe_print(f"   * Total Requests Processed : {analyzer.stats['total']}")
        safe_print(f"   * Normal Traffic Requests  : {analyzer.stats['normal']}")
        safe_print(f"   * Attacks Detected         : {colorize(str(analyzer.stats['attacks']), Colors.BRIGHT_RED)}")
        safe_print(f"   * Critical RCE Exploits    : {colorize(str(analyzer.stats['critical']), Colors.BRIGHT_RED + Colors.BOLD)}")
        safe_print(f"   * Suspicious (Anti-FP Hold): {colorize(str(analyzer.stats.get('suspicious', 0)), Colors.YELLOW)}")
        safe_print(f"   * Payloads Saved To        : {analyzer.save_file} and {analyzer.save_file.with_suffix('.txt')}")
        safe_print(colorize("[*] Monitor stopped cleanly.", Colors.GREEN))


def main() -> None:
    parser = argparse.ArgumentParser(description="Real-Time Web Log & Traffic Analyzer for CTF Attack-Defense")
    parser.add_argument("--log", "-l", type=str, default=None, help="Path to access.log (or '-' for stdin)")
    parser.add_argument("--save", "-s", type=str, default="captured_attacks.jsonl", help="Path to save attack payloads")
    parser.add_argument("--alert-only", "-a", action="store_true", help="Display only detected attack requests")
    parser.add_argument("--whitelist", "-w", type=str, default="127.0.0.1,::1", help="Comma-separated whitelisted IPs")
    parser.add_argument("--no-static-filter", action="store_false", dest="ignore_static", help="Do not ignore static asset requests")
    parser.add_argument("--no-follow", action="store_false", dest="follow", help="Process existing log and exit without following")
    parser.add_argument("--stdin", action="store_true", help="Read log lines directly from standard input")

    args = parser.parse_args()
    log_target = "-" if args.stdin else args.log
    wl_ips = [ip.strip() for ip in args.whitelist.split(",") if ip.strip()]

    monitor_logs(
        log_path=log_target,
        save_file=args.save,
        alert_only=args.alert_only,
        ignore_static=args.ignore_static,
        whitelist_ips=wl_ips,
        follow=args.follow,
    )


if __name__ == "__main__":
    main()
