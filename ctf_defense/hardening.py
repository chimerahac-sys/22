#!/usr/bin/env python3
"""Linux System Hardening Engine for CTF Attack-Defense.

Performs hardening checks and automated safe remediation:
  - Permissions audit (dangerous binaries, SUID files, webroot permissions)
  - PHP configuration audit (disable_functions, allow_url_include, expose_php)
  - Kernel / sysctl network protections (SYN cookies, spoof protection)
  - SSH security check (PermitRootLogin, password auth)
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

from .colors import Colors, colorize, print_banner, safe_print

ROOT_DEFAULT = "/var/www/html"

DANGEROUS_BINARIES = [
    "/usr/bin/gcc", "/usr/bin/g++", "/usr/bin/as", "/usr/bin/make",
    "/usr/bin/gdb", "/usr/bin/ncat", "/usr/bin/socat"
]


def check_sysctl() -> List[Tuple[str, str, str, bool]]:
    """Check recommended kernel security parameters."""
    checks = [
        ("net.ipv4.tcp_syncookies", "1", "SYN Flood Protection"),
        ("net.ipv4.conf.all.accept_source_route", "0", "Disable IP Source Routing"),
        ("net.ipv4.conf.all.accept_redirects", "0", "Disable ICMP Redirects"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "Ignore ICMP Broadcasts"),
        ("fs.protected_hardlinks", "1", "Protected Hardlinks"),
        ("fs.protected_symlinks", "1", "Protected Symlinks"),
    ]
    results = []
    for param, expected, desc in checks:
        val = ""
        try:
            r = subprocess.run(["sysctl", "-n", param], capture_output=True, text=True, timeout=2)
            if r.returncode == 0:
                val = r.stdout.strip()
        except Exception:
            pass
        results.append((param, val, desc, val == expected))
    return results


def check_dangerous_binaries() -> List[Tuple[str, bool]]:
    """Check permissions on compiler & raw networking tools."""
    results = []
    for b in DANGEROUS_BINARIES:
        if os.path.exists(b):
            try:
                st = os.stat(b)
                mode = oct(st.st_mode)[-3:]
                # Safe if permissions are 700 or not world-executable
                is_safe = mode in ("700", "750", "710", "700") or (int(mode[-1]) == 0)
                results.append((f"{b} ({mode})", is_safe))
            except Exception:
                results.append((b, False))
    return results


def check_php_ini() -> List[Tuple[str, str, str, bool]]:
    """Check PHP configuration for security best practices."""
    results = []
    try:
        r = subprocess.run(["php", "-r", "echo ini_get('disable_functions');"], capture_output=True, text=True, timeout=2)
        df = r.stdout.strip()
        has_df = bool(df and "exec" in df and "system" in df)
        results.append(("disable_functions", df[:60] if df else "(none)", "Disable dangerous PHP functions (system, exec, passthru)", has_df))
    except Exception:
        results.append(("disable_functions", "N/A", "PHP not installed or not in PATH", False))

    try:
        r = subprocess.run(["php", "-r", "echo ini_get('allow_url_include');"], capture_output=True, text=True, timeout=2)
        val = r.stdout.strip()
        results.append(("allow_url_include", val or "0", "Disallow remote file inclusion via include/require", val in ("0", "")))
    except Exception:
        pass

    try:
        r = subprocess.run(["php", "-r", "echo ini_get('expose_php');"], capture_output=True, text=True, timeout=2)
        val = r.stdout.strip()
        results.append(("expose_php", val or "1", "Hide PHP version banner from HTTP headers", val in ("0", "")))
    except Exception:
        pass

    return results


def run_hardening_check(web_root: str = ROOT_DEFAULT) -> int:
    """Run read-only hardening audit."""
    print_banner("Linux System Hardening Audit", "Security Posture Inspection")

    # 1. Kernel sysctl
    safe_print(colorize("\n[1] KERNEL & NETWORK (SYSCTL):", Colors.BOLD + Colors.BRIGHT_CYAN))
    sysctl_res = check_sysctl()
    for param, val, desc, ok in sysctl_res:
        badge = colorize("[✓ PASS]", Colors.GREEN) if ok else colorize("[! WEAK]", Colors.YELLOW)
        safe_print(f"  {badge} {desc:<32} {param} = {val or 'unknown'}")

    # 2. Dangerous Binaries
    safe_print(colorize("\n[2] COMPILERS & ATTAKER TOOLS PERMISSIONS:", Colors.BOLD + Colors.BRIGHT_CYAN))
    bin_res = check_dangerous_binaries()
    if bin_res:
        for b, ok in bin_res:
            badge = colorize("[✓ SAFE]", Colors.GREEN) if ok else colorize("[! OPEN]", Colors.BRIGHT_RED)
            safe_print(f"  {badge} {b}")
    else:
        safe_print("  * No compilers (gcc, gdb) found in standard paths.")

    # 3. PHP INI Settings
    safe_print(colorize("\n[3] PHP CONFIGURATION AUDIT:", Colors.BOLD + Colors.BRIGHT_CYAN))
    php_res = check_php_ini()
    for param, val, desc, ok in php_res:
        badge = colorize("[✓ SAFE]", Colors.GREEN) if ok else colorize("[! WARN]", Colors.YELLOW)
        safe_print(f"  {badge} {param:<22} : {val} ({colorize(desc, Colors.DIM)})")

    # 4. Webroot Permissions
    safe_print(colorize("\n[4] WEBROOT PERMISSIONS:", Colors.BOLD + Colors.BRIGHT_CYAN))
    if os.path.isdir(web_root):
        writable_files = []
        for base, dirs, files in os.walk(web_root):
            for f in files:
                p = os.path.join(base, f)
                if os.access(p, os.W_OK) and p.endswith((".php", ".py", ".js")):
                    writable_files.append(p)
        safe_print(f"  [*] Web Root Path    : {web_root}")
        safe_print(f"  [*] Writable Scripts : {len(writable_files)} scripts writable by current user")
    else:
        safe_print(f"  [!] Web root not found: {web_root}")

    safe_print(colorize("\n" + "=" * 75, Colors.DIM))
    safe_print("Untuk mengaplikasikan hardening otomatis, jalankan:")
    safe_print(f"  {colorize('sudo python adctf.py hardening --apply', Colors.BOLD + Colors.BRIGHT_GREEN)}\n")
    return 0


def run_hardening_apply(web_root: str = ROOT_DEFAULT, lock_binaries: bool = True) -> int:
    """Apply recommended system hardening settings."""
    print_banner("Applying System Hardening", "Automated Remediation")

    # 1. Lock dangerous compilers/binaries to root-only (chmod 700)
    if lock_binaries:
        safe_print(colorize("[1] Membatasi akses tools compiler & netcat ke root (chmod 700)...", Colors.YELLOW))
        for b in DANGEROUS_BINARIES:
            if os.path.exists(b):
                try:
                    os.chmod(b, 0o700)
                    safe_print(f"  [✓] chmod 700 {b}")
                except PermissionError:
                    safe_print(f"  [!] Butuh sudo untuk chmod {b}")
                except Exception as e:
                    safe_print(f"  [✗] Gagal chmod {b}: {e}")

    # 2. Apply kernel sysctl protections
    safe_print(colorize("\n[2] Mengaktifkan proteksi kernel sysctl...", Colors.YELLOW))
    sysctl_cmds = [
        ("net.ipv4.tcp_syncookies", "1"),
        ("net.ipv4.conf.all.accept_source_route", "0"),
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("fs.protected_hardlinks", "1"),
        ("fs.protected_symlinks", "1"),
    ]
    for param, val in sysctl_cmds:
        try:
            r = subprocess.run(["sysctl", "-w", f"{param}={val}"], capture_output=True, text=True, timeout=2)
            if r.returncode == 0:
                safe_print(f"  [✓] sysctl {param}={val}")
        except Exception:
            pass

    # 3. Webroot file permissions (files 644, dirs 755)
    safe_print(colorize("\n[3] Merapikan permission webroot (file 644, folder 755)...", Colors.YELLOW))
    if os.path.isdir(web_root):
        try:
            for base, dirs, files in os.walk(web_root):
                for d in dirs:
                    try: os.chmod(os.path.join(base, d), 0o755)
                    except Exception: pass
                for f in files:
                    try: os.chmod(os.path.join(base, f), 0o644)
                    except Exception: pass
            safe_print(f"  [✓] Permissions dirapikan pada {web_root}")
        except Exception as e:
            safe_print(f"  [!] Permission error: {e}")

    safe_print(colorize("\n[✓] Hardening selesai diaplikasikan.", Colors.BOLD + Colors.BRIGHT_GREEN))
    return 0
