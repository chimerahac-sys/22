#!/usr/bin/env python3
"""End-to-End Automated Defense Pipeline for CTF Attack-Defense.

Executes complete defensive workflow in < 5 seconds:
  1. Environment Detection (Web server, language, web root, database, logs)
  2. Full Emergency Backup (.tar.gz + DB dump + Git baseline commit)
  3. Adaptive System Hardening (Sysctl kernel, compiler permissions, webroot ACLs)
  4. Instant OWASP Top-10 Micro-WAF Auto-Deploy (.user.ini / index.php)
  5. Deep Webshell & Backdoor Sweep
  6. Source Code Vulnerability Scanner (SQLi, RCE, LFI, SSTI, XSS)
  7. SLA Health Verification (Ensures web is 200 OK after hardening)
  8. Executive Tactical Dashboard & Next Action Advisory
"""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from .colors import Colors, colorize, print_banner, safe_print
from .doctor import EnvironmentDoctor
from .backup import run_backup, ROOT_DEFAULT, BACKUP_DEFAULT
from .hardening import run_hardening_apply
from .micro_waf import generate_waf, _detect_web_env
from .webshell_finder import find_webshells
from .scanner import run_scan, DB_DEFAULT, get_db
from .health_checker import HealthChecker


def run_e2e_pipeline(
    web_root: str = ROOT_DEFAULT,
    backup_dir: str = BACKUP_DEFAULT,
    db_path: str = DB_DEFAULT,
    whitelist_ips: Optional[List[str]] = None,
    auto_quarantine_webshells: bool = False,
    start_port: int = 80,
) -> int:
    """Execute all-in-one end-to-end automated defense pipeline."""
    t0 = time.time()
    print_banner("AD-CTF End-to-End Automated Defense", "1-Command Full Host Lockdown & Intelligence")
    safe_print(colorize("[*] Memulai orkestrasi pertahanan menyeluruh (End-to-End Pipeline)...\n", Colors.BOLD + Colors.BRIGHT_WHITE))

    pipeline_status = []

    # ─────────────────────────────────────────────────────────────────────
    # STEP 1: Auto-Detect Environment
    # ─────────────────────────────────────────────────────────────────────
    safe_print(colorize("▶ [1/7] Mendeteksi Environment & Stack Server...", Colors.BOLD + Colors.BRIGHT_CYAN))
    env = _detect_web_env()
    detected_root = env.get("webroot", web_root)
    if not os.path.isdir(detected_root) and os.path.isdir(web_root):
        detected_root = web_root
    elif not os.path.isdir(detected_root) and os.path.isdir("."):
        detected_root = os.path.abspath(".")

    safe_print(f"   ├─ Web Server : {colorize(env['server'].upper(), Colors.GREEN)}")
    safe_print(f"   ├─ Bahasa     : {colorize(env['language'].upper(), Colors.GREEN)}")
    safe_print(f"   └─ Web Root   : {colorize(detected_root, Colors.BOLD + Colors.CYAN)}")
    pipeline_status.append(("Environment Detection", "OK", f"{env['server']} + {env['language']}"))

    # ─────────────────────────────────────────────────────────────────────
    # STEP 2: Backup Webroot, Database & Git Baseline
    # ─────────────────────────────────────────────────────────────────────
    safe_print(colorize("\n▶ [2/7] Mengamankan Backup Webroot, Database & Git Baseline...", Colors.BOLD + Colors.BRIGHT_CYAN))
    try:
        b_res = run_backup(detected_root, backup_dir)
        pipeline_status.append(("Backup & Git Baseline", "OK" if b_res == 0 else "WARN", "Web archive + DB dump saved"))
    except Exception as e:
        safe_print(colorize(f"   [!] Error backup: {e}", Colors.YELLOW))
        pipeline_status.append(("Backup & Git Baseline", "WARN", str(e)))

    # ─────────────────────────────────────────────────────────────────────
    # STEP 3: Adaptive System Hardening
    # ─────────────────────────────────────────────────────────────────────
    safe_print(colorize("\n▶ [3/7] Mengaplikasikan System & Kernel Hardening...", Colors.BOLD + Colors.BRIGHT_CYAN))
    try:
        run_hardening_apply(detected_root, lock_binaries=True)
        pipeline_status.append(("System Hardening", "OK", "Sysctl + Compilers 700 + Permissions 644/755"))
    except Exception as e:
        safe_print(colorize(f"   [!] Hardening warning: {e}", Colors.YELLOW))
        pipeline_status.append(("System Hardening", "WARN", "Partial (run with sudo for full)"))

    # ─────────────────────────────────────────────────────────────────────
    # STEP 4: Auto-Generate & Deploy OWASP Top-10 Micro-WAF
    # ─────────────────────────────────────────────────────────────────────
    safe_print(colorize("\n▶ [4/7] Memasang OWASP Top-10 Micro-WAF (Anti-False-Positive)...", Colors.BOLD + Colors.BRIGHT_CYAN))
    waf_path = "/tmp/ctf_waf.php" if env["language"] != "python" else os.path.join(detected_root, "ctf_waf.py")
    try:
        generate_waf(
            waf_type=env["language"] if env["language"] in ("php", "python") else "php",
            output_path=waf_path,
            webroot=detected_root,
            whitelist_ips=whitelist_ips,
            auto_deploy=True,
        )
        pipeline_status.append(("OWASP Top-10 WAF", "OK", f"Active ({waf_path})"))
    except Exception as e:
        safe_print(colorize(f"   [!] Gagal pasang WAF: {e}", Colors.BRIGHT_RED))
        pipeline_status.append(("OWASP Top-10 WAF", "FAILED", str(e)))

    # ─────────────────────────────────────────────────────────────────────
    # STEP 5: Deep Webshell & Backdoor Sweep
    # ─────────────────────────────────────────────────────────────────────
    safe_print(colorize("\n▶ [5/7] Melakukan Deep Webshell & Backdoor Hunting...", Colors.BOLD + Colors.BRIGHT_CYAN))
    try:
        qdir = os.path.expanduser("~/.adctf/quarantine") if auto_quarantine_webshells else None
        webshells = find_webshells(detected_root, quarantine_dir=qdir)
        if webshells:
            safe_print(colorize(f"   [!] DITEMUKAN {len(webshells)} POTENSI BACKDOOR:", Colors.BOLD + Colors.BRIGHT_RED))
            for ws in webshells[:3]:
                safe_print(f"       • {colorize(ws['path'], Colors.BRIGHT_WHITE)} -> {ws['snippet']}")
            pipeline_status.append(("Webshell Sweep", "ALERT", f"{len(webshells)} backdoor ditemukan!"))
        else:
            safe_print(colorize("   [✓] Webroot bersih dari backdoor terselubung.", Colors.GREEN))
            pipeline_status.append(("Webshell Sweep", "OK", "Clean (0 webshells)"))
    except Exception as e:
        pipeline_status.append(("Webshell Sweep", "WARN", str(e)))

    # ─────────────────────────────────────────────────────────────────────
    # STEP 6: Source Code Vulnerability Scanner
    # ─────────────────────────────────────────────────────────────────────
    safe_print(colorize("\n▶ [6/7] Membedah Celah Source Code (Static Vuln Scanner)...", Colors.BOLD + Colors.BRIGHT_CYAN))
    try:
        run_scan(detected_root, db_path)
        conn = get_db(db_path)
        count = conn.execute("SELECT COUNT(*) FROM patch_state WHERE status_patched=0").fetchone()[0]
        conn.close()
        pipeline_status.append(("Vulnerability Scan", "OK", f"{count} celah tercatat di SQLite"))
    except Exception as e:
        pipeline_status.append(("Vulnerability Scan", "WARN", str(e)))

    # ─────────────────────────────────────────────────────────────────────
    # STEP 7: SLA Health Verification
    # ─────────────────────────────────────────────────────────────────────
    safe_print(colorize("\n▶ [7/7] Memverifikasi Ketersediaan Layanan Web (SLA Check)...", Colors.BOLD + Colors.BRIGHT_CYAN))
    sla_ok = True
    try:
        checker = HealthChecker(targets=["127.0.0.1"], port=start_port, path="/", delay=0.0)
        res = checker.run_all(continuous=False)
        if res and res[0].is_healthy:
            safe_print(colorize(f"   [✓] Web Service UP (HTTP {res[0].status_code}) — SLA 100% AMAN!", Colors.BOLD + Colors.BRIGHT_GREEN))
            pipeline_status.append(("SLA Health Check", "OK", f"HTTP {res[0].status_code} UP"))
        else:
            code = res[0].status_code if res else "DOWN"
            safe_print(colorize(f"   [!] Web Service Status: {code}. Cek konfigurasi webroot!", Colors.BRIGHT_RED))
            pipeline_status.append(("SLA Health Check", "WARN", f"Status: {code}"))
            sla_ok = False
    except Exception as e:
        safe_print(colorize(f"   [!] SLA probe warning: {e}", Colors.YELLOW))
        pipeline_status.append(("SLA Health Check", "WARN", str(e)))

    elapsed = time.time() - t0

    # ─────────────────────────────────────────────────────────────────────
    # EXECUTIVE TACTICAL SUMMARY DASHBOARD
    # ─────────────────────────────────────────────────────────────────────
    safe_print(colorize("\n" + "═" * 75, Colors.BRIGHT_CYAN))
    safe_print(colorize(f" 🛡️  AD-CTF DEFENSIVE READINESS DASHBOARD (Selesai dlm {elapsed:.2f}s)", Colors.BOLD + Colors.BRIGHT_WHITE))
    safe_print(colorize("═" * 75, Colors.BRIGHT_CYAN))

    for name, status, detail in pipeline_status:
        if status == "OK":
            badge = colorize("[✓ SECURED]", Colors.BOLD + Colors.GREEN)
        elif status == "ALERT":
            badge = colorize("[! ALERT  ]", Colors.BG_RED + Colors.BOLD + Colors.WHITE)
        elif status == "WARN":
            badge = colorize("[* WARN   ]", Colors.YELLOW)
        else:
            badge = colorize("[✗ FAILED ]", Colors.BRIGHT_RED)

        safe_print(f" {badge} {name:<26} : {colorize(detail, Colors.BRIGHT_WHITE)}")

    safe_print(colorize("═" * 75, Colors.BRIGHT_CYAN))
    safe_print(colorize("🚀 LANGKAH BERIKUTNYA:", Colors.BOLD + Colors.BRIGHT_YELLOW))
    safe_print(f" 1. {colorize('Jalankan Autopilot (Radar + Auto Replay + Auto Submit):', Colors.BOLD)}")
    safe_print(f"    {colorize('python3 adctf.py autopilot --targets 10.60.1-20.1 --submit-url http://10.0.0.1/api/submit --token TOKEN', Colors.CYAN)}")
    safe_print(f" 2. {colorize('Tambal Celah Source Code Terprioritas:', Colors.BOLD)}")
    safe_print(f"    {colorize('python3 adctf.py next', Colors.CYAN)} (Lihat kode & petunjuk fix) -> edit kode -> {colorize('python3 adctf.py done', Colors.CYAN)}")
    safe_print("")
    return 0
