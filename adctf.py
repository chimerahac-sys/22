#!/usr/bin/env python3
"""AD-CTF Master Battle Station — Unified Attack-Defense Command Line Interface.

Zero-dependency local defense, vulnerability scanner, guided patcher,
OWASP Top-10 Micro-WAF, real-time log sniffer, replay engine, targeted probe,
hardening auditor, firewall builder, webshell hunter, and autonomous copilot.
"""

import argparse
import os
import sys
from pathlib import Path

# Add package root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from ctf_defense.colors import Colors, colorize, print_banner, safe_print
from ctf_defense.doctor import run_doctor
from ctf_defense.triage import run_triage
from ctf_defense.hardening import run_hardening_check, run_hardening_apply
from ctf_defense.firewall import run_firewall_setup
from ctf_defense.webshell_finder import run_webshell_hunter
from ctf_defense.backup import run_backup, run_restore, ROOT_DEFAULT, BACKUP_DEFAULT
from ctf_defense.scanner import run_scan, run_next_patch, run_done_patch, run_list_patches, DB_DEFAULT
from ctf_defense.log_analyzer import monitor_logs
from ctf_defense.health_checker import run_health_checks
from ctf_defense.micro_waf import generate_waf
from ctf_defense.replay_engine import replay_attacks
from ctf_defense.targeted_probe import run_targeted_probe
from ctf_defense.flag_submitter import submit_flags
from ctf_defense.autopilot import run_autopilot, expand_target_ips
from ctf_defense.patch_guides import show_all_patch_guides
from ctf_defense.pipeline import run_e2e_pipeline


def interactive_menu():
    """Render interactive beginner-friendly terminal menu."""
    print_banner("AD-CTF Master Battle Station", "Unified Attack-Defense Framework v3.2")
    safe_print("Pilih mode eksekusi:")
    safe_print(colorize("  [ENTER / 1] ⚡ 1-COMMAND AUTO-DEFENSE (Full End-to-End: Backup + Hardening + WAF + Scan + SLA)", Colors.BOLD + Colors.BRIGHT_GREEN))
    safe_print(colorize("  [2]         ★ AUTOPILOT BATTLE MODE (Live Radar + Auto-Reflect Replay + Auto-Submit)", Colors.BOLD + Colors.BRIGHT_CYAN))
    safe_print(colorize("  [3]         🩺 Pre-Flight Doctor & Triage Recon", Colors.YELLOW))
    safe_print(colorize("  [4]         🛡️  Hardening (Sysctl + Compiler Lock 700 + Permissions)", Colors.YELLOW))
    safe_print(colorize("  [5]         🧱 Firewall & UFW Setup (Allow Web/SSH + Whitelist SLA)", Colors.YELLOW))
    safe_print(colorize("  [6]         🕷️  Deep Webshell & Backdoor Hunter", Colors.YELLOW))
    safe_print(colorize("  [7]         🔍 Source Code Vuln Scanner & Guided Patcher", Colors.YELLOW))
    safe_print(colorize("  [8]         📡 Real-Time Log Sniffer & Attack Radar", Colors.YELLOW))
    safe_print(colorize("  [9]         🛡️  OWASP Top-10 Micro-WAF Generator & Deployer", Colors.YELLOW))
    safe_print(colorize("  [10]        ⚡ Exploit Replay ke Subnet Lawan (Multi-Threaded)", Colors.YELLOW))
    safe_print(colorize("  [11]        🎯 Targeted Single-Shot Exploit Probe", Colors.YELLOW))
    safe_print(colorize("  [12]        🚩 Submit Flag Gateway", Colors.YELLOW))
    safe_print(colorize("  [13]        📖 Emergency Code Patching Cheatsheet", Colors.YELLOW))
    safe_print(colorize("  [0]         Keluar", Colors.DIM))
    safe_print(colorize("-" * 75, Colors.DIM))

    try:
        choice = input(f"Pilihan [{colorize('1', Colors.BOLD + Colors.GREEN)}]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        safe_print("\n[STOP] Dibatalkan.")
        return

    if choice in ("", "1", "start", "init", "auto-defend", "defend"):
        run_e2e_pipeline()
    elif choice in ("2", "auto", "autopilot", "*"):
        targets = input("Target subnet musuh (contoh: 10.60.1-20.1): ").strip()
        submit_url = input("URL submit flag game server (kosongkan jika tidak ada): ").strip()
        run_autopilot(targets_spec=targets, submit_url=submit_url if submit_url else None)
    elif choice == "3":
        run_doctor(ROOT_DEFAULT)
        run_triage(ROOT_DEFAULT)
    elif choice == "4":
        run_hardening_check(ROOT_DEFAULT)
    elif choice == "5":
        run_firewall_setup()
    elif choice == "6":
        run_webshell_hunter(ROOT_DEFAULT)
    elif choice == "7":
        run_scan(ROOT_DEFAULT, DB_DEFAULT)
        run_next_patch(DB_DEFAULT)
    elif choice == "8":
        monitor_logs(None, alert_only=False)
    elif choice == "9":
        generate_waf("php", "/tmp/ctf_waf.php", ROOT_DEFAULT, auto_deploy=True)
    elif choice == "10":
        targets = input("Target subnet/IP (e.g. 10.60.1-20.1): ").strip()
        replay_attacks([targets] if targets else ["127.0.0.1"])
    elif choice == "11":
        targets = input("Target subnet/IP (e.g. 10.60.1-20.1): ").strip()
        ep = input("Endpoint (default /): ").strip() or "/"
        param = input("Parameter name (e.g. id): ").strip() or "id"
        payload = input("Payload: ").strip() or "1' UNION SELECT 1,2,3--"
        run_targeted_probe(expand_target_ips(targets) if targets else ["127.0.0.1"], endpoint=ep, param=param, payload=payload)
    elif choice == "12":
        url = input("URL submit flag: ").strip() or "http://10.0.0.1/api/submit_flag"
        submit_flags(url=url)
    elif choice == "13":
        show_all_patch_guides()


def main():
    if len(sys.argv) == 1:
        interactive_menu()
        return 0

    p = argparse.ArgumentParser(
        prog="adctf.py",
        description="AD-CTF Master Battle Station — Unified Attack-Defense Framework v3.2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--db", default=DB_DEFAULT, help="Path to SQLite state database")
    sub = p.add_subparsers(dest="cmd", required=True)

    # 1. start / init / auto-defend / quickstart (FULL END-TO-END PIPELINE)
    x = sub.add_parser("start", aliases=["init", "auto-defend", "defend", "quickstart", "setup"],
                       help="1-Command Full End-to-End Defense Pipeline (Backup + Hardening + WAF + Scan + SLA)")
    x.add_argument("--web-root", default=ROOT_DEFAULT)
    x.add_argument("--backup-dir", default=BACKUP_DEFAULT)
    x.add_argument("--whitelist", default="", help="Comma-separated SLA checker IPs to whitelist")
    x.add_argument("--backup-only", action="store_true", help="Only run backup without the full hardening/WAF chain")
    x.add_argument("--quarantine", action="store_true", help="Auto-quarantine detected webshells")
    x.set_defaults(fn=lambda a: run_backup(a.web_root, a.backup_dir) if a.backup_only else run_e2e_pipeline(
        web_root=a.web_root,
        backup_dir=a.backup_dir,
        db_path=a.db,
        whitelist_ips=[ip.strip() for ip in a.whitelist.split(",") if ip.strip()] if a.whitelist else None,
        auto_quarantine_webshells=a.quarantine,
    ))

    # 2. autopilot
    x = sub.add_parser("autopilot", aliases=["copilot", "auto"], help="All-in-one automated sniffer + replay + submitter")
    x.add_argument("--targets", "-t", default="", help="Opponent IP range (e.g. 10.60.1-20.1)")
    x.add_argument("--submit-url", "-u", default=None, help="Flag submit URL")
    x.add_argument("--token", default=None, help="Team API token")
    x.add_argument("--log", "--log-file", dest="log_file", default=None, help="Path access log")
    x.add_argument("--waf-capture", default="/tmp/waf_captured.jsonl", help="Path to WAF capture file")
    x.add_argument("--port", type=int, default=80, help="Target web port")
    x.add_argument("--threads", type=int, default=10, help="Concurrency threads")
    x.set_defaults(fn=lambda a: run_autopilot(a.targets, a.submit_url, a.token, a.log_file, a.waf_capture, a.port, a.threads, a.db))

    # 3. doctor
    x = sub.add_parser("doctor", aliases=["preflight"], help="Pre-flight host diagnostics & readiness check")
    x.add_argument("--web-root", default=ROOT_DEFAULT)
    x.set_defaults(fn=lambda a: run_doctor(a.web_root))

    # 4. triage
    x = sub.add_parser("triage", aliases=["audit"], help="Rapid 1-second system reconnaissance")
    x.add_argument("--web-root", default=ROOT_DEFAULT)
    x.set_defaults(fn=lambda a: run_triage(a.web_root))

    # 5. hardening
    x = sub.add_parser("hardening", help="System permissions, sysctl, and PHP hardening audit & apply")
    x.add_argument("--web-root", default=ROOT_DEFAULT)
    x.add_argument("--apply", action="store_true", help="Apply hardening fixes automatically (requires sudo)")
    x.set_defaults(fn=lambda a: run_hardening_apply(a.web_root) if a.apply else run_hardening_check(a.web_root))

    # 6. firewall
    x = sub.add_parser("firewall", aliases=["ufw"], help="Setup inbound firewall rules & whitelist SLA game server")
    x.add_argument("--ssh-port", type=int, default=22)
    x.add_argument("--http-port", action="append", type=int, default=[80, 443])
    x.add_argument("--whitelist", default="", help="Comma-separated SLA checker IPs")
    x.add_argument("--subnet", default=None, help="Internal team subnet to allow")
    x.add_argument("--apply", action="store_true", help="Apply UFW rules immediately (requires sudo)")
    x.set_defaults(fn=lambda a: run_firewall_setup(
        a.ssh_port,
        a.http_port,
        [ip.strip() for ip in a.whitelist.split(",") if ip.strip()] if a.whitelist else [],
        a.subnet,
        a.apply
    ))

    # 7. webshell
    x = sub.add_parser("webshell", aliases=["backdoor"], help="Scan webroot for webshells, backdoors & recent modifications")
    x.add_argument("--web-root", default=ROOT_DEFAULT)
    x.add_argument("--recent", type=int, default=None, help="Filter files modified within N minutes")
    x.add_argument("--quarantine", action="store_true", help="Move detected webshells to quarantine directory")
    x.set_defaults(fn=lambda a: run_webshell_hunter(a.web_root, a.recent, a.quarantine))

    # 8. restore
    x = sub.add_parser("restore", help="Emergency backup extraction")
    x.add_argument("--backup-dir", default=BACKUP_DEFAULT)
    x.add_argument("--archive", default=None)
    x.add_argument("--confirm", action="store_true")
    x.set_defaults(fn=lambda a: run_restore(a.backup_dir, a.archive, a.confirm))

    # 9. scan
    x = sub.add_parser("scan", help="Scan source code for vulnerabilities")
    x.add_argument("--web-root", default=ROOT_DEFAULT)
    x.set_defaults(fn=lambda a: run_scan(a.web_root, a.db))

    # 10. next & done & list & patch
    x = sub.add_parser("next", help="Get next priority vulnerability to patch")
    x.set_defaults(fn=lambda a: run_next_patch(a.db))
    x = sub.add_parser("done", help="Mark current vulnerability as patched")
    x.set_defaults(fn=lambda a: run_done_patch(a.db))
    x = sub.add_parser("list", aliases=["status"], help="List patch checklist")
    x.set_defaults(fn=lambda a: run_list_patches(a.db))
    x = sub.add_parser("patch", help="Launch interactive guided patch workflow")
    x.set_defaults(fn=lambda a: run_next_patch(a.db))

    # 11. watch / monitor
    x = sub.add_parser("watch", aliases=["monitor"], help="Real-time log sniffer & attack alert")
    x.add_argument("--log", "--log-file", dest="log_file", default=None)
    x.add_argument("--alert-only", action="store_true")
    x.set_defaults(fn=lambda a: monitor_logs(a.log_file, alert_only=a.alert_only))

    # 12. check / health
    x = sub.add_parser("check", aliases=["health"], help="Health check & SLA verifier")
    x.add_argument("--url", action="append")
    x.add_argument("--base", default="http://127.0.0.1")
    x.add_argument("--endpoint", action="append")
    x.add_argument("--timeout", type=int, default=4)
    x.set_defaults(fn=lambda a: run_health_checks(a.url or [a.base], path=(a.endpoint[0] if a.endpoint else "/"), timeout=a.timeout))

    # 13. attack / replay
    x = sub.add_parser("attack", aliases=["replay"], help="Replay captured attacks against enemy teams")
    x.add_argument("target", nargs="?", default="")
    x.add_argument("--targets", "-t", default="")
    x.add_argument("--port", type=int, default=80)
    x.add_argument("--threads", type=int, default=10)
    x.add_argument("--timeout", type=int, default=3)
    x.add_argument("--delay", type=float, default=0.5, help="Delay between requests to prevent DoS")
    x.add_argument("--attacks", default="captured_attacks.jsonl")
    x.set_defaults(fn=lambda a: replay_attacks(
        [a.targets or a.target] if (a.targets or a.target) else ["127.0.0.1"],
        port=a.port,
        threads=a.threads,
        timeout=a.timeout,
        delay=a.delay,
        attack_file=a.attacks,
    ))

    # 14. probe (targeted manual probe)
    x = sub.add_parser("probe", help="Send sequential safe probe request to enemy subnet")
    x.add_argument("--targets", "-t", required=True, help="Opponent IP range (e.g. 10.60.1-20.1)")
    x.add_argument("--endpoint", "-e", default="/", help="Web endpoint to test")
    x.add_argument("--param", "-p", default="id", help="Vulnerable parameter name")
    x.add_argument("--payload", default="1' UNION SELECT 1,2,3--", help="Exploit payload to send")
    x.add_argument("--method", default="GET", choices=["GET", "POST"])
    x.add_argument("--port", type=int, default=80)
    x.add_argument("--delay", type=float, default=1.5, help="Delay between targets (>=1.0s)")
    x.set_defaults(fn=lambda a: run_targeted_probe(
        expand_target_ips(a.targets),
        endpoint=a.endpoint,
        param=a.param,
        payload=a.payload,
        method=a.method,
        port=a.port,
        delay=a.delay,
    ))

    # 15. submit
    x = sub.add_parser("submit", aliases=["submit-flag"], help="Submit captured flags to Game Server")
    x.add_argument("--url", "-u", default="http://10.0.0.1/api/submit_flag")
    x.add_argument("--token", "-t", default=None)
    x.add_argument("--flag", "-f", default=None)
    x.add_argument("--file", default="captured_flags.txt")
    x.set_defaults(fn=lambda a: submit_flags(url=a.url, token=a.token, flag=a.flag, flag_file=a.file))

    # 16. waf
    x = sub.add_parser("waf", aliases=["waf-gen"], help="Generate Advanced OWASP Top-10 Micro-WAF")
    x.add_argument("--type", choices=["php", "python", "auto"], default="php")
    x.add_argument("--out", default="")
    x.add_argument("--whitelist", default="")
    x.add_argument("--web-root", default=ROOT_DEFAULT)
    x.add_argument("--deploy", action="store_true")
    x.set_defaults(fn=lambda a: generate_waf(
        a.type,
        a.out,
        a.web_root,
        whitelist_ips=[ip.strip() for ip in a.whitelist.split(",") if ip.strip()] if a.whitelist else None,
        auto_deploy=a.deploy,
    ))

    # 17. patch-guide
    x = sub.add_parser("patch-guide", help="Show before-and-after code patch snippets")
    x.add_argument("--category", "-c", default="", help="Filter by category (SQLi, LFI, RCE, SSTI, DESER)")
    x.set_defaults(fn=lambda a: show_all_patch_guides(a.category))

    args = p.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
