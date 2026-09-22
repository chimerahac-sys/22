#!/usr/bin/env python3
"""AD-CTF Master Battle Station — Unified Attack-Defense Command Line Interface.

Zero-dependency local defense, vulnerability scanner, guided patcher,
OWASP Top-10 Micro-WAF, real-time log sniffer, replay engine, targeted probe,
hardening auditor, firewall builder, webshell hunter, 1-click autopatcher, and autonomous copilot.

MODIFIED FOR JCC 2026 (Jatim Cybersecurity Competition):
- Compliant with Attack-Defense format rules
- No automated scanners (sqlmap, burp, dirb) - manual probing only
- WireGuard VPN integration for target access
- JCC API endpoint support for flag submission
- SSH-based patching workflow
- Service management via make commands
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
from ctf_defense.autopatch import apply_safe_autopatch
from ctf_defense.log_analyzer import monitor_logs
from ctf_defense.health_checker import run_health_checks
from ctf_defense.micro_waf import generate_waf
from ctf_defense.replay_engine import replay_attacks
from ctf_defense.targeted_probe import run_targeted_probe
from ctf_defense.flag_submitter import submit_flags
from ctf_defense.autopilot import run_autopilot, expand_target_ips
from ctf_defense.patch_guides import show_all_patch_guides
from ctf_defense.pipeline import run_e2e_pipeline
from ctf_defense.exploit_payloads import print_payload_summary, get_payloads_for_category, ALL_PAYLOADS


def interactive_menu():
    """Render interactive beginner-friendly terminal menu."""
    print_banner("AD-CTF Master Battle Station", "JCC 2026 Edition - Attack Defense Framework v4.0")
    safe_print(colorize("⚠️  PENTING: Dilarang menggunakan automated scanner (sqlmap, burp, dirb)!", Colors.BG_RED + Colors.BOLD + Colors.WHITE))
    safe_print(colorize("   Gunakan hanya manual probing dan LLM Web (Free/Paid) sesuai aturan JCC 2026.\n", Colors.YELLOW))
    safe_print("Pilih mode eksekusi:")
    safe_print(colorize("  [ENTER / 1] ⚡ 1-COMMAND AUTO-DEFENSE (Full End-to-End: Backup + Hardening + WAF + Scan + SLA)", Colors.BOLD + Colors.BRIGHT_GREEN))
    safe_print(colorize("  [2]         ★ AUTOPILOT BATTLE MODE (Live Radar + Anti-Loop Replay + Auto-Submit) - MANUAL ONLY", Colors.BOLD + Colors.BRIGHT_CYAN))
    safe_print(colorize("  [3]         🩹 1-Click Auto-Patcher (Bungkus LFI/SQLi/RCE dengan backup & SLA rollback)", Colors.BOLD + Colors.BRIGHT_YELLOW))
    safe_print(colorize("  [4]         🩺 Pre-Flight Doctor & Triage Recon", Colors.YELLOW))
    safe_print(colorize("  [5]         🛡️  Hardening (Sysctl + Compiler Lock 700 + Permissions)", Colors.YELLOW))
    safe_print(colorize("  [6]         🧱 Firewall & UFW Setup (Allow Web/SSH + Whitelist SLA)", Colors.YELLOW))
    safe_print(colorize("  [7]         🕷️  Deep Webshell & Backdoor Hunter", Colors.YELLOW))
    safe_print(colorize("  [8]         🔍 Source Code Vuln Scanner & Guided Patcher (MANUAL REVIEW REQUIRED)", Colors.BOLD + Colors.YELLOW))
    safe_print(colorize("  [9]         📡 Real-Time Log Sniffer & Attack Radar", Colors.YELLOW))
    safe_print(colorize("  [10]        🛡️  OWASP Top-10 Micro-WAF Generator & Deployer", Colors.YELLOW))
    safe_print(colorize("  [11]        ⚡ Manual Exploit Replay ke Subnet Lawan (Rate Limited, No DoS)", Colors.BOLD + Colors.YELLOW))
    safe_print(colorize("  [12]        🎯 Targeted Single-Shot Exploit Probe (MANUAL - Compliant with JCC Rules)", Colors.BOLD + Colors.YELLOW))
    safe_print(colorize("  [13]        🚩 Submit Flag Gateway (JCC API Compatible)", Colors.BOLD + Colors.BRIGHT_GREEN))
    safe_print(colorize("  [14]        📖 Emergency Code Patching Cheatsheet", Colors.YELLOW))
    safe_print(colorize("  [15]        🎯 Exploit Payload Arsenal (SQLi, LFI, RCE, SSTI, Deser)", Colors.YELLOW))
    safe_print(colorize("  [16]        🔑 WireGuard VPN Status & Target IP Fetcher (JCC API)", Colors.BOLD + Colors.CYAN))
    safe_print(colorize("  [17]        🔧 Service Management (make start/restart/stop/compile)", Colors.BOLD + Colors.CYAN))
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
        targets = input("Target subnet musuh (contoh: 10.60.1-20.1 atau dari JCC API): ").strip()
        submit_url = input("URL submit flag game server (default: https://jcc.jatimprov.go.id/api/Game/<GAME_ID>/Ad/Submit): ").strip()
        token = input("API Token (dari A&D Toolkit interface): ").strip()
        if not submit_url:
            submit_url = "https://jcc.jatimprov.go.id/api/Game/GAME_ID/Ad/Submit"
        run_autopilot(targets_spec=targets, submit_url=submit_url if submit_url else None, token=token if token else None)
    elif choice in ("3", "autopatch", "patch-auto"):
        apply_safe_autopatch(ROOT_DEFAULT, DB_DEFAULT)
    elif choice == "4":
        run_doctor(ROOT_DEFAULT)
        run_triage(ROOT_DEFAULT)
    elif choice == "5":
        run_hardening_check(ROOT_DEFAULT)
    elif choice == "6":
        run_firewall_setup()
    elif choice == "7":
        run_webshell_hunter(ROOT_DEFAULT)
    elif choice == "8":
        default_target = ROOT_DEFAULT
        try:
            if not os.path.isdir(ROOT_DEFAULT) or not any(Path(ROOT_DEFAULT).iterdir()):
                default_target = "."
        except Exception:
            default_target = "."
        try:
            target_in = input(f"Target folder source code [{colorize(default_target, Colors.BOLD + Colors.GREEN)}]: ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        target_root = target_in if target_in else default_target
        safe_print(colorize("\n⚠️  PERINGATAN: Hasil scan harus di-review MANUAL sebelum patching!", Colors.BG_YELLOW + Colors.BOLD + Colors.BLACK))
        safe_print(colorize("   Dilarang menggunakan auto-patching tanpa verifikasi!\n", Colors.YELLOW))
        run_scan(target_root, DB_DEFAULT)
        run_next_patch(DB_DEFAULT)
    elif choice == "9":
        monitor_logs(None, alert_only=False)
    elif choice == "10":
        generate_waf("php", "/tmp/ctf_waf.php", ROOT_DEFAULT, auto_deploy=True)
    elif choice == "11":
        targets = input("Target subnet/IP (e.g. 10.60.1-20.1): ").strip()
        delay_input = input("Delay antar request (detik, min 1.0 untuk hindari DoS) [1.5]: ").strip()
        delay = float(delay_input) if delay_input else 1.5
        if delay < 1.0:
            safe_print(colorize("⚠️  Delay terlalu cepat! Menggunakan 1.5s untuk menghindari DoS.", Colors.YELLOW))
            delay = 1.5
        replay_attacks([targets] if targets else ["127.0.0.1"], delay=delay)
    elif choice == "12":
        targets = input("Target subnet/IP (e.g. 10.60.1-20.1): ").strip()
        ep = input("Endpoint (default /): ").strip() or "/"
        param = input("Parameter name (e.g. id): ").strip() or "id"
        payload = input("Payload (MANUAL INPUT - jangan gunakan automated scanner): ").strip() or "1' UNION SELECT 1,2,3--"
        delay_input = input("Delay antar target (detik, min 1.0) [1.5]: ").strip()
        delay = float(delay_input) if delay_input else 1.5
        if delay < 1.0:
            delay = 1.5
        run_targeted_probe(expand_target_ips(targets) if targets else ["127.0.0.1"], endpoint=ep, param=param, payload=payload, delay=delay)
    elif choice in ("13", "submit", "flag"):
        safe_print(colorize("\n📌 INFO: Format submit flag JCC 2026:", Colors.CYAN))
        safe_print("   API: POST https://jcc.jatimprov.go.id/api/Game/<GAME_ID>/Ad/Submit")
        safe_print("   Header: Authorization: Bearer <API_TOKEN>")
        safe_print("   Body: {\"flags\":[\"flag{...}\"]}\n")
        url = input("URL submit flag (default: https://jcc.jatimprov.go.id/api/Game/GAME_ID/Ad/Submit): ").strip()
        token = input("API Token: ").strip()
        if not url:
            url = "https://jcc.jatimprov.go.id/api/Game/GAME_ID/Ad/Submit"
        submit_flags(url=url, token=token)
    elif choice == "14":
        show_all_patch_guides()
    elif choice in ("15", "arsenal", "payloads"):
        print_payload_summary()
    elif choice in ("16", "wireguard", "vpn", "targets"):
        safe_print(colorize("\n🔑 WireGuard VPN Configuration for JCC 2026", Colors.BOLD + Colors.CYAN))
        safe_print("1. Download konfigurasi WireGuard dari platform JCC")
        safe_print("2. Install WireGuard sesuai OS Anda")
        safe_print("3. Import file .conf ke WireGuard")
        safe_print("4. Aktifkan koneksi VPN")
        safe_print("")
        game_id = input("Masukkan GAME_ID (atau kosongkan untuk skip): ").strip()
        api_token = input("Masukkan API_TOKEN: ").strip()
        if game_id and api_token:
            safe_print(f"\n[*] Fetching target IPs untuk Game ID: {game_id}")
            import urllib.request
            import json
            try:
                req = urllib.request.Request(
                    f"https://jcc.jatimprov.go.id/api/Game/{game_id}/Ad/Targets",
                    headers={"Authorization": f"Bearer {api_token}"}
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    safe_print(colorize(f"\n[✓] Berhasil mendapatkan {len(data.get('targets', []))} target IPs:", Colors.GREEN))
                    for idx, target in enumerate(data.get('targets', [])[:20], 1):
                        ip = target.get('ip', 'N/A')
                        safe_print(f"   {idx}. {ip}")
                    if len(data.get('targets', [])) > 20:
                        safe_print(f"   ... dan {len(data.get('targets', [])) - 20} lainnya")
            except Exception as e:
                safe_print(colorize(f"[✗] Error fetching targets: {e}", Colors.RED))
        else:
            safe_print(colorize("\n[!] Skip fetch targets. Pastikan VPN aktif sebelum menyerang.", Colors.YELLOW))
    elif choice in ("17", "service", "make"):
        safe_print(colorize("\n🔧 Service Management Commands (JCC 2026)", Colors.BOLD + Colors.CYAN))
        safe_print("Perintah yang tersedia:")
        safe_print("  - make start    : Menjalankan challenge")
        safe_print("  - make restart  : Restart challenge setelah patching")
        safe_print("  - make stop     : Menghentikan challenge")
        safe_print("  - make compile  : Kompilasi binary (khusus kategori pwn)")
        safe_print("")
        cmd = input("Jalankan perintah (start/restart/stop/compile) [restart]: ").strip().lower()
        if cmd in ("start", "restart", "stop", "compile"):
            import subprocess
            try:
                result = subprocess.run(["make", cmd], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    safe_print(colorize(f"[✓] make {cmd} berhasil!", Colors.GREEN))
                else:
                    safe_print(colorize(f"[✗] make {cmd} gagal: {result.stderr}", Colors.RED))
                if result.stdout:
                    safe_print(f"Output:\n{result.stdout}")
            except Exception as e:
                safe_print(colorize(f"[✗] Error menjalankan make {cmd}: {e}", Colors.RED))
        else:
            safe_print(colorize("[!] Perintah tidak valid.", Colors.YELLOW))


def main():
    if len(sys.argv) == 1:
        interactive_menu()
        return 0

    p = argparse.ArgumentParser(
        prog="adctf.py",
        description="AD-CTF Master Battle Station — Unified Attack-Defense Framework v3.3",
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
    x.add_argument("--pattern", default=None, help="Custom flag regex pattern")
    x.set_defaults(fn=lambda a: run_autopilot(
        a.targets, a.submit_url, a.token, a.log_file, a.waf_capture, a.port, a.threads, a.db, flag_pattern=a.pattern
    ))

    # 3. autopatch
    x = sub.add_parser("autopatch", aliases=["patch-auto"], help="1-Click safe automated micro-patcher for PHP/Python")
    x.add_argument("--web-root", default=ROOT_DEFAULT)
    x.add_argument("--dry-run", action="store_true", help="Only show patch diffs without modifying files")
    x.set_defaults(fn=lambda a: apply_safe_autopatch(a.web_root, a.db, dry_run=a.dry_run))

    # 4. doctor
    x = sub.add_parser("doctor", aliases=["preflight"], help="Pre-flight host diagnostics & readiness check")
    x.add_argument("--web-root", default=ROOT_DEFAULT)
    x.set_defaults(fn=lambda a: run_doctor(a.web_root))

    # 5. triage
    x = sub.add_parser("triage", aliases=["audit"], help="Rapid 1-second system reconnaissance")
    x.add_argument("--web-root", default=ROOT_DEFAULT)
    x.set_defaults(fn=lambda a: run_triage(a.web_root))

    # 6. hardening
    x = sub.add_parser("hardening", help="System permissions, sysctl, and PHP hardening audit & apply")
    x.add_argument("--web-root", default=ROOT_DEFAULT)
    x.add_argument("--apply", action="store_true", help="Apply hardening fixes automatically (requires sudo)")
    x.set_defaults(fn=lambda a: run_hardening_apply(a.web_root) if a.apply else run_hardening_check(a.web_root))

    # 7. firewall
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

    # 8. webshell
    x = sub.add_parser("webshell", aliases=["backdoor"], help="Scan webroot for webshells, backdoors & recent modifications")
    x.add_argument("--web-root", default=ROOT_DEFAULT)
    x.add_argument("--recent", type=int, default=None, help="Filter files modified within N minutes")
    x.add_argument("--quarantine", action="store_true", help="Move detected webshells to quarantine directory")
    x.set_defaults(fn=lambda a: run_webshell_hunter(a.web_root, a.recent, a.quarantine))

    # 9. restore
    x = sub.add_parser("restore", help="Emergency backup extraction")
    x.add_argument("--backup-dir", default=BACKUP_DEFAULT)
    x.add_argument("--archive", default=None)
    x.add_argument("--confirm", action="store_true")
    x.set_defaults(fn=lambda a: run_restore(a.backup_dir, a.archive, a.confirm))

    # 10. scan
    x = sub.add_parser("scan", help="Scan source code for vulnerabilities")
    x.add_argument("--web-root", default=ROOT_DEFAULT)
    x.set_defaults(fn=lambda a: run_scan(a.web_root, a.db))

    # 11. next & done & list & patch
    x = sub.add_parser("next", help="Get next priority vulnerability to patch")
    x.set_defaults(fn=lambda a: run_next_patch(a.db))
    x = sub.add_parser("done", help="Mark current vulnerability as patched")
    x.set_defaults(fn=lambda a: run_done_patch(a.db))
    x = sub.add_parser("list", aliases=["status"], help="List patch checklist")
    x.set_defaults(fn=lambda a: run_list_patches(a.db))
    x = sub.add_parser("patch", help="Launch interactive guided patch workflow")
    x.set_defaults(fn=lambda a: run_next_patch(a.db))

    # 12. watch / monitor
    x = sub.add_parser("watch", aliases=["monitor"], help="Real-time log sniffer & attack alert")
    x.add_argument("--log", "--log-file", dest="log_file", default=None)
    x.add_argument("--alert-only", action="store_true")
    x.set_defaults(fn=lambda a: monitor_logs(a.log_file, alert_only=a.alert_only))

    # 13. check / health
    x = sub.add_parser("check", aliases=["health"], help="Health check & SLA verifier")
    x.add_argument("--url", action="append")
    x.add_argument("--base", default="http://127.0.0.1")
    x.add_argument("--endpoint", action="append")
    x.add_argument("--timeout", type=int, default=4)
    x.set_defaults(fn=lambda a: run_health_checks(a.url or [a.base], path=(a.endpoint[0] if a.endpoint else "/"), timeout=a.timeout))

    # 14. attack / replay
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

    # 15. probe (targeted manual probe)
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

    # 16. submit - JCC 2026 API compatible
    x = sub.add_parser("submit", aliases=["submit-flag"], help="Submit captured flags to JCC 2026 Game Server")
    x.add_argument("--url", "-u", default="https://jcc.jatimprov.go.id/api/Game/GAME_ID/Ad/Submit", help="JCC API endpoint")
    x.add_argument("--token", "-t", default=None, help="API Token (Bearer)")
    x.add_argument("--flag", "-f", default=None)
    x.add_argument("--file", default="captured_flags.txt")
    x.add_argument("--pattern", default=None, help="Custom flag regex pattern")
    x.set_defaults(fn=lambda a: submit_flags(
        url=a.url, token=a.token, flag=a.flag, flag_file=a.file, flag_pattern=a.pattern, db_path=a.db
    ))

    # 17. waf
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

    # 18. patch-guide
    x = sub.add_parser("patch-guide", help="Show before-and-after code patch snippets")
    x.add_argument("--category", "-c", default="", help="Filter by category (SQLi, LFI, RCE, SSTI, DESER)")
    x.set_defaults(fn=lambda a: show_all_patch_guides(a.category))

    # 19. arsenal
    x = sub.add_parser("arsenal", aliases=["payloads", "exploit-list"], help="Display offensive exploit payload arsenal")
    x.add_argument("--category", "-c", default="", help="Filter by category (SQLi, LFI, RCE, SSTI, DESER, NOSQLI, XXE)")
    x.set_defaults(fn=lambda a: print_payload_summary())

    args = p.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
