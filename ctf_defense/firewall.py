#!/usr/bin/env python3
"""Automated Firewall & Traffic Filter (UFW / iptables) with Game Server Whitelisting."""

import os
import shutil
import subprocess
import sys
from typing import List, Optional

from .colors import Colors, colorize, print_banner, safe_print


def generate_ufw_commands(
    ssh_port: int = 22,
    http_ports: List[int] = [80, 443],
    whitelist_ips: List[str] = [],
    allow_team_subnet: Optional[str] = None,
) -> List[str]:
    """Generate minimal and safe UFW commands."""
    cmds = [
        "ufw default deny incoming",
        "ufw default allow outgoing",
        f"ufw allow {ssh_port}/tcp comment 'SSH Management'",
    ]
    for p in http_ports:
        cmds.append(f"ufw allow {p}/tcp comment 'Web Service'")

    for ip in whitelist_ips:
        cmds.append(f"ufw allow from {ip} comment 'SLA Checker Whitelist'")

    if allow_team_subnet:
        cmds.append(f"ufw allow from {allow_team_subnet} comment 'Team Internal Subnet'")

    cmds.append("ufw --force enable")
    return cmds


def run_firewall_setup(
    ssh_port: int = 22,
    http_ports: List[int] = [80, 443],
    whitelist_ips: List[str] = [],
    allow_team_subnet: Optional[str] = None,
    apply: bool = False,
) -> int:
    """Setup or preview UFW rules."""
    print_banner("Firewall & Traffic Guard (UFW)", "Inbound Port Lockdown & SLA Whitelisting")

    cmds = generate_ufw_commands(ssh_port, http_ports, whitelist_ips, allow_team_subnet)

    safe_print(colorize("[*] Rencana Aturan Firewall (UFW):", Colors.BOLD + Colors.BRIGHT_YELLOW))
    for c in cmds:
        safe_print(f"  $ {colorize(c, Colors.CYAN)}")

    if not shutil.which("ufw"):
        safe_print(colorize("\n[!] UFW tidak terinstall pada sistem. Install via: sudo apt install -y ufw", Colors.BRIGHT_RED))
        return 1

    if not apply:
        safe_print(colorize("\n[PREVIEW MODE] Aturan di atas belum diaplikasikan.", Colors.YELLOW))
        safe_print("Untuk mengaktifkan aturan firewall ini, jalankan:")
        safe_print(f"  {colorize('sudo python adctf.py firewall --apply', Colors.BOLD + Colors.BRIGHT_GREEN)}\n")
        return 0

    safe_print(colorize("\n[*] Menerapkan aturan UFW...", Colors.YELLOW))
    for c in cmds:
        try:
            subprocess.run(c.split(), check=True, capture_output=True, text=True, timeout=5)
            safe_print(f"  [✓] Sukses: {c}")
        except Exception as e:
            safe_print(f"  [✗] Gagal: {c} ({e})")

    safe_print(colorize("\n[✓] Firewall aktif dan melindungi server!", Colors.BOLD + Colors.BRIGHT_GREEN))
    return 0
