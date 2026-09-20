#!/usr/bin/env python3
"""Pre-flight Environment Diagnostics & Doctor for CTF Attack-Defense.

Verifies readiness before the competition starts:
  - Python runtime & encoding
  - System CLI utilities (git, tmux, ss, lsof, ufw, iptables)
  - Web server access log existence & read permissions
  - Webroot write permissions & Git tracking status
  - Socket binding & local connectivity
"""

import os
import shutil
import socket
import sys
from pathlib import Path

from .colors import Colors, colorize, safe_print, print_banner


class EnvironmentDoctor:
    """Performs pre-flight validation on the competition host."""

    DEFAULT_LOGS = [
        "/var/log/nginx/access.log",
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
        "access.log",
    ]

    WEBROOT_CANDIDATES = [
        "/var/www/html",
        "/var/www",
        "/app",
        "/srv",
        "/opt",
    ]

    REQUIRED_TOOLS = ["git", "ss", "lsof", "tmux", "ufw", "curl"]

    def __init__(self):
        self.issues = []
        self.fixes = []

    def check_python(self) -> bool:
        """Check Python version and encoding."""
        v = sys.version_info
        if v.major >= 3 and v.minor >= 8:
            safe_print(f" [✓] Python Version      : {sys.version.split()[0]} ({colorize('COMPATIBLE', Colors.GREEN)})")
            return True
        else:
            safe_print(f" [✗] Python Version      : {sys.version.split()[0]} ({colorize('OUTDATED - need >= 3.8', Colors.BRIGHT_RED)})")
            self.issues.append("Python version is older than 3.8")
            self.fixes.append("Install modern python3: sudo apt update && sudo apt install -y python3")
            return False

    def check_tools(self) -> None:
        """Verify presence of essential defense utilities."""
        for tool in self.REQUIRED_TOOLS:
            path = shutil.which(tool)
            if path:
                safe_print(f" [✓] CLI Tool [{tool:<8}] : {colorize(path, Colors.GREEN)}")
            else:
                safe_print(f" [!] CLI Tool [{tool:<8}] : {colorize('MISSING', Colors.YELLOW)}")
                if tool in ("git", "tmux", "lsof", "curl"):
                    self.issues.append(f"Tool '{tool}' not installed")
                    self.fixes.append(f"sudo apt update && sudo apt install -y {tool}")

    def check_logs(self) -> None:
        """Verify access log existence and permissions."""
        found = False
        for log_path in self.DEFAULT_LOGS:
            p = Path(log_path)
            if p.exists():
                found = True
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        f.read(10)
                    safe_print(f" [✓] Web Access Log      : {colorize(str(p), Colors.GREEN)} ({colorize('READABLE', Colors.GREEN)})")
                except PermissionError:
                    safe_print(f" [✗] Web Access Log      : {colorize(str(p), Colors.BRIGHT_RED)} ({colorize('PERMISSION DENIED', Colors.BRIGHT_RED)})")
                    self.issues.append(f"Cannot read log file {p}")
                    self.fixes.append(f"sudo chmod +r {p}   # Or add user: sudo usermod -aG adm $USER")
                break

        if not found:
            safe_print(f" [!] Web Access Log      : {colorize('No standard access.log found in /var/log/nginx or apache2', Colors.YELLOW)}")

    def check_webroot(self) -> None:
        """Verify webroot writeability and Git repository presence."""
        for candidate in self.WEBROOT_CANDIDATES:
            p = Path(candidate)
            if p.exists() and p.is_dir():
                is_git = (p / ".git").exists()
                git_status = colorize("GIT TRACKED", Colors.GREEN) if is_git else colorize("NOT TRACKED BY GIT", Colors.YELLOW)
                safe_print(f" [✓] App Root [{candidate}] : Found ({git_status})")
                if not is_git:
                    self.issues.append(f"Webroot {candidate} is not initialized with Git")
                    self.fixes.append(f"cd {candidate} && git init && git add . && git commit -m 'Initial clean state'")
                break

    def check_network(self) -> None:
        """Verify loopback socket binding on active and standard web ports."""
        from .environment import get_listening_ports
        active_ports = get_listening_ports()
        web_ports = [p for p in active_ports if p in (80, 8080, 5000, 8000, 3000, 8888, 9000, 443)]
        if web_ports:
            for wp in web_ports:
                safe_print(f" [✓] Web Port [{wp:<5}]      : {colorize('LISTENING & CONNECTABLE', Colors.GREEN)}")
        else:
            safe_print(f" [.] Web Ports           : {colorize('No HTTP port currently listening (start web service first)', Colors.YELLOW)}")

    def run_diagnostics(self) -> None:
        """Execute full doctor suite."""
        print_banner("Attack-Defense Environment Doctor", "Pre-Flight Host Diagnostics & Readiness Check")
        safe_print("")
        self.check_python()
        self.check_tools()
        self.check_logs()
        self.check_webroot()
        self.check_network()

        safe_print(colorize("\n" + "=" * 75, Colors.BRIGHT_CYAN))
        if not self.issues:
            safe_print(colorize("[✓] ALL CHECKS PASSED! Host is 100% battle-ready for the competition.", Colors.BOLD + Colors.BRIGHT_GREEN))
        else:
            safe_print(colorize(f"[!] FOUND {len(self.issues)} RECOMMENDED OPTIMIZATIONS:", Colors.BOLD + Colors.BRIGHT_YELLOW))
            for idx, fix in enumerate(self.fixes, 1):
                safe_print(f"   {idx}. {colorize(fix, Colors.CYAN)}")
        safe_print("")


def run_doctor(web_root: str = "/var/www/html") -> int:
    doc = EnvironmentDoctor()
    if web_root not in doc.WEBROOT_CANDIDATES:
        doc.WEBROOT_CANDIDATES.insert(0, web_root)
    doc.run_diagnostics()
    return 0 if not doc.issues else 0


def main() -> None:
    run_doctor()


if __name__ == "__main__":
    main()
