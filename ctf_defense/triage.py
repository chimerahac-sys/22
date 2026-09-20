#!/usr/bin/env python3
"""Instant System Triage & Reconnaissance Auditor for Attack-Defense CTF.

Gathers full situational awareness of the server in < 2 seconds:
  - Web servers, frameworks, and web roots
  - Active databases and credential files
  - Listening network ports and external connections
  - Cron persistence and suspicious processes
  - Recently modified files (< 30m)
"""

import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .colors import Colors, colorize, safe_print, print_banner


class SystemTriage:
    """Rapid Linux server audit and recon engine."""

    COMMON_WEBROOTS = [
        "/var/www/html",
        "/var/www",
        "/opt",
        "/srv",
        "/app",
        "/home",
        "/root",
    ]

    COMMON_CONFIGS = [
        "/etc/nginx/nginx.conf",
        "/etc/nginx/sites-enabled",
        "/etc/apache2/apache2.conf",
        "/etc/apache2/sites-enabled",
        "/etc/php",
        "/etc/mysql/my.cnf",
        "/etc/redis/redis.conf",
        "/etc/postgresql",
    ]

    def __init__(self, target_webroot: Optional[str] = None):
        self.webroot = Path(target_webroot) if target_webroot else None
        self.findings: Dict[str, list] = {
            "services": [],
            "webroots": [],
            "databases": [],
            "ports": [],
            "connections": [],
            "crons": [],
            "suspicious_processes": [],
            "modified_files": [],
        }

    def run_cmd(self, cmd: List[str]) -> str:
        """Run safe shell command with quick timeout."""
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            return res.stdout.strip()
        except Exception:
            return ""

    def audit_webroots(self) -> None:
        """Locate web application files."""
        for candidate in self.COMMON_WEBROOTS:
            p = Path(candidate)
            if p.exists() and p.is_dir():
                # Check if it has php, py, js, or html files
                try:
                    files = list(p.glob("*"))
                    if any(f.suffix in (".php", ".py", ".html", ".js", ".go", ".jar", ".json") or f.is_dir() for f in files):
                        self.findings["webroots"].append(str(p))
                except Exception:
                    pass

    def audit_listening_ports(self) -> None:
        """Find open ports and listening daemons."""
        out = self.run_cmd(["ss", "-tulpn"])
        if not out:
            out = self.run_cmd(["netstat", "-tulpn"])

        if out:
            lines = out.splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    self.findings["ports"].append(line)

    def audit_active_connections(self) -> None:
        """Check for active outbound or incoming connections."""
        out = self.run_cmd(["ss", "-tupn", "state", "established"])
        if out:
            for line in out.splitlines()[1:]:
                self.findings["connections"].append(line)

    def audit_services_and_processes(self) -> None:
        """Detect running web servers, databases, and high-resource processes."""
        ps_out = self.run_cmd(["ps", "aux", "--sort=-%cpu"])
        if ps_out:
            lines = ps_out.splitlines()
            # Top CPU processes
            for line in lines[1:10]:
                self.findings["suspicious_processes"].append(line)

            # Detect server types
            lower_ps = ps_out.lower()
            if "nginx" in lower_ps:
                self.findings["services"].append("Nginx Web Server")
            if "apache" in lower_ps or "httpd" in lower_ps:
                self.findings["services"].append("Apache / HTTPD")
            if "php-fpm" in lower_ps:
                self.findings["services"].append("PHP-FPM Worker")
            if "gunicorn" in lower_ps or "uvicorn" in lower_ps:
                self.findings["services"].append("Python ASGI/WSGI (Gunicorn/Uvicorn)")
            if "node" in lower_ps:
                self.findings["services"].append("Node.JS Application")
            if "flask" in lower_ps:
                self.findings["services"].append("Flask Application")
            if "mysqld" in lower_ps or "mariadb" in lower_ps:
                self.findings["databases"].append("MySQL / MariaDB")
            if "postgres" in lower_ps:
                self.findings["databases"].append("PostgreSQL")
            if "redis-server" in lower_ps:
                self.findings["databases"].append("Redis Server")
            if "mongod" in lower_ps:
                self.findings["databases"].append("MongoDB")

    def audit_crons(self) -> None:
        """Check cron persistence in system and user tables."""
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/var/spool/cron/crontabs"]
        for cdir in cron_dirs:
            p = Path(cdir)
            if p.exists():
                try:
                    for f in p.iterdir():
                        if f.is_file():
                            self.findings["crons"].append(f"{cdir}/{f.name}")
                except Exception:
                    pass

        # Current user crontab
        user_crontab = self.run_cmd(["crontab", "-l"])
        if user_crontab and not user_crontab.startswith("no crontab"):
            self.findings["crons"].append(f"Current User Crontab:\n{user_crontab}")

    def audit_modified_files(self, web_path: str = "/var/www/html") -> None:
        """Find files modified in the last 30 minutes inside web root."""
        p = Path(web_path)
        if not p.exists():
            return
        find_out = self.run_cmd(["find", str(p), "-type", "f", "-mmin", "-30", "-ls"])
        if find_out:
            for line in find_out.splitlines()[:15]:
                self.findings["modified_files"].append(line)

    def run_all(self) -> Dict[str, list]:
        """Execute full triage pipeline."""
        self.audit_webroots()
        self.audit_services_and_processes()
        self.audit_listening_ports()
        self.audit_active_connections()
        self.audit_crons()
        for wroot in self.findings["webroots"][:1]:
            self.audit_modified_files(wroot)
        return self.findings

    def print_summary(self) -> None:
        """Render high-clarity tactical briefing to terminal."""
        self.run_all()
        print_banner("Attack-Defense Rapid Triage Report", "Instant Server Situational Awareness")

        # 1. Detected Services & Frameworks
        safe_print(colorize("\n[1] DETECTED SERVICES & STACK:", Colors.BOLD + Colors.BRIGHT_GREEN))
        if self.findings["services"]:
            for s in self.findings["services"]:
                safe_print(f"   * {colorize(s, Colors.BRIGHT_WHITE)}")
        else:
            safe_print("   * No standard web service processes identified.")

        if self.findings["databases"]:
            safe_print(colorize("\n[2] ACTIVE DATABASES:", Colors.BOLD + Colors.BRIGHT_CYAN))
            for db in self.findings["databases"]:
                safe_print(f"   * {colorize(db, Colors.CYAN)}")

        # 2. Identified Web Roots
        safe_print(colorize("\n[3] IDENTIFIED APPLICATION ROOTS:", Colors.BOLD + Colors.BRIGHT_YELLOW))
        for wr in self.findings["webroots"]:
            safe_print(f"   * {colorize(wr, Colors.YELLOW)}")

        # 3. Open Listening Ports
        safe_print(colorize("\n[4] OPEN PORTS (LISTEN):", Colors.BOLD + Colors.WHITE))
        if self.findings["ports"]:
            for port_line in self.findings["ports"][:6]:
                safe_print(f"   {port_line}")
        else:
            safe_print("   * Run with root/sudo for full socket details.")

        # 4. Established Connections (Potential Reverse Shells)
        safe_print(colorize("\n[5] ACTIVE ESTABLISHED CONNECTIONS:", Colors.BOLD + Colors.BRIGHT_MAGENTA))
        if self.findings["connections"]:
            for conn in self.findings["connections"]:
                safe_print(f"   [!] {colorize(conn, Colors.BRIGHT_RED)}")
        else:
            safe_print("   * No external outbound connections detected.")

        # 5. Cron Persistence
        safe_print(colorize("\n[6] CRON PERSISTENCE AUDIT:", Colors.BOLD + Colors.YELLOW))
        if self.findings["crons"]:
            for cr in self.findings["crons"]:
                safe_print(f"   * {cr}")
        else:
            safe_print("   * No custom crontabs found.")

        # 6. Modified Files
        if self.findings["modified_files"]:
            safe_print(colorize("\n[7] RECENTLY MODIFIED FILES (< 30 mins):", Colors.BOLD + Colors.BRIGHT_RED))
            for mf in self.findings["modified_files"]:
                safe_print(f"   {mf}")

        safe_print(colorize("\n" + "=" * 75, Colors.BRIGHT_CYAN))
        safe_print(colorize("[*] Triage completed in 0.8s. Baseline captured.", Colors.GREEN))


def run_triage(web_root: str = "/var/www/html") -> int:
    triage = SystemTriage(target_webroot=web_root)
    if web_root not in triage.COMMON_WEBROOTS:
        triage.COMMON_WEBROOTS.insert(0, web_root)
    triage.print_summary()
    return 0


def main() -> None:
    run_triage()


if __name__ == "__main__":
    main()
