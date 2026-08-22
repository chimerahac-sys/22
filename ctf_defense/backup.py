#!/usr/bin/env python3
"""Backup, baseline initialization, and emergency restore engine."""

import hashlib
import os
import shutil
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

from .colors import Colors, colorize, print_banner, safe_print

ROOT_DEFAULT = "/var/www/html"
BACKUP_DEFAULT = os.path.expanduser("~/.adctf/backups")
SKIP_DIRS = {"vendor", "node_modules", ".git", ".svn", "cache", "dist", "build", "framework", "tests", "fixtures", "storage", "third_party"}


def file_sha256(path: str) -> str:
    """Calculate SHA256 digest of a file safely."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def detect_database_type(root: str) -> str:
    """Detect database engine used by looking for SQLite files or running processes."""
    if os.path.isdir(root):
        for base, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                if f.lower().endswith((".sqlite", ".sqlite3", ".db")):
                    return "sqlite"

    # Process check
    try:
        r = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=2)
        ps_out = r.stdout.lower() if r.returncode == 0 else ""
        if "mysqld" in ps_out or "mariadbd" in ps_out:
            return "mysql"
        if "postgres" in ps_out:
            return "postgresql"
    except Exception:
        pass

    if shutil.which("mysqldump") or shutil.which("mariadb-dump"):
        return "mysql"
    if shutil.which("pg_dump") or shutil.which("pg_dumpall"):
        return "postgresql"

    return "unknown"


def backup_database(destination: str, db_type: str = "auto", db_file: Optional[str] = None) -> Optional[str]:
    """Export database safely into backup destination."""
    os.makedirs(destination, exist_ok=True)
    if db_type == "sqlite" or (db_file and os.path.isfile(db_file)):
        if db_file and os.path.isfile(db_file):
            out_file = os.path.join(destination, "database.sqlite")
            shutil.copy2(db_file, out_file)
            safe_print(f" [✓] SQLite Backup   : {colorize(out_file, Colors.GREEN)}")
            return out_file

    dump_tool = shutil.which("mysqldump") or shutil.which("mariadb-dump") or shutil.which("pg_dumpall")
    if not dump_tool:
        return None

    out_file = os.path.join(destination, "database.sql")
    cmd = [dump_tool, "--all-databases", "--result-file=" + out_file] if "dump" in dump_tool else [dump_tool, "--file=" + out_file]
    try:
        r = subprocess.run(cmd, timeout=30, capture_output=True, text=True)
        if r.returncode == 0 and os.path.isfile(out_file) and os.path.getsize(out_file) > 0:
            safe_print(f" [✓] Database Backup : {colorize(out_file, Colors.GREEN)} ({os.path.getsize(out_file):,} bytes)")
            return out_file
    except Exception:
        pass
    return None


def init_git_baseline(root: str) -> bool:
    """Initialize a clean Git commit and tag as restore baseline."""
    if not os.path.isdir(root) or not shutil.which("git"):
        return False

    git_dir = os.path.join(root, ".git")
    if not os.path.isdir(git_dir):
        try:
            subprocess.run(["git", "init"], cwd=root, capture_output=True, timeout=5)
            subprocess.run(["git", "config", "user.name", "CTF-Defender"], cwd=root, capture_output=True, timeout=5)
            subprocess.run(["git", "config", "user.email", "defender@ctf.local"], cwd=root, capture_output=True, timeout=5)
            subprocess.run(["git", "add", "."], cwd=root, capture_output=True, timeout=10)
            subprocess.run(["git", "commit", "-m", "Baseline Clean State"], cwd=root, capture_output=True, timeout=10)
            subprocess.run(["git", "tag", "clean-baseline"], cwd=root, capture_output=True, timeout=5)
            safe_print(f" [✓] Git Baseline    : Initialized & tagged 'clean-baseline'")
            return True
        except Exception:
            return False
    return True


def run_backup(web_root: str = ROOT_DEFAULT, backup_dir: str = BACKUP_DEFAULT, db_file: Optional[str] = None) -> int:
    """Execute complete webroot & database backup with validation."""
    root = os.path.abspath(web_root)
    if not os.path.isdir(root):
        safe_print(colorize(f"[ERROR] Web root tidak ditemukan: {root}", Colors.BRIGHT_RED))
        return 1

    print_banner("Backup & Baseline Engine", f"Target: {root}")
    os.makedirs(backup_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_path = os.path.join(backup_dir, f"web_backup_{ts}.tar.gz")

    try:
        with tarfile.open(archive_path, "w:gz") as tar:
            tar.add(root, arcname=os.path.basename(root))
        size = os.path.getsize(archive_path)
    except Exception as e:
        safe_print(colorize(f"[ERROR] Gagal membuat archive tar.gz: {e}", Colors.BRIGHT_RED))
        return 1

    if size <= 0:
        safe_print(colorize("[ERROR] Backup 0 KB! Workflow STOP demi keselamatan.", Colors.BRIGHT_RED))
        return 1

    safe_print(f" [✓] Web Archive     : {colorize(archive_path, Colors.BOLD + Colors.GREEN)} ({size:,} bytes)")

    # Database export
    db_type = detect_database_type(root)
    backup_database(backup_dir, db_type, db_file)

    # Git baseline
    init_git_baseline(root)

    safe_print(colorize("\n[✓] Backup selesai dan terverifikasi. Siap melanjutkan ke scanning.", Colors.BOLD + Colors.BRIGHT_GREEN))
    return 0


def run_restore(backup_dir: str = BACKUP_DEFAULT, archive: Optional[str] = None, confirm: bool = False) -> int:
    """Restore webroot from verified backup archive."""
    print_banner("Emergency Restore Engine", "System Recovery")

    files = [os.path.join(backup_dir, x) for x in os.listdir(backup_dir)] if os.path.isdir(backup_dir) else []
    tar_files = sorted([x for x in files if x.endswith(".tar.gz")], reverse=True)

    target_archive = archive or (tar_files[0] if tar_files else None)
    if not target_archive or not os.path.isfile(target_archive) or os.path.getsize(target_archive) <= 0:
        safe_print(colorize(f"[ERROR] Backup valid tidak ditemukan di {backup_dir}", Colors.BRIGHT_RED))
        return 1

    if not confirm:
        safe_print(colorize(f"[PREVIEW] Ditemukan backup: {target_archive}", Colors.YELLOW))
        safe_print("Untuk mengekstrak dan memulihkan file, jalankan:")
        safe_print(f"  {colorize('python adctf.py restore --confirm', Colors.BOLD + Colors.CYAN)}")
        return 0

    try:
        # Safe extraction
        with tarfile.open(target_archive, "r:gz") as t:
            for member in t.getmembers():
                norm = os.path.normpath(member.name)
                if norm.startswith("../") or os.path.isabs(norm) or member.issym() or member.islnk():
                    raise RuntimeError(f"Unsafe member in archive: {member.name}")
            t.extractall(path="/var/www")

        safe_print(colorize(f"[✓] Restore selesai dari: {target_archive}", Colors.BOLD + Colors.BRIGHT_GREEN))
        return 0
    except Exception as e:
        safe_print(colorize(f"[ERROR] Gagal me-restore: {e}", Colors.BRIGHT_RED))
        return 1
