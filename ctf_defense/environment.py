#!/usr/bin/env python3
"""Universal Adaptive Environment & Stack Detector for CTF Attack-Defense.

Zero-dependency, high-precision detection of:
  - Web Servers: Nginx, Apache, Caddy, Lighttpd, Gunicorn, Uvicorn, PM2, Built-in servers
  - Languages: PHP, Python, Node.js, Java, Go, Ruby, Static HTML
  - Frameworks: Laravel, Symfony, CodeIgniter 3/4, WordPress, Django, Flask, FastAPI, Express, NestJS, Spring Boot
  - DocumentRoots: Distinguishes between project root (e.g. /var/www/html) and public webroot (e.g. /var/www/html/public)
  - Databases: MySQL/MariaDB, PostgreSQL, SQLite, Redis, MongoDB
  - Active Listening Ports & Local Connectivity
  - Required Framework Writable Directories (Storage, Cache, Uploads)
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .colors import Colors, colorize, print_banner, safe_print

DEFAULT_SEARCH_ROOTS = [
    "/var/www/html",
    "/var/www",
    "/app",
    "/srv/http",
    "/srv/www",
    "/opt/app",
    "/home/ctf",
    "/home/ctf/web",
    ".",
]


@dataclass
class EnvironmentInfo:
    server: str = "unknown"             # nginx, apache, caddy, lighttpd, gunicorn, uvicorn, pm2, standalone, unknown
    server_version: str = ""
    language: str = "unknown"           # php, python, node, java, go, ruby, static, unknown
    language_version: str = ""
    framework: str = "native"           # laravel, codeigniter4, codeigniter3, symfony, wordpress, django, flask, fastapi, express, nestjs, spring, native, unknown
    webroot: str = "/var/www/html"      # Project root directory
    public_webroot: str = "/var/www/html" # Actual document root (e.g. /var/www/html/public for Laravel)
    entry_files: List[str] = field(default_factory=list) # Found entry point files (e.g. index.php, app.py)
    active_ports: List[int] = field(default_factory=list)
    primary_port: int = 80
    databases: List[str] = field(default_factory=list)
    sqlite_dbs: List[str] = field(default_factory=list)
    writable_dirs: List[str] = field(default_factory=list)
    php_ini_paths: List[str] = field(default_factory=list)
    is_docker: bool = False
    is_root: bool = False
    details: Dict[str, str] = field(default_factory=dict)


def _safe_run(cmd: List[str], timeout: float = 2.5) -> str:
    """Execute command safely without throwing exceptions."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + (" " + r.stderr if r.stderr else "")
    except Exception:
        return ""


def detect_is_docker() -> bool:
    """Check if execution is happening inside a Docker container."""
    if os.path.exists("/.dockerenv"):
        return True
    try:
        if os.path.isfile("/proc/1/cgroup"):
            with open("/proc/1/cgroup", "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                if "docker" in content or "containerd" in content or "kubepods" in content:
                    return True
    except Exception:
        pass
    return False


def get_listening_ports() -> List[int]:
    """Discover open TCP listening ports on localhost using ss / netstat / socket probe."""
    ports = set()

    # Method 1: parse `ss -tulnp` or `ss -tln`
    ss_out = _safe_run(["ss", "-tln"])
    if ss_out:
        for line in ss_out.splitlines():
            # Look for *:PORT or 0.0.0.0:PORT or 127.0.0.1:PORT or :::PORT
            m = re.findall(r"(?:(?:::|0\.0\.0\.0|127\.0\.0\.1|\*):)(\d{2,5})\b", line)
            for p in m:
                try:
                    port_num = int(p)
                    if 1 <= port_num <= 65535:
                        ports.add(port_num)
                except ValueError:
                    pass

    # Method 2: parse `netstat -tln` if ss returned empty
    if not ports:
        netstat_out = _safe_run(["netstat", "-tln"])
        if netstat_out:
            m = re.findall(r"(?:(?:::|0\.0\.0\.0|127\.0\.0\.1|\*):)(\d{2,5})\b", netstat_out)
            for p in m:
                try:
                    ports.add(int(p))
                except ValueError:
                    pass

    # Method 3: Socket probe fallback for common CTF ports
    common_ctf_ports = [80, 8080, 5000, 8000, 3000, 4000, 8888, 9000, 443, 3306, 5432, 6379, 27017]
    for cp in common_ctf_ports:
        if cp in ports:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.05)
                if s.connect_ex(("127.0.0.1", cp)) == 0:
                    ports.add(cp)
        except Exception:
            pass

    # Sort HTTP-relevant ports first
    http_priority = [80, 8080, 5000, 8000, 3000, 8888, 9000, 4000, 443]
    sorted_ports = sorted(list(ports), key=lambda p: (0 if p in http_priority else 1, p))
    return sorted_ports


def find_php_ini_files() -> List[str]:
    """Find all relevant php.ini paths on the host."""
    paths = []
    # 1. php --ini CLI
    php_ini_out = _safe_run(["php", "--ini"])
    for line in php_ini_out.splitlines():
        if "Loaded Configuration File" in line:
            p = line.split(":", 1)[-1].strip()
            if p and p != "(none)" and os.path.isfile(p) and p not in paths:
                paths.append(p)

    # 2. Standard Linux FPM / Apache php.ini locations
    standard_locations = [
        "/etc/php/8.3/fpm/php.ini", "/etc/php/8.3/apache2/php.ini", "/etc/php/8.3/cli/php.ini",
        "/etc/php/8.2/fpm/php.ini", "/etc/php/8.2/apache2/php.ini", "/etc/php/8.2/cli/php.ini",
        "/etc/php/8.1/fpm/php.ini", "/etc/php/8.1/apache2/php.ini", "/etc/php/8.1/cli/php.ini",
        "/etc/php/8.0/fpm/php.ini", "/etc/php/8.0/apache2/php.ini", "/etc/php/8.0/cli/php.ini",
        "/etc/php/7.4/fpm/php.ini", "/etc/php/7.4/apache2/php.ini", "/etc/php/7.4/cli/php.ini",
        "/usr/local/etc/php/php.ini", "/etc/php.ini",
    ]
    for loc in standard_locations:
        if os.path.isfile(loc) and loc not in paths:
            paths.append(loc)
    return paths


def detect_framework_and_stack(root_dir: str) -> Tuple[str, str, str, str, List[str], List[str]]:
    """Deep inspect project root for language, framework, public webroot, version, entry files, writable dirs.
    
    Returns:
        (language, framework, public_webroot, version_hint, entry_files, writable_dirs)
    """
    if not os.path.isdir(root_dir):
        return ("unknown", "unknown", root_dir, "", [], [])

    abs_root = os.path.abspath(root_dir)
    public_root = abs_root
    language = "unknown"
    framework = "native"
    version_hint = ""
    entry_files = []
    writable_dirs = []

    # Check for direct files in root
    try:
        root_files = set(os.listdir(abs_root))
    except Exception:
        root_files = set()

    # ─────────────────────────────────────────────────────────────────────
    # 1. PHP ECOSYSTEM DETECTION (Laravel, Symfony, CodeIgniter, WordPress)
    # ─────────────────────────────────────────────────────────────────────
    composer_json_path = os.path.join(abs_root, "composer.json")
    composer_content = ""
    if os.path.isfile(composer_json_path):
        try:
            with open(composer_json_path, "r", encoding="utf-8", errors="ignore") as f:
                composer_content = f.read().lower()
        except Exception:
            pass

    # A. Laravel Detection
    is_laravel = (
        "artisan" in root_files or
        "laravel/framework" in composer_content or
        (os.path.isdir(os.path.join(abs_root, "bootstrap")) and os.path.isdir(os.path.join(abs_root, "app", "Http")))
    )
    if is_laravel:
        language = "php"
        framework = "laravel"
        public_dir = os.path.join(abs_root, "public")
        if os.path.isdir(public_dir):
            public_root = public_dir
            if os.path.isfile(os.path.join(public_dir, "index.php")):
                entry_files.append(os.path.join(public_dir, "index.php"))
        if os.path.isfile(os.path.join(abs_root, "artisan")):
            entry_files.append(os.path.join(abs_root, "artisan"))
        # Laravel mandatory writable directories (prevent 500 error if permissions too strict)
        for sdir in ["storage", "storage/logs", "storage/framework", "storage/framework/views", "storage/framework/sessions", "storage/framework/cache", "bootstrap/cache"]:
            p = os.path.join(abs_root, sdir)
            if os.path.isdir(p):
                writable_dirs.append(p)

    # B. WordPress Detection
    elif "wp-config.php" in root_files or os.path.isdir(os.path.join(abs_root, "wp-content")):
        language = "php"
        framework = "wordpress"
        public_root = abs_root
        if "index.php" in root_files:
            entry_files.append(os.path.join(abs_root, "index.php"))
        if "wp-config.php" in root_files:
            entry_files.append(os.path.join(abs_root, "wp-config.php"))
        wp_uploads = os.path.join(abs_root, "wp-content", "uploads")
        if os.path.isdir(wp_uploads):
            writable_dirs.append(wp_uploads)

    # C. CodeIgniter 4 Detection
    elif "spark" in root_files or ("codeigniter4/framework" in composer_content):
        language = "php"
        framework = "codeigniter4"
        public_dir = os.path.join(abs_root, "public")
        if os.path.isdir(public_dir):
            public_root = public_dir
            if os.path.isfile(os.path.join(public_dir, "index.php")):
                entry_files.append(os.path.join(public_dir, "index.php"))
        ci_writable = os.path.join(abs_root, "writable")
        if os.path.isdir(ci_writable):
            writable_dirs.append(ci_writable)

    # D. CodeIgniter 3 Detection
    elif os.path.isdir(os.path.join(abs_root, "application", "config")) and "index.php" in root_files:
        language = "php"
        framework = "codeigniter3"
        public_root = abs_root
        entry_files.append(os.path.join(abs_root, "index.php"))

    # E. Symfony Detection
    elif os.path.isdir(os.path.join(abs_root, "bin")) and os.path.isfile(os.path.join(abs_root, "bin", "console")):
        language = "php"
        framework = "symfony"
        public_dir = os.path.join(abs_root, "public")
        if os.path.isdir(public_dir):
            public_root = public_dir
            if os.path.isfile(os.path.join(public_dir, "index.php")):
                entry_files.append(os.path.join(public_dir, "index.php"))
        sym_var = os.path.join(abs_root, "var")
        if os.path.isdir(sym_var):
            writable_dirs.append(sym_var)

    # F. Native PHP Detection
    elif any(f.endswith((".php", ".phtml", ".inc")) for f in root_files):
        language = "php"
        framework = "native"
        public_root = abs_root
        if "index.php" in root_files:
            entry_files.append(os.path.join(abs_root, "index.php"))
        else:
            for f in sorted(root_files):
                if f.endswith(".php"):
                    entry_files.append(os.path.join(abs_root, f))
                    break

    # ─────────────────────────────────────────────────────────────────────
    # 2. PYTHON ECOSYSTEM DETECTION (Django, Flask, FastAPI, Tornado)
    # ─────────────────────────────────────────────────────────────────────
    req_txt_path = os.path.join(abs_root, "requirements.txt")
    req_content = ""
    if os.path.isfile(req_txt_path):
        try:
            with open(req_txt_path, "r", encoding="utf-8", errors="ignore") as f:
                req_content = f.read().lower()
        except Exception:
            pass

    # A. Django Detection
    if "manage.py" in root_files or "django" in req_content:
        language = "python"
        framework = "django"
        public_root = abs_root
        if "manage.py" in root_files:
            entry_files.append(os.path.join(abs_root, "manage.py"))
        for candidate in ["wsgi.py", "asgi.py"]:
            for r, _, fs in os.walk(abs_root):
                if candidate in fs:
                    entry_files.append(os.path.join(r, candidate))
                    break
        for mdir in ["media", "static", "staticfiles"]:
            p = os.path.join(abs_root, mdir)
            if os.path.isdir(p):
                writable_dirs.append(p)

    # B. FastAPI Detection
    elif "fastapi" in req_content or any("fastapi" in f for f in root_files):
        language = "python"
        framework = "fastapi"
        public_root = abs_root
        for candidate in ["main.py", "app.py", "server.py", "api.py"]:
            if candidate in root_files:
                entry_files.append(os.path.join(abs_root, candidate))

    # C. Flask / Native Python Detection
    elif language == "unknown" and (
        "app.py" in root_files or "main.py" in root_files or "wsgi.py" in root_files or
        any(f.endswith(".py") for f in root_files) or "flask" in req_content
    ):
        language = "python"
        # Distinguish Flask from generic Python
        is_flask = "flask" in req_content
        if not is_flask:
            for pyf in ["app.py", "main.py", "server.py", "wsgi.py"]:
                if pyf in root_files:
                    try:
                        with open(os.path.join(abs_root, pyf), "r", encoding="utf-8", errors="ignore") as pf:
                            if "from flask" in pf.read() or "import flask" in pf.read():
                                is_flask = True
                                break
                    except Exception:
                        pass
        framework = "flask" if is_flask else "native"
        public_root = abs_root
        for candidate in ["app.py", "main.py", "wsgi.py", "server.py", "run.py"]:
            if candidate in root_files:
                entry_files.append(os.path.join(abs_root, candidate))

    # ─────────────────────────────────────────────────────────────────────
    # 3. NODE.JS ECOSYSTEM DETECTION (Express, NestJS, Next.js)
    # ─────────────────────────────────────────────────────────────────────
    package_json_path = os.path.join(abs_root, "package.json")
    if language == "unknown" and os.path.isfile(package_json_path):
        language = "node"
        pkg_content = ""
        try:
            with open(package_json_path, "r", encoding="utf-8", errors="ignore") as f:
                pkg_content = f.read().lower()
        except Exception:
            pass
        if "@nestjs/core" in pkg_content:
            framework = "nestjs"
        elif "next" in pkg_content:
            framework = "nextjs"
        elif "express" in pkg_content:
            framework = "express"
        elif "fastify" in pkg_content:
            framework = "fastify"
        else:
            framework = "native"
        public_root = os.path.join(abs_root, "public") if os.path.isdir(os.path.join(abs_root, "public")) else abs_root
        for candidate in ["server.js", "app.js", "index.js", "main.js", "dist/main.js"]:
            p = os.path.join(abs_root, candidate)
            if os.path.isfile(p):
                entry_files.append(p)

    # ─────────────────────────────────────────────────────────────────────
    # 4. JAVA / SPRING BOOT DETECTION
    # ─────────────────────────────────────────────────────────────────────
    if language == "unknown" and ("pom.xml" in root_files or "build.gradle" in root_files or any(f.endswith(".jar") for f in root_files)):
        language = "java"
        framework = "spring" if "pom.xml" in root_files else "native"
        public_root = abs_root

    # ─────────────────────────────────────────────────────────────────────
    # 5. GO / RUST / STATIC DETECTION
    # ─────────────────────────────────────────────────────────────────────
    if language == "unknown":
        if "go.mod" in root_files or any(f.endswith(".go") for f in root_files):
            language = "go"
            framework = "native"
        elif "Cargo.toml" in root_files or any(f.endswith(".rs") for f in root_files):
            language = "rust"
            framework = "native"
        elif "index.html" in root_files:
            language = "static"
            framework = "native"
            entry_files.append(os.path.join(abs_root, "index.html"))

    # Common uploads / temp writable directory check across all frameworks
    for udir in ["uploads", "upload", "temp", "tmp", "public/uploads", "public/upload"]:
        up = os.path.join(abs_root, udir)
        if os.path.isdir(up) and up not in writable_dirs:
            writable_dirs.append(up)

    return (language, framework, public_root, version_hint, entry_files, writable_dirs)


def detect_environment(custom_webroot: Optional[str] = None) -> EnvironmentInfo:
    """Master environment inspection function.
    
    Robust against strange server configurations, custom webroots, and unexpected process environments.
    """
    env = EnvironmentInfo()
    env.is_docker = detect_is_docker()
    env.is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

    # 1. Discover Process List (ps aux)
    ps_out = _safe_run(["ps", "aux"]).lower()

    # Detect Web Server Process
    if "nginx" in ps_out:
        env.server = "nginx"
    elif "apache2" in ps_out or "httpd" in ps_out:
        env.server = "apache"
    elif "caddy" in ps_out:
        env.server = "caddy"
    elif "lighttpd" in ps_out:
        env.server = "lighttpd"
    elif "gunicorn" in ps_out or "uvicorn" in ps_out:
        env.server = "gunicorn" if "gunicorn" in ps_out else "uvicorn"
    elif "pm2" in ps_out or ("node" in ps_out and "server" in ps_out):
        env.server = "node-http"
    elif "php -s" in ps_out or "artisan serve" in ps_out:
        env.server = "php-builtin"
    else:
        # Fallback to checking installed server binaries
        if shutil.which("nginx"):
            env.server = "nginx"
        elif shutil.which("apache2") or shutil.which("httpd"):
            env.server = "apache"

    # Server version detection
    if env.server == "nginx":
        ver = _safe_run(["nginx", "-v"])
        m = re.search(r"nginx/([\d.]+)", ver)
        if m:
            env.server_version = m.group(1)
    elif env.server == "apache":
        ver = _safe_run(["apache2", "-v"]) or _safe_run(["httpd", "-v"])
        m = re.search(r"Apache/([\d.]+)", ver)
        if m:
            env.server_version = m.group(1)

    # 2. Discover Best Web Root
    chosen_root = ""
    if custom_webroot and os.path.isdir(custom_webroot):
        chosen_root = os.path.abspath(custom_webroot)
    else:
        for cand in DEFAULT_SEARCH_ROOTS:
            if os.path.isdir(cand):
                cand_abs = os.path.abspath(cand)
                try:
                    files = os.listdir(cand_abs)
                    has_code = any(f.endswith((".php", ".py", ".js", ".html", ".json", ".lock", ".env")) or f in ("artisan", "manage.py", "app.py", "package.json", "composer.json", "index.php") for f in files)
                    if has_code or cand in ("/var/www/html", "/app"):
                        chosen_root = cand_abs
                        break
                except Exception:
                    pass

    if not chosen_root:
        chosen_root = os.path.abspath(".")

    env.webroot = chosen_root

    # 3. Inspect Language, Framework, Public Webroot & Writable Dirs
    lang, fw, pub_root, ver_hint, entries, w_dirs = detect_framework_and_stack(chosen_root)
    env.language = lang
    env.framework = fw
    env.public_webroot = pub_root
    env.entry_files = entries
    env.writable_dirs = w_dirs

    # Language version detection
    if env.language == "php":
        pver = _safe_run(["php", "-v"])
        m = re.search(r"PHP ([\d.]+)", pver)
        if m:
            env.language_version = m.group(1)
        env.php_ini_paths = find_php_ini_files()
    elif env.language == "python":
        env.language_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    elif env.language == "node":
        nver = _safe_run(["node", "-v"]).strip()
        env.language_version = nver.lstrip("v")

    # 4. Discover Listening Ports & Primary SLA Port
    env.active_ports = get_listening_ports()
    if 80 in env.active_ports:
        env.primary_port = 80
    elif 8080 in env.active_ports:
        env.primary_port = 8080
    elif 5000 in env.active_ports:
        env.primary_port = 5000
    elif 8000 in env.active_ports:
        env.primary_port = 8000
    elif 3000 in env.active_ports:
        env.primary_port = 3000
    elif env.active_ports:
        env.primary_port = env.active_ports[0]
    else:
        env.primary_port = 80

    # 5. Database Discovery
    if "mysql" in ps_out or "mariadb" in ps_out or 3306 in env.active_ports:
        env.databases.append("mysql")
    if "postgres" in ps_out or 5432 in env.active_ports:
        env.databases.append("postgresql")
    if "redis" in ps_out or 6379 in env.active_ports:
        env.databases.append("redis")
    if "mongod" in ps_out or 27017 in env.active_ports:
        env.databases.append("mongodb")

    # SQLite file scanner
    for r, dirs, files in os.walk(chosen_root):
        # Ignore heavy dirs
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "vendor", ".adctf")]
        for f in files:
            if f.endswith((".sqlite", ".sqlite3", ".db", ".s3db")):
                db_path = os.path.join(r, f)
                env.sqlite_dbs.append(db_path)
                if "sqlite" not in env.databases:
                    env.databases.append("sqlite")

    return env


def print_environment_summary(env: EnvironmentInfo) -> None:
    """Print a clean tactical diagnostic summary of the detected environment."""
    safe_print(colorize("\n" + "═" * 75, Colors.BRIGHT_CYAN))
    safe_print(colorize(" 🌐 ADAPTIVE HOST & STACK RECONNAISSANCE", Colors.BOLD + Colors.BRIGHT_WHITE))
    safe_print(colorize("═" * 75, Colors.BRIGHT_CYAN))

    # Server badge
    server_badge = f"{env.server.upper()} {env.server_version}".strip()
    safe_print(f" ├─ Web Server        : {colorize(server_badge, Colors.BOLD + Colors.GREEN)}")

    # Language & Framework badge
    lang_badge = f"{env.language.upper()} {env.language_version}".strip()
    fw_badge = f"{env.framework.upper()}"
    safe_print(f" ├─ Stack & Framework : {colorize(lang_badge, Colors.CYAN)} [{colorize(fw_badge, Colors.BOLD + Colors.BRIGHT_YELLOW)}]")

    # Paths
    safe_print(f" ├─ Project Webroot   : {colorize(env.webroot, Colors.BOLD + Colors.BRIGHT_WHITE)}")
    if env.public_webroot != env.webroot:
        safe_print(f" ├─ Public Entry Root : {colorize(env.public_webroot, Colors.BOLD + Colors.BRIGHT_GREEN)} ({colorize('DocumentRoot for WAF/SLA', Colors.DIM)})")

    # Entry files
    if env.entry_files:
        entries_str = ", ".join(os.path.basename(e) for e in env.entry_files[:4])
        safe_print(f" ├─ Entry Point Files : {colorize(entries_str, Colors.CYAN)}")

    # Active Ports
    ports_str = ", ".join(str(p) for p in env.active_ports[:8]) if env.active_ports else "None detected"
    safe_print(f" ├─ Active Ports      : {colorize(ports_str, Colors.GREEN)} (Primary SLA Port: {colorize(str(env.primary_port), Colors.BOLD + Colors.BRIGHT_GREEN)})")

    # Databases
    dbs_str = ", ".join(env.databases).upper() if env.databases else "None detected"
    safe_print(f" ├─ Databases Found   : {colorize(dbs_str, Colors.YELLOW)}")
    if env.sqlite_dbs:
        safe_print(f" │  └─ SQLite Files   : {colorize(str(len(env.sqlite_dbs)) + ' file(s)', Colors.DIM)}")

    # Writable Dirs
    if env.writable_dirs:
        wdirs_str = ", ".join(os.path.relpath(w, env.webroot) for w in env.writable_dirs[:4])
        safe_print(f" ├─ Framework Storage : {colorize(wdirs_str, Colors.CYAN)} (Protected from strict chmod)")

    # Docker & Privileges
    env_type = "Docker Container" if env.is_docker else "Bare Metal / VM"
    priv_str = "root" if env.is_root else "standard user"
    safe_print(f" └─ Host Environment  : {colorize(env_type, Colors.DIM)} ({colorize(priv_str, Colors.YELLOW)})")
    safe_print(colorize("═" * 75, Colors.BRIGHT_CYAN) + "\n")
