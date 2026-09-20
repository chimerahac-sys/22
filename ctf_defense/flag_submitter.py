#!/usr/bin/env python3
"""Automated, Reliable Flag Submitter with Persistent SQLite Retry Queue for CTF.

Supports:
  - HTTP REST API (POST JSON / Form Data)
  - TCP Raw Socket (e.g. nc flags.ctf.game 1337)
  - SQLite persistent queue (survives crashes & network drops)
  - Automatic exponential retry buffer for failed flags (HTTP 502/504)
  - Broad flag format regex parsing (FLAG, JCSC, CTF, etc.)
"""

import argparse
import json
import os
import re
import socket
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set, Tuple

import urllib.request
import urllib.parse
import urllib.error

from .colors import Colors, colorize, safe_print, print_banner
from .patterns import FLAG_REGEX, compile_flag_regex

QUEUE_DB_DEFAULT = os.path.expanduser("~/.adctf/state.db")


def get_queue_db(db_path: str = QUEUE_DB_DEFAULT) -> sqlite3.Connection:
    """Initialize persistent queue database with WAL mode for concurrency."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS flag_queue(
        flag TEXT PRIMARY KEY,
        token TEXT,
        status TEXT DEFAULT 'PENDING',  -- PENDING, ACCEPTED, REJECTED, EXPIRED
        attempts INTEGER DEFAULT 0,
        first_seen TEXT,
        last_attempt TEXT,
        server_response TEXT
    );
    """)
    conn.commit()
    return conn


class FlagSubmitter:
    """Submits flags to competition game server with persistent retry queue."""

    def __init__(
        self,
        server_url: str = "http://10.0.0.1/api/submit_flag",
        token: Optional[str] = None,
        proto: str = "http",
        tcp_host: Optional[str] = None,
        tcp_port: int = 1337,
        db_path: str = QUEUE_DB_DEFAULT,
        history_file: str = "submitted_flags.txt",
    ):
        self.server_url = server_url
        self.token = token
        self.proto = proto
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        self.db_path = db_path
        self.history_file = Path(history_file)

    def enqueue_flag(self, flag: str, token: Optional[str] = None) -> bool:
        """Enqueue a newly discovered flag into SQLite queue."""
        tok = token or self.token
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            conn = get_queue_db(self.db_path)
            conn.execute(
                "INSERT OR IGNORE INTO flag_queue(flag, token, status, attempts, first_seen, last_attempt) VALUES (?, ?, 'PENDING', 0, ?, ?)",
                (flag, tok, now, now),
            )
            conn.commit()
            conn.close()
            return True
        except Exception:
            return False

    def submit_http(self, flag: str, token: Optional[str] = None) -> Tuple[bool, str, bool]:
        """Submit single flag via HTTP API. Returns (is_accepted, msg, is_permanent)."""
        tok = token or self.token
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "CTF-FlagSubmitter/3.0",
        }
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
            headers["X-Team-Token"] = tok

        payload = {"flag": flag, "token": tok}

        try:
            req = urllib.request.Request(
                self.server_url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                resp_text = resp.read().decode("utf-8", errors="replace")
                low = resp_text.lower()

                # Classification
                if any(w in low for w in ("success", "accepted", "correct", "valid", "earned", "point")):
                    return True, resp_text, True
                elif any(w in low for w in ("already", "duplicate", "dup", "claimed")):
                    return False, f"Already submitted: {resp_text[:40]}", True
                elif any(w in low for w in ("invalid", "wrong", "fake", "bad flag")):
                    return False, f"Invalid: {resp_text[:40]}", True
                elif any(w in low for w in ("expired", "old", "round ended")):
                    return False, f"Expired: {resp_text[:40]}", True
                else:
                    return True, resp_text, True
        except urllib.error.HTTPError as e:
            code = e.code
            err_text = e.read().decode("utf-8", errors="replace")
            # 500, 502, 503, 504 are temporary server errors (SHOULD RETRY)
            if code in (500, 502, 503, 504, 429):
                return False, f"HTTP {code} Gateway/Server Error: {err_text[:30]}", False
            return False, f"HTTP {code}: {err_text[:40]}", True
        except Exception as e:
            # Network drop / timeout (SHOULD RETRY)
            return False, f"Network error: {str(e)[:40]}", False

    def submit_tcp(self, flag: str) -> Tuple[bool, str, bool]:
        """Submit single flag via TCP raw socket."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(4.0)
                s.connect((self.tcp_host or "127.0.0.1", self.tcp_port))
                s.sendall(f"{flag}\n".encode("utf-8"))
                resp = s.recv(1024).decode("utf-8", errors="replace").strip()
                low = resp.lower()
                is_accepted = any(w in low for w in ("success", "accepted", "correct", "valid", "1"))
                return is_accepted, resp, True
        except Exception as e:
            return False, f"Socket error: {str(e)[:40]}", False

    def process_queue(self, max_batch: int = 50) -> int:
        """Process all pending and failed-retry flags from SQLite queue."""
        conn = get_queue_db(self.db_path)
        rows = conn.execute(
            "SELECT flag, token, attempts FROM flag_queue WHERE status = 'PENDING' AND attempts < 10 ORDER BY attempts ASC LIMIT ?",
            (max_batch,),
        ).fetchall()

        if not rows:
            conn.close()
            return 0

        submitted_count = 0
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")

        for r in rows:
            flag = r["flag"]
            tok = r["token"]
            attempts = r["attempts"] + 1

            if self.proto == "http":
                ok, msg, is_permanent = self.submit_http(flag, tok)
            else:
                ok, msg, is_permanent = self.submit_tcp(flag)

            new_status = "PENDING"
            if ok:
                new_status = "ACCEPTED"
                submitted_count += 1
                safe_print(f" [✓] {colorize(flag, Colors.BOLD + Colors.BRIGHT_GREEN)} -> {colorize(msg[:45], Colors.GREEN)}")
            elif is_permanent:
                new_status = "REJECTED"
                safe_print(f" [✗] {colorize(flag, Colors.BRIGHT_RED)} -> {colorize(msg[:45], Colors.YELLOW)}")
            else:
                new_status = "PENDING"
                safe_print(f" [↻] {colorize(flag, Colors.YELLOW)} -> {colorize(f'{msg[:40]} (Will retry #{attempts})', Colors.DIM)}")

            conn.execute(
                "UPDATE flag_queue SET status=?, attempts=?, last_attempt=?, server_response=? WHERE flag=?",
                (new_status, attempts, now, msg[:100], flag),
            )
            conn.commit()

            # Record in text log
            try:
                with open(self.history_file, "a", encoding="utf-8") as f:
                    f.write(f"[{datetime.now().strftime('%H:%M:%S')}] [{new_status}] {flag} -> {msg[:50]}\n")
            except Exception:
                pass

            time.sleep(0.2)

        conn.close()
        return submitted_count


def submit_flags(
    url: str = "http://10.0.0.1/api/submit_flag",
    token: Optional[str] = None,
    flag: Optional[str] = None,
    flag_file: str = "captured_flags.txt",
    tcp_host: Optional[str] = None,
    tcp_port: int = 1337,
    db_path: str = QUEUE_DB_DEFAULT,
    flag_pattern: Optional[str] = None,
) -> int:
    """Entrypoint to enqueue flags and flush the queue to game server."""
    submitter = FlagSubmitter(
        server_url=url,
        token=token,
        proto="tcp" if tcp_host else "http",
        tcp_host=tcp_host,
        tcp_port=tcp_port,
        db_path=db_path,
    )

    rgx = compile_flag_regex(flag_pattern)
    enqueued = 0

    if flag:
        submitter.enqueue_flag(flag.strip(), token)
        enqueued += 1
    elif Path(flag_file).exists():
        with open(flag_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                for match in rgx.findall(line):
                    submitter.enqueue_flag(match, token)
                    enqueued += 1

    print_banner("Automated Flag Submitter", "Scoring Engine Gateway with Retry Queue")
    safe_print(f"[*] Enqueued Flags    : {enqueued} candidates")
    safe_print(f"[*] Target Endpoint   : {url if not tcp_host else f'{tcp_host}:{tcp_port}'}")
    safe_print(colorize("-" * 75, Colors.DIM))

    ok_count = submitter.process_queue()
    safe_print(colorize("-" * 75, Colors.DIM))
    safe_print(f"[*] Selesai. Total flag diterima: {colorize(str(ok_count), Colors.BOLD + Colors.BRIGHT_GREEN)}\n")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Reliable CTF Flag Submitter")
    parser.add_argument("--url", "-u", type=str, default="http://10.0.0.1/api/submit_flag", help="Scoring server submission URL")
    parser.add_argument("--token", "-t", type=str, default=None, help="Team API token")
    parser.add_argument("--flag", "-f", type=str, default=None, help="Single flag to submit")
    parser.add_argument("--file", default="captured_flags.txt", help="File containing flags (one per line)")
    parser.add_argument("--tcp", type=str, default=None, help="TCP Host for raw flag socket (e.g. 10.0.0.1)")
    parser.add_argument("--tcp-port", type=int, default=1337, help="TCP Port")
    parser.add_argument("--pattern", default=None, help="Custom flag regex pattern")

    args = parser.parse_args()
    submit_flags(
        url=args.url,
        token=args.token,
        flag=args.flag,
        flag_file=args.file,
        tcp_host=args.tcp,
        tcp_port=args.tcp_port,
        flag_pattern=args.pattern,
    )


if __name__ == "__main__":
    main()
