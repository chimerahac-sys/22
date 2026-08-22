#!/usr/bin/env python3
"""Automated Flag Submitter for Attack-Defense CTF.

Supports:
  - HTTP REST API (POST JSON or Form-Data)
  - TCP Raw Socket (e.g. nc flags.ctf.game 1337)
  - Flag deduplication & persistent submission history
  - Live flag queue processing
"""

import argparse
import json
import re
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Tuple

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    HAS_REQUESTS = False

from .colors import Colors, colorize, safe_print, print_banner


class FlagSubmitter:
    """Submits flags to competition game server."""

    def __init__(
        self,
        server_url: str,
        token: Optional[str] = None,
        proto: str = "http",
        tcp_host: Optional[str] = None,
        tcp_port: int = 1337,
        history_file: str = "submitted_flags.txt",
    ):
        self.server_url = server_url
        self.token = token
        self.proto = proto
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        self.history_file = Path(history_file)
        self.submitted_flags: Set[str] = self._load_history()

    def _load_history(self) -> Set[str]:
        """Load already submitted flags to prevent duplicate penalties."""
        if not self.history_file.exists():
            return set()
        seen = set()
        with open(self.history_file, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if parts:
                    seen.add(parts[-1])
        return seen

    def _record_submission(self, flag: str, status: str) -> None:
        """Append submitted flag record to log file."""
        try:
            with open(self.history_file, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{status}] {flag}\n")
        except Exception:
            pass

    def submit_http(self, flag: str) -> Tuple[bool, str]:
        """Submit single flag via HTTP API."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "CTF-FlagSubmitter/2.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
            headers["X-Team-Token"] = self.token

        payload = {"flag": flag, "token": self.token}

        try:
            if HAS_REQUESTS:
                resp = requests.post(self.server_url, json=payload, headers=headers, timeout=4.0)
                resp_text = resp.text
                is_ok = resp.status_code in (200, 201) and ("success" in resp_text.lower() or "accepted" in resp_text.lower() or "correct" in resp_text.lower())
                return is_ok, resp_text
            else:
                req = urllib.request.Request(
                    self.server_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=4.0) as resp:
                    resp_text = resp.read().decode("utf-8")
                    return True, resp_text
        except Exception as e:
            return False, str(e)

    def submit_tcp(self, flag: str) -> Tuple[bool, str]:
        """Submit single flag via TCP raw socket."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(4.0)
                s.connect((self.tcp_host or "127.0.0.1", self.tcp_port))
                s.sendall(f"{flag}\n".encode("utf-8"))
                resp = s.recv(1024).decode("utf-8", errors="replace")
                return True, resp.strip()
        except Exception as e:
            return False, str(e)

    def submit_flags(self, flags: List[str]) -> None:
        """Batch submit a list of flags."""
        new_flags = [f for f in flags if f not in self.submitted_flags]
        print_banner("Automated Flag Submitter", "Scoring Engine Gateway")
        safe_print(f"[*] Queue Size        : {len(flags)} total | {len(new_flags)} new")
        safe_print(f"[*] Submission Target : {self.server_url if self.proto == 'http' else f'{self.tcp_host}:{self.tcp_port}'}")
        safe_print(colorize("-" * 75, Colors.DIM))

        if not new_flags:
            safe_print(colorize("[*] All flags in queue have already been submitted.", Colors.YELLOW))
            return

        for flag in new_flags:
            if self.proto == "http":
                ok, msg = self.submit_http(flag)
            else:
                ok, msg = self.submit_tcp(flag)

            self.submitted_flags.add(flag)
            status_str = "ACCEPTED" if ok else "FAILED"
            self._record_submission(flag, status_str)

            if ok:
                safe_print(f" [✓] {colorize(flag, Colors.BOLD + Colors.BRIGHT_GREEN)} -> {colorize(msg[:50], Colors.GREEN)}")
            else:
                safe_print(f" [✗] {colorize(flag, Colors.BRIGHT_RED)} -> {colorize(msg[:50], Colors.YELLOW)}")

            time.sleep(0.2)


def main() -> None:
    parser = argparse.ArgumentParser(description="CTF Flag Submitter")
    parser.add_argument("--url", "-u", type=str, default="http://10.0.0.1/api/submit_flag", help="Scoring server submission URL")
    parser.add_argument("--token", "-t", type=str, default=None, help="Team API token")
    parser.add_argument("--flag", "-f", type=str, default=None, help="Single flag to submit")
    parser.add_argument("--file", type=str, default="captured_flags.txt", help="File containing flags (one per line)")
def submit_flags(
    url: str = "http://10.0.0.1/api/submit_flag",
    token: Optional[str] = None,
    flag: Optional[str] = None,
    flag_file: str = "captured_flags.txt",
    tcp_host: Optional[str] = None,
    tcp_port: int = 1337,
) -> int:
    flags = []
    if flag:
        flags.append(flag)
    elif Path(flag_file).exists():
        with open(flag_file, "r", encoding="utf-8") as f:
            for line in f:
                m = re.search(r"(?:FLAG|flag|CTF)\{[A-Za-z0-9_\-]+\}", line)
                if m:
                    flags.append(m.group(0))

    flags = list(dict.fromkeys(flags))
    proto = "tcp" if tcp_host else "http"
    submitter = FlagSubmitter(
        server_url=url,
        token=token,
        proto=proto,
        tcp_host=tcp_host,
        tcp_port=tcp_port,
    )
    submitter.submit_flags(flags)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="CTF Flag Submitter")
    parser.add_argument("--url", "-u", type=str, default="http://10.0.0.1/api/submit_flag", help="Scoring server submission URL")
    parser.add_argument("--token", "-t", type=str, default=None, help="Team API token")
    parser.add_argument("--flag", "-f", type=str, default=None, help="Single flag to submit")
    parser.add_argument("--file", default="captured_flags.txt", help="File containing flags (one per line)")
    parser.add_argument("--tcp", type=str, default=None, help="TCP Host for raw flag socket (e.g. 10.0.0.1)")
    parser.add_argument("--tcp-port", type=int, default=1337, help="TCP Port")

    args = parser.parse_args()
    submit_flags(url=args.url, token=args.token, flag=args.flag, flag_file=args.file, tcp_host=args.tcp, tcp_port=args.tcp_port)


if __name__ == "__main__":
    main()
