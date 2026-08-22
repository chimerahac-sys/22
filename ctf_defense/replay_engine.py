#!/usr/bin/env python3
"""Attack Replay Engine for Attack-Defense CTF.

Reads attacks captured by the Log Analyzer and automatically replays them
against all opponent teams (10.x.y.z) with concurrency and regex flag extraction.
"""

import argparse
import concurrent.futures
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.parse
    HAS_REQUESTS = False

from .colors import Colors, colorize, safe_print, print_banner
from .health_checker import TargetParser


class ReplayEngine:
    """Replays captured exploits against enemy infrastructure with thread-pool concurrency."""

    DEFAULT_FLAG_REGEX = re.compile(r"(?:FLAG|flag|CTF)\{[A-Za-z0-9_\-]{16,64}\}")

    def __init__(
        self,
        target_hosts: List[str],
        port: int = 80,
        protocol: str = "http",
        delay: float = 0.1,
        timeout: float = 3.0,
        threads: int = 10,
        flag_pattern: Optional[str] = None,
        flags_file: str = "captured_flags.txt",
    ):
        self.target_hosts = target_hosts
        self.port = port
        self.protocol = protocol
        self.delay = delay
        self.timeout = timeout
        self.threads = max(1, threads)
        self.flag_regex = re.compile(flag_pattern) if flag_pattern else self.DEFAULT_FLAG_REGEX
        self.flags_file = Path(flags_file)
        self.captured_flags: Set[str] = set()

        if HAS_REQUESTS:
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": "Mozilla/5.0 (Security-Audit-Replay/2.0)"})
            adapter = HTTPAdapter(pool_connections=self.threads * 2, pool_maxsize=self.threads * 2)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
        else:
            self.session = None

    def load_captured_attacks(self, jsonl_file: str) -> List[dict]:
        """Load captured attacks from log analyzer JSONL output."""
        attacks = []
        p = Path(jsonl_file)
        if not p.exists():
            return attacks

        seen_uris = set()
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    key = f"{data.get('method')}:{data.get('uri')}"
                    if key not in seen_uris:
                        seen_uris.add(key)
                        attacks.append(data)
                except Exception:
                    pass
        return attacks

    def replay_single(self, host: str, method: str, uri: str, body: Optional[str] = None) -> List[str]:
        """Fire a single exploit against a target host and extract flags."""
        url = f"{self.protocol}://{host}:{self.port}{uri}"
        found_flags = []

        try:
            if HAS_REQUESTS:
                resp = self.session.request(
                    method=method.upper(),
                    url=url,
                    data=body,
                    timeout=(1.5, self.timeout),
                    allow_redirects=True,
                )
                response_text = resp.text
            else:
                req = urllib.request.Request(
                    url,
                    data=body.encode("utf-8") if body else None,
                    method=method.upper(),
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    response_text = resp.read().decode("utf-8", errors="replace")

            # Extract flags from response
            matches = self.flag_regex.findall(response_text)
            for m in matches:
                flag_str = m if isinstance(m, str) else m[0]
                if flag_str not in self.captured_flags:
                    self.captured_flags.add(flag_str)
                    found_flags.append(flag_str)
                    self._save_flag(host, flag_str)

        except Exception:
            pass

        return found_flags

    def _save_flag(self, host: str, flag: str) -> None:
        """Append newly captured flag to file."""
        try:
            with open(self.flags_file, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {host} -> {flag}\n")
        except Exception:
            pass

    def run_replay(self, attacks_file: str) -> None:
        """Iterate over all captured attacks and blast them against enemy hosts with thread pool."""
        attacks = self.load_captured_attacks(attacks_file)
        print_banner("Attack Replay Engine", "Opponent Exploit Mirror & Flag Extractor")
        safe_print(f"[*] Opponent Targets  : {colorize(str(len(self.target_hosts)), Colors.BOLD + Colors.GREEN)}")
        safe_print(f"[*] Attacks Loaded    : {colorize(str(len(attacks)), Colors.BOLD + Colors.CYAN)} unique payloads")
        safe_print(f"[*] Concurrency       : {colorize(str(self.threads) + ' worker threads', Colors.YELLOW)}")
        safe_print(f"[*] Flag Output File  : {colorize(str(self.flags_file), Colors.YELLOW)}")
        safe_print(colorize("-" * 75, Colors.DIM))
        safe_print("")

        if not attacks:
            safe_print(colorize(f"[!] No attacks found in {attacks_file}. Run 'defense_tool.py monitor' first!", Colors.BRIGHT_RED))
            return

        for a_idx, attack in enumerate(attacks, 1):
            method = attack.get("method", "GET")
            uri = attack.get("uri", "/")
            sig = ",".join(attack.get("signatures", []))
            safe_print(colorize(f"\n[>] Replaying Payload #{a_idx} [{sig}] ({method} {uri[:60]}...)", Colors.BOLD + Colors.BRIGHT_WHITE))

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_host = {
                    executor.submit(self.replay_single, host, method, uri): host
                    for host in self.target_hosts
                }

                for future in concurrent.futures.as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        flags = future.result()
                        if flags:
                            for fl in flags:
                                safe_print(f"   [+] {colorize(host, Colors.CYAN)} -> 🚩 {colorize(fl, Colors.BOLD + Colors.BRIGHT_GREEN)}")
                        else:
                            safe_print(f"   [.] {host} -> No flag")
                    except Exception:
                        safe_print(f"   [!] {host} -> Connection error")

        safe_print(colorize("\n" + "=" * 75, Colors.BRIGHT_CYAN))
        safe_print(colorize(f"[*] Replay round complete. Total new flags captured: {len(self.captured_flags)}", Colors.BOLD + Colors.BRIGHT_WHITE))


def replay_attacks(
    targets: List[str],
    port: int = 80,
    threads: int = 10,
    delay: float = 0.5,
    timeout: int = 3,
    attack_file: str = "captured_attacks.jsonl",
    flag_output: str = "captured_flags.txt",
) -> int:
    expanded = []
    for t in targets:
        expanded.extend(TargetParser.expand_range(t))
    expanded = list(dict.fromkeys(expanded))

    engine = ReplayEngine(
        target_hosts=expanded,
        port=port,
        delay=delay,
        threads=threads,
        timeout=timeout,
        flags_file=flag_output,
    )
    engine.run_replay(attack_file)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-threaded CTF attack replay engine")
    parser.add_argument("attacks", type=str, help="Captured attack JSONL file")
    parser.add_argument("--targets", "-t", type=str, required=True, help="Target IP or range")
    parser.add_argument("--port", "-p", type=int, default=80, help="Target port")
    parser.add_argument("--delay", "-d", type=float, default=0.5, help="Delay between requests")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent threads")
    parser.add_argument("--pattern", type=str, default=None, help="Flag regex pattern")
    parser.add_argument("--output", "-o", type=str, default="captured_flags.txt", help="Flag output file")

    args = parser.parse_args()
    targets = TargetParser.expand_range(args.targets)

    engine = ReplayEngine(
        target_hosts=targets,
        port=args.port,
        delay=args.delay,
        threads=args.threads,
        flag_pattern=args.pattern,
        flags_file=args.output,
    )
    engine.run_replay(args.attacks)


if __name__ == "__main__":
    main()
