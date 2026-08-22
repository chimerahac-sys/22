#!/usr/bin/env python3
"""Web Health Check & API Response Parser (Automated Testing).

Controlled, rate-limited service availability tester and token/flag extraction
engine designed for internal CTF networks (10.x.x.x).
"""

import argparse
import ipaddress
import json
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Use requests with graceful fallback to urllib.request
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False

from .colors import Colors, colorize, safe_print, print_banner


@dataclass
class TargetResult:
    target: str
    url: str
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    is_healthy: bool = False
    error_message: Optional[str] = None
    extracted_tokens: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class TargetParser:
    """Expands flexible target specifications into individual IP addresses / URLs."""

    @staticmethod
    def expand_range(spec: str) -> List[str]:
        """Expand IP range strings like '10.10.1.1-10.10.1.20' or '10.60.1-5.1' or CIDR '10.0.0.0/28'."""
        targets = []
        spec = spec.strip()

        if not spec:
            return targets

        # 1. Check for CIDR notation (e.g. 10.10.1.0/28)
        if "/" in spec:
            try:
                net = ipaddress.ip_network(spec, strict=False)
                return [str(ip) for ip in net.hosts()]
            except ValueError:
                pass

        # 2. Check for octet range like 10.60.1-5.1
        octet_range_match = re.match(r"^(\d+)\.(\d+)\.(\d+)-(\d+)\.(\d+)$", spec)
        if octet_range_match:
            o1, o2, start_o3, end_o3, o4 = map(int, octet_range_match.groups())
            for o3 in range(start_o3, end_o3 + 1):
                targets.append(f"{o1}.{o2}.{o3}.{o4}")
            return targets

        # 3. Check for full IP range like 10.10.1.1-10.10.1.20
        ip_range_match = re.match(r"^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$", spec)
        if ip_range_match:
            start_ip = int(ipaddress.IPv4Address(ip_range_match.group(1)))
            end_ip = int(ipaddress.IPv4Address(ip_range_match.group(2)))
            for ip_int in range(start_ip, end_ip + 1):
                targets.append(str(ipaddress.IPv4Address(ip_int)))
            return targets

        # 4. Check for comma-separated list
        if "," in spec:
            for item in spec.split(","):
                targets.extend(TargetParser.expand_range(item))
            return list(dict.fromkeys(targets))

        # Single host/IP
        return [spec]

    @staticmethod
    def load_from_file(file_path: str) -> List[str]:
        """Load target specifications line-by-line from file."""
        p = Path(file_path)
        if not p.exists():
            return []
        targets = []
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.extend(TargetParser.expand_range(line))
        return list(dict.fromkeys(targets))


class HealthChecker:
    """Automated service health checker with rate-limiting and regex token extractor."""

    DEFAULT_FLAG_PATTERNS = [
        r"FLAG\{[A-Za-z0-9_\-]{16,64}\}",
        r"flag\{[A-Za-z0-9_\-]{16,64}\}",
        r"CTF\{[A-Za-z0-9_\-]{16,64}\}",
        r"[A-Za-z0-9]{32}=",
    ]

    def __init__(
        self,
        targets: List[str],
        port: int = 80,
        protocol: str = "http",
        path: str = "/",
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
        timeout: float = 3.0,
        delay: float = 0.5,
        expected_status: int = 200,
        expected_keyword: Optional[str] = None,
        regex_patterns: Optional[List[str]] = None,
        log_file: str = "health_check.log",
        token_file: str = "extracted_tokens.jsonl",
    ):
        self.targets = targets
        self.port = port
        self.protocol = protocol
        self.path = path if path.startswith("/") else f"/{path}"
        self.method = method.upper()
        self.headers = headers or {"User-Agent": "CTF-ServiceHealthChecker/2.0"}
        self.data = data
        self.timeout = timeout
        self.delay = max(0.0, delay)
        self.expected_status = expected_status
        self.expected_keyword = expected_keyword

        # Regex extractors
        patterns_to_compile = regex_patterns or self.DEFAULT_FLAG_PATTERNS
        self.compiled_patterns = [re.compile(p) for p in patterns_to_compile]

        self.log_file = Path(log_file)
        self.token_file = Path(token_file)
        self.seen_tokens: Set[str] = set()

        self._setup_http_session()

    def _setup_http_session(self) -> None:
        """Configure requests session with connection pooling and retry safety."""
        if HAS_REQUESTS:
            self.session = requests.Session()
            self.session.headers.update(self.headers)
            retries = Retry(
                total=1,
                backoff_factor=0.2,
                status_forcelist=[502, 503, 504],
                raise_on_status=False,
            )
            adapter = HTTPAdapter(max_retries=retries, pool_connections=20, pool_maxsize=20)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
        else:
            self.session = None

    def build_url(self, target: str) -> str:
        """Construct full URL from target, port, and path."""
        if target.startswith("http://") or target.startswith("https://"):
            return target
        return f"{self.protocol}://{target}:{self.port}{self.path}"

    def check_target(self, target: str) -> TargetResult:
        """Perform controlled health check on single target."""
        url = self.build_url(target)
        result = TargetResult(target=target, url=url)

        start_time = time.time()
        try:
            if HAS_REQUESTS:
                resp = self.session.request(
                    method=self.method,
                    url=url,
                    data=self.data,
                    timeout=self.timeout,
                    allow_redirects=True,
                )
                elapsed_ms = (time.time() - start_time) * 1000.0
                result.status_code = resp.status_code
                result.response_time_ms = round(elapsed_ms, 2)
                response_text = resp.text
            else:
                # Fallback to standard library urllib
                req = urllib.request.Request(
                    url,
                    data=self.data.encode("utf-8") if self.data else None,
                    headers=self.headers,
                    method=self.method,
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    elapsed_ms = (time.time() - start_time) * 1000.0
                    result.status_code = resp.status
                    result.response_time_ms = round(elapsed_ms, 2)
                    response_text = resp.read().decode("utf-8", errors="replace")

            # Validation logic
            status_match = result.status_code == self.expected_status
            keyword_match = True
            if self.expected_keyword:
                keyword_match = self.expected_keyword in response_text

            result.is_healthy = status_match and keyword_match
            if not status_match:
                result.error_message = f"HTTP status {result.status_code} != expected {self.expected_status}"
            elif not keyword_match:
                result.error_message = f"Expected keyword '{self.expected_keyword}' not found in body"

            # Regex token extraction
            extracted = []
            for pattern in self.compiled_patterns:
                matches = pattern.findall(response_text)
                for m in matches:
                    token_val = m if isinstance(m, str) else m[0]
                    if token_val not in extracted:
                        extracted.append(token_val)
            result.extracted_tokens = extracted

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000.0
            result.response_time_ms = round(elapsed_ms, 2)
            result.is_healthy = False
            result.error_message = str(e)

        self._record_results(result)
        return result

    def _record_results(self, result: TargetResult) -> None:
        """Write execution logs and persist any extracted tokens."""
        # 1. Append to health check log
        status_tag = "HEALTHY" if result.is_healthy else "UNHEALTHY"
        log_line = (
            f"[{result.timestamp}] [{status_tag}] target={result.target} "
            f"code={result.status_code or '-'} time={result.response_time_ms:.1f}ms "
            f"tokens={len(result.extracted_tokens)} err={result.error_message or 'none'}\n"
        )
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(log_line)
        except Exception:
            pass

        # 2. Append new extracted tokens
        for token in result.extracted_tokens:
            if token not in self.seen_tokens:
                self.seen_tokens.add(token)
                record = {
                    "timestamp": result.timestamp,
                    "target": result.target,
                    "url": result.url,
                    "token": token,
                }
                try:
                    with open(self.token_file, "a", encoding="utf-8") as f:
                        f.write(json.dumps(record) + "\n")
                    # Also append to human readable list
                    txt_path = self.token_file.with_suffix(".txt")
                    with open(txt_path, "a", encoding="utf-8") as f:
                        f.write(f"{token}\n")
                except Exception:
                    pass

    def run_all(self, continuous: bool = False, interval: float = 10.0) -> List[TargetResult]:
        """Execute checks against all targets with rate-limiting between requests."""
        total_targets = len(self.targets)
        print_banner("Web Service Health & API Parser", "SLA Verification & Flag Extractor")
        safe_print(f"[*] Target Count      : {colorize(str(total_targets), Colors.BOLD + Colors.GREEN)}")
        safe_print(f"[*] Rate-Limit Delay  : {colorize(f'{self.delay}s per request', Colors.YELLOW)} (Anti-DoS Protection)")
        safe_print(f"[*] Expected Status   : {colorize(str(self.expected_status), Colors.CYAN)}")
        safe_print(f"[*] Pattern Extractors: {colorize(str(len(self.compiled_patterns)), Colors.BRIGHT_GREEN)} regex active")
        safe_print(f"[*] Health Log File   : {self.log_file}")
        safe_print(f"[*] Tokens Output     : {self.token_file}")
        safe_print(colorize("-" * 75, Colors.DIM))
        safe_print("")

        try:
            cycle = 1
            while True:
                if continuous:
                    safe_print(colorize(f"[#] === SCAN CYCLE #{cycle} ({datetime.now().strftime('%H:%M:%S')}) ===", Colors.BOLD + Colors.CYAN))

                results = []
                healthy_count = 0

                for idx, target in enumerate(self.targets, 1):
                    res = self.check_target(target)
                    results.append(res)
                    if res.is_healthy:
                        healthy_count += 1

                    # Print formatted terminal status
                    if res.is_healthy:
                        status_badge = colorize(" [UP]   ", Colors.GREEN + Colors.BOLD)
                    else:
                        status_badge = colorize(" [DOWN] ", Colors.BRIGHT_RED + Colors.BOLD)

                    latency_str = f"{res.response_time_ms:>6.1f}ms"
                    code_str = str(res.status_code) if res.status_code else "ERR"

                    target_padded = f"{target:<18}"
                    code_padded = f"{code_str:<4}"
                    line_out = f" {status_badge} {colorize(target_padded, Colors.WHITE)} | Code: {colorize(code_padded, Colors.CYAN)} | Time: {colorize(latency_str, Colors.YELLOW)}"
                    safe_print(line_out)

                    if res.extracted_tokens:
                        for token in res.extracted_tokens:
                            safe_print(f"   └─ [*] {colorize('EXTRACTED TOKEN/FLAG:', Colors.BRIGHT_MAGENTA + Colors.BOLD)} {colorize(token, Colors.BRIGHT_GREEN + Colors.BOLD)}")

                    if not res.is_healthy and res.error_message:
                        safe_print(f"   └─ [!] {colorize(res.error_message, Colors.DIM + Colors.RED)}")

                    # Rate-limiting sleep between requests to avoid overloading the network/service
                    if idx < total_targets and self.delay > 0:
                        time.sleep(self.delay)

                safe_print("")
                safe_print(colorize(f"[SUMMARY] {healthy_count}/{total_targets} hosts UP | {len(self.seen_tokens)} total unique tokens captured", Colors.BOLD + Colors.BRIGHT_WHITE))
                safe_print(colorize("-" * 75, Colors.DIM))

                if not continuous:
                    return results

                cycle += 1
                time.sleep(interval)

        except KeyboardInterrupt:
            safe_print("")
            safe_print(colorize("[*] Health checks interrupted by user.", Colors.YELLOW))
            return []


def run_health_checks(
    targets_spec: str,
    port: int = 80,
    protocol: str = "http",
    path: str = "/",
    method: str = "GET",
    delay: float = 0.5,
    timeout: float = 3.0,
    expected_status: int = 200,
    expected_keyword: Optional[str] = None,
    regex_pattern: Optional[str] = None,
    continuous: bool = False,
    interval: float = 10.0,
    targets_file: Optional[str] = None,
) -> None:
    """CLI helper to parse targets and execute health checker."""
    targets = []
    if targets_file:
        targets = TargetParser.load_from_file(targets_file)
    elif targets_spec:
        targets = TargetParser.expand_range(targets_spec)

    if not targets:
        print(colorize("[!] No targets specified. Use --targets '10.10.1.1-10.10.1.20' or --file targets.txt", Colors.BRIGHT_RED))
        sys.exit(1)

    patterns = [regex_pattern] if regex_pattern else None

    checker = HealthChecker(
        targets=targets,
        port=port,
        protocol=protocol,
        path=path,
        method=method,
        delay=delay,
        timeout=timeout,
        expected_status=expected_status,
        expected_keyword=expected_keyword,
        regex_patterns=patterns,
    )
    checker.run_all(continuous=continuous, interval=interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="Web Health Check & API Response Parser for CTF Attack-Defense")
    parser.add_argument("--targets", "-t", type=str, default="", help="Target IP or range (e.g., 10.10.1.1-10.10.1.20 or 10.60.1-10.1)")
    parser.add_argument("--file", "-f", type=str, default=None, help="File containing target IPs (one per line)")
    parser.add_argument("--port", "-p", type=int, default=80, help="Target service port (default: 80)")
    parser.add_argument("--protocol", type=str, default="http", choices=["http", "https"], help="Protocol (default: http)")
    parser.add_argument("--path", type=str, default="/", help="Path or endpoint (default: /)")
    parser.add_argument("--method", "-m", type=str, default="GET", choices=["GET", "POST", "HEAD"], help="HTTP Method")
    parser.add_argument("--delay", "-d", type=float, default=0.5, help="Inter-request delay in seconds (Anti-DoS rate limiter)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Request timeout in seconds (default: 3.0)")
    parser.add_argument("--status", type=int, default=200, help="Expected HTTP status code (default: 200)")
    parser.add_argument("--keyword", "-k", type=str, default=None, help="Expected substring in response body")
    parser.add_argument("--pattern", type=str, default=None, help="Custom regex pattern to extract from response body")
    parser.add_argument("--loop", "-l", action="store_true", help="Run continuously in a loop")
    parser.add_argument("--interval", type=float, default=15.0, help="Interval between loops in seconds")

    args = parser.parse_args()

    run_health_checks(
        targets_spec=args.targets,
        port=args.port,
        protocol=args.protocol,
        path=args.path,
        method=args.method,
        delay=args.delay,
        timeout=args.timeout,
        expected_status=args.status,
        expected_keyword=args.keyword,
        regex_pattern=args.pattern,
        continuous=args.loop,
        interval=args.interval,
        targets_file=args.file,
    )


if __name__ == "__main__":
    main()
