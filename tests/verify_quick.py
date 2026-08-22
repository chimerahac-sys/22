#!/usr/bin/env python3
import subprocess
import sys

sample_logs = """10.10.1.5 - - [22/Aug/2026:20:00:00 +0000] "GET /search.php?q=%27%20UNION%20SELECT%201,2,3--%20 HTTP/1.1" 200 500
10.10.3.8 - - [22/Aug/2026:20:00:01 +0000] "GET /index.php?page=../../../../etc/passwd HTTP/1.1" 200 1200
10.10.9.2 - - [22/Aug/2026:20:00:02 +0000] "POST /ping.php?host=127.0.0.1;cat%20/flag HTTP/1.1" 200 80
10.10.0.1 - - [22/Aug/2026:20:00:03 +0000] "GET /assets/style.css HTTP/1.1" 200 4000
"""

# Write temporary access log file
with open("test_access.log", "w", encoding="utf-8") as f:
    f.write(sample_logs)

from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ctf_defense.log_analyzer import LogAnalyzer

analyzer = LogAnalyzer(log_path="test_access.log", save_file="test_attacks.jsonl")
for line in sample_logs.strip().splitlines():
    entry = analyzer.analyze_entry(analyzer.parse_line(line))
    formatted = analyzer.format_terminal_output(entry)
    if formatted:
        print(formatted)
        print()
