#!/usr/bin/env python3
"""ANSI terminal color definitions and formatted banner/logger utility."""

import sys
import os

# Enable UTF-8 for console output on Windows where supported
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Detect ANSI color support
USE_COLOR = sys.stdout.isatty() or os.environ.get("FORCE_COLOR", "0") == "1"


class Colors:
    """ANSI color codes for terminal formatting."""
    RESET = "\033[0m" if USE_COLOR else ""
    BOLD = "\033[1m" if USE_COLOR else ""
    DIM = "\033[2m" if USE_COLOR else ""
    UNDERLINE = "\033[4m" if USE_COLOR else ""

    # Foreground colors
    BLACK = "\033[30m" if USE_COLOR else ""
    RED = "\033[31m" if USE_COLOR else ""
    GREEN = "\033[32m" if USE_COLOR else ""
    YELLOW = "\033[33m" if USE_COLOR else ""
    BLUE = "\033[34m" if USE_COLOR else ""
    MAGENTA = "\033[35m" if USE_COLOR else ""
    CYAN = "\033[36m" if USE_COLOR else ""
    WHITE = "\033[37m" if USE_COLOR else ""

    # Bright foreground
    BRIGHT_RED = "\033[91m" if USE_COLOR else ""
    BRIGHT_GREEN = "\033[92m" if USE_COLOR else ""
    BRIGHT_YELLOW = "\033[93m" if USE_COLOR else ""
    BRIGHT_BLUE = "\033[94m" if USE_COLOR else ""
    BRIGHT_MAGENTA = "\033[95m" if USE_COLOR else ""
    BRIGHT_CYAN = "\033[96m" if USE_COLOR else ""
    BRIGHT_WHITE = "\033[97m" if USE_COLOR else ""

    # Background colors
    BG_RED = "\033[41m" if USE_COLOR else ""
    BG_GREEN = "\033[42m" if USE_COLOR else ""
    BG_YELLOW = "\033[43m" if USE_COLOR else ""
    BG_BLUE = "\033[44m" if USE_COLOR else ""
    BG_MAGENTA = "\033[45m" if USE_COLOR else ""
    BG_CYAN = "\033[46m" if USE_COLOR else ""


def colorize(text: str, color: str) -> str:
    """Wrap text in ANSI color escape codes."""
    if not USE_COLOR:
        return str(text)
    return f"{color}{text}{Colors.RESET}"


def safe_print(text: str, file=None, flush: bool = True) -> None:
    """Print text safely across different terminal encodings and flush immediately."""
    target = file or sys.stdout
    try:
        print(text, file=target, flush=flush)
    except UnicodeEncodeError:
        # Fallback to ascii replacement for legacy Windows terminals
        clean_text = text.encode(target.encoding or "ascii", errors="replace").decode(target.encoding or "ascii")
        print(clean_text, file=target, flush=flush)


def print_banner(title: str, subtitle: str = "") -> None:
    """Print a clean CTF defense banner."""
    line = "=" * 75
    safe_print(colorize(line, Colors.BRIGHT_CYAN))
    safe_print(colorize(f"  [+] {title.upper()}", Colors.BOLD + Colors.BRIGHT_WHITE))
    if subtitle:
        safe_print(colorize(f"      {subtitle}", Colors.CYAN))
    safe_print(colorize(line, Colors.BRIGHT_CYAN))
