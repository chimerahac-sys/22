"""CTF Attack-Defense Modular Defense & Offense Framework.
Designed for Linux & CTF lab simulations with zero-dependency stdlib Python 3.
"""

__version__ = "3.2.0"

from .colors import Colors, colorize, safe_print, print_banner
from .doctor import EnvironmentDoctor, run_doctor
from .triage import SystemTriage, run_triage
from .hardening import run_hardening_check, run_hardening_apply
from .firewall import run_firewall_setup, generate_ufw_commands
from .webshell_finder import find_webshells, run_webshell_hunter
from .backup import run_backup, run_restore, init_git_baseline
from .scanner import run_scan, run_next_patch, run_done_patch, run_list_patches, print_patch_guides, get_db
from .log_analyzer import LogAnalyzer, monitor_logs
from .health_checker import HealthChecker, run_health_checks
from .micro_waf import generate_waf, RULES, _deep_decode, _check_payload
from .replay_engine import ReplayEngine, replay_attacks
from .targeted_probe import run_targeted_probe, probe_single
from .flag_submitter import FlagSubmitter, submit_flags
from .autopilot import run_autopilot
from .patch_guides import show_all_patch_guides, SNIPPETS
from .pipeline import run_e2e_pipeline

__all__ = [
    "Colors",
    "colorize",
    "safe_print",
    "print_banner",
    "EnvironmentDoctor",
    "run_doctor",
    "SystemTriage",
    "run_triage",
    "run_hardening_check",
    "run_hardening_apply",
    "run_firewall_setup",
    "generate_ufw_commands",
    "find_webshells",
    "run_webshell_hunter",
    "run_backup",
    "run_restore",
    "init_git_baseline",
    "run_scan",
    "run_next_patch",
    "run_done_patch",
    "run_list_patches",
    "print_patch_guides",
    "get_db",
    "LogAnalyzer",
    "monitor_logs",
    "HealthChecker",
    "run_health_checks",
    "generate_waf",
    "RULES",
    "_deep_decode",
    "_check_payload",
    "ReplayEngine",
    "replay_attacks",
    "run_targeted_probe",
    "probe_single",
    "FlagSubmitter",
    "submit_flags",
    "run_autopilot",
    "show_all_patch_guides",
    "SNIPPETS",
    "run_e2e_pipeline",
]
