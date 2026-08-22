# 🛡️ AD-CTF Master Battle Station (v3.1)

> **Framework Pertahanan, Hardening & Counter-Attack Terpadu untuk Simulasi Lab Attack-Defense CTF.**  
> *Zero-Dependency · 100% Python 3 Standard Library · Aman untuk SLA Game Server · Anti-DoS Compliant.*

---

## 📂 Struktur Proyek yang Rapi & Terhubung Penuh

Semua fungsi dari modul pertahanan, hardening, firewall, scanner, replay, hingga probe manual sekarang terintegrasi rapi di bawah paket `ctf_defense/` dan dapat dipanggil langsung dari 1 entry point `adctf.py`:

```
cyber/
├── adctf.py                     # 🚀 MASTER CLI (1 Pintu Utama untuk Semua 17 Perintah)
├── ctf_defense/                 # ⚙️ CORE ENGINE (Semua Modul Terhubung & Saling Menyambung)
│   ├── __init__.py              # Export modul API lengkap
│   ├── colors.py                # Formatting ANSI & visual box-card
│   ├── doctor.py                # Pre-flight environment diagnostics & auto-recommendations
│   ├── triage.py                # 1-detik audit sistem (port, DB, cron, reverse shell)
│   ├── hardening.py             # Sysctl kernel network, permissions compiler, & PHP hardening
│   ├── firewall.py              # Automated UFW & Game Server SLA allowlisting
│   ├── webshell_finder.py       # Deep webshell & backdoor hunter + karantina otomatis
│   ├── backup.py                # Backup .tar.gz + DB dump + baseline Git + emergency restore
│   ├── scanner.py               # Static code vuln scanner (PHP/Py/JS) & SQLite patch state
│   ├── patch_guides.py          # Koleksi sebelum-dan-sesudah patch kode (SQLi, LFI, RCE, SSTI)
│   ├── log_analyzer.py          # Real-time log sniffer & radar serangan visual
│   ├── micro_waf.py             # Advanced OWASP Top-10 WAF generator (PHP/Python/Nginx)
│   ├── health_checker.py        # SLA health verification & regex flag extractor
│   ├── replay_engine.py         # Multi-threaded rate-limited exploit replayer
│   ├── targeted_probe.py        # Sequential safe manual exploit probe (private IP only)
│   ├── flag_submitter.py        # Flag submitter gateway (HTTP & raw TCP socket)
│   └── autopilot.py             # Autonomous copilot loop (Sniff + WAF + Replay + Submit + SLA)
├── docs/                        # 📚 DOKUMENTASI LENGKAP & CHEATSHEET
│   ├── README.md                # Panduan Utama & Arsitektur Framework
│   ├── OPERATOR-GUIDE.md        # 🎮 Panduan Santai Teman Tim (Tinggal Copas Perintah)
│   ├── MASTER-CHEATSHEET.md     # 🛡️ Master IR, Hardening & Micro-Patching Cheatsheet
│   ├── TACTICAL-PLAYBOOK.md     # 🏆 Playbook Taktis & Timeline Menit-per-Menit
│   └── references/              # 📖 13 Cheatsheet Teknis Spesifik (SQLi, XSS, UFW, dll)
└── tests/                       # 🧪 UNIT TESTS
    └── test_suite.py            # 100% Automated Unit Test Suite (11/11 Passed)
```

---

## 🎮 Cara Pengoperasian

### 1. Menu Terminal Interaktif (Cukup Tekan Angka)
```bash
python3 adctf.py
```
Akan muncul menu nomor **1 s.d. 15 / auto**:
```
===========================================================================
  [+] AD-CTF MASTER BATTLE STATION
      Unified Attack-Defense Framework v3.1
===========================================================================
Pilih modul yang ingin dijalankan:
  ★. AUTOPILOT   - Mode Otomatis Khusus Operator (Sniff + WAF + Replay + Submit)
  1. Doctor      - Pre-flight environment diagnostics & fix recommendations
  2. Triage      - Situational audit (ports, services, DBs, crons, active connections)
  3. Hardening   - System & binary permissions + sysctl network lockdown
  4. Firewall    - Automated UFW rules + Game Server SLA allowlisting
  5. Webshell    - Deep webshell & backdoor scanner & quarantine
  6. Start       - Full backup web & database + init Git baseline
  7. Scan        - Source code static vulnerability scanner (PHP/Python/JS)
  8. Next/Done   - Step-by-step guided micro-patching workflow
  9. Watch       - Real-time log sniffer & attack radar alert
 10. Check       - Health check & SLA verification
 11. WAF Gen     - Generate & auto-deploy OWASP Top-10 Micro-WAF
 12. Replay      - Blast captured exploits to enemy teams (Multi-threaded)
 13. Probe       - Targeted safe exploit probe (Sequential single-shot)
 14. Submit Flag - Batch submit captured flags to game server
 15. Patch Guide - Instant before-and-after code fix cheatsheet
  0. Keluar
```

---

### 2. Mode AUTOPILOT (Khusus Teman Tim / Operator)
```bash
python3 adctf.py autopilot --targets 10.60.1-20.1 --submit-url http://10.0.0.1/api/submit --token TEAM_TOKEN
```
- 📡 **Mendeteksi** serangan lawan dari log web server dan intercept WAF.
- ⚡ **Memantulkan balik** serangan musuh ke semua tim lawan secara paralel & terkontrol.
- 🚩 **Auto-Submit** flag curian ke server panitia.
- 🩺 **Mengecek SLA** kesehatan web server setiap 30 detik.

---

### 3. Daftar Lengkap Perintah CLI

| Modul | Perintah CLI | Fungsi & Deskripsi |
|---|---|---|
| **Doctor** | `python3 adctf.py doctor` | Diagnostik kesiapan Python, binary tools (`git`, `tmux`, `lsof`, `ufw`), log, dan webroot. |
| **Triage** | `python3 adctf.py triage` | Recon 1-detik: port listening, database aktif, koneksi keluar (reverse shell), cron, dan modified files. |
| **Hardening** | `python3 adctf.py hardening` <br> `sudo python3 adctf.py hardening --apply` | Audit & aplikasikan proteksi sysctl kernel, kunci compiler gcc/gdb/nc (chmod 700), dan rapikan permission webroot. |
| **Firewall** | `python3 adctf.py firewall --whitelist 10.0.0.1` <br> `sudo python3 adctf.py firewall --apply` | Konfigurasi UFW otomatis: izinkan SSH & Web, izinkan IP Game Server panitia (SLA), tolak port liar lainnya. |
| **Webshell** | `python3 adctf.py webshell` <br> `python3 adctf.py webshell --quarantine` | Scan backdoor terselubung (`eval(`, `base64_decode(`, `assert(`, `$$var()`, file hidden/ekstensi ganda) dan karantina otomatis. |
| **Backup** | `python3 adctf.py start` | Full backup `.tar.gz` webroot + dump database (MySQL/PostgreSQL/SQLite) + inisialisasi Git baseline. |
| **Restore** | `python3 adctf.py restore --confirm` | Ekstrak aman dan pulihkan webroot dari backup jika web dirusak lawan. |
| **Scan** | `python3 adctf.py scan` | Static code scanner untuk menemukan celah SQLi, RCE, LFI, SSTI, XSS pada source code. |
| **Next / Done** | `python3 adctf.py next` <br> `python3 adctf.py done` | Guided micro-patching: buka bug prioritas lengkap dengan baris kodenya, lalu verifikasi perbaikan. |
| **Checklist** | `python3 adctf.py list` | Tampilkan status semua temuan bug (✅ PATCHED / ❌ OPEN). |
| **Watch** | `python3 adctf.py watch` | Log sniffer real-time dengan kartu visual berwarna dan rekomendasi aksi instan. |
| **SLA Check** | `python3 adctf.py check` | Verifikasi ketersediaan web server & ekstraksi flag jika ada. |
| **WAF** | `python3 adctf.py waf --whitelist 10.0.0.1 --deploy` | Generate & pasang WAF OWASP Top-10 (45+ rules) otomatis via `.user.ini` tanpa restart web server. |
| **Replay** | `python3 adctf.py attack 10.60.1-20.1` | Tembakkan seluruh payload serangan musuh yang terekam ke tim lawan secara multi-threaded. |
| **Probe** | `python3 adctf.py probe -t 10.60.1-20.1 -p id --payload "1' UNION SELECT 1,2,3--"` | Uji coba payload spesifik ke subnet lawan secara berurutan dengan jeda aman (anti-DoS). |
| **Submit** | `python3 adctf.py submit --file captured_flags.txt` | Kirim semua flag yang didapat ke Scoring Server panitia (HTTP / TCP raw socket). |
| **Patch Guide** | `python3 adctf.py patch-guide` | Kamus contekan kode perbaikan (before vs after) untuk SQLi, LFI, RCE, SSTI, Deserialization. |
