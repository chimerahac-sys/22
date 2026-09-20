# 🛡️ AD-CTF Master Battle Station (v3.3)

> **Framework Pertahanan, Hardening, Auto-Patcher & Counter-Attack Terpadu untuk Simulasi Lab Attack-Defense CTF.**  
> *Zero-Dependency · 100% Python 3 Standard Library · Anti-Replay Loop · Persistent Flag Queue · Anti-DoS Compliant.*

---

## 🚀 Fitur Baru & Peningkatan Stabilitas (v3.3)

1. ⚡ **1-Command Auto-Defense (`python3 adctf.py start`)**: 7 fase pertahanan terpadu (Environment Scan, Backup & Git Baseline, Adaptive Hardening, WAF Deploy, Webshell Sweep, Vuln Scan, SLA Verification) dalam **< 1.5 detik**.
2. 🩹 **1-Click Safe Micro-Patcher (`python3 adctf.py autopatch`)**: Membungkus celah LFI (`basename`), SQLi (`(int)` cast), dan RCE (`escapeshellarg`) secara otomatis dengan backup `.bak` dan **SLA Auto-Rollback**.
3. 🔄 **Anti-Replay Loop & Deduplication (Autopilot)**: Mencegah penembakan payload yang sama berulang kali (90s TTL cache) dan otomatis memblokir *friendly fire* ke IP tim sendiri atau Game Server panitia.
4. 🚩 **Persistent Flag Queue & Retry Buffer**: Flag yang gagal terkirim (misal karena Game Server panitia 502/504) disimpan ke SQLite `flag_queue` dan otomatis di-retry berkala sampai sukses (*0% flag loss*).
5. 🛡️ **Dual-Tier Instant WAF**: Pemasangan ganda via `.user.ini` + injeksi aman baris pertama `index.php` untuk aktivasi seketika (**0-detik aktif** tanpa terhalang cache PHP-FPM).
6. 🔤 **Universal & Custom Flag Regex**: Mendukung format bendera universal (`FLAG{...}`, `JCSC{...}`, `CTF{...}`) dan kustom via flag `--pattern`.

---

## 🎮 Panduan Singkat Hari-H

### 1. Menit 0–2 (Amankan Server Seketika)
```bash
python3 adctf.py start
```

### 2. Menit 3 (Jalankan Autopilot Tempur - Teman Tim/Operator)
```bash
python3 adctf.py autopilot --targets 10.60.1-20.1 --submit-url http://10.0.0.1/api/submit --token TEAM_TOKEN
```

### 3. Menit 5 (Tambal Celah Source Code - Hacker/Coder)
Pilih salah satu:
- **Cara Instan (1-Klik Auto-Patch)**:
  ```bash
  python3 adctf.py autopatch
  ```
- **Cara Terarah (Guided Patching)**:
  ```bash
  python3 adctf.py next   # Lihat bug prioritas + contekan fix
  # Edit kode
  python3 adctf.py done   # Verifikasi file dan tandai selesai
  ```

---

## 🧪 Validasi Pengujian
- **Unit Test Suite**: `python -m unittest tests/test_suite.py` → **15/15 Tests PASSED (100% OK)**
- **Waktu Eksekusi Pipeline**: **~1.5 Detik**
- **Dependensi**: 100% Python Standard Library (Tanpa pip install).
