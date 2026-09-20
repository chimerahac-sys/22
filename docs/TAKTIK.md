# 🏆 MASTER TAKTIK ATTACK-DEFENSE (JCC / CTF A&D)
> **Panduan Strategi Tempur Solo Carry + 1 Operator: Dari Menit 0 hingga Akhir Lomba.**  
> *100% Fleksibel untuk Segala Macam Environment (PHP, Python Flask, Node.js, Custom Webroot, Docker).*

---

## 🧠 1. Mindset & Pembagian Tugas (Tim 2 Orang)

Karena kamu adalah **Lead Analyst / Solo Carry** dan temanmu adalah **Operator Terminal**, bagi tugas secara kaku agar tidak panik:

```
┌───────────────────────────────────────────────┬───────────────────────────────────────────────┐
│ 💻 KAMU (Solo Carry / Coder / Analyst)        │ 🎮 TEMANMU (Operator Terminal)                │
├───────────────────────────────────────────────┼───────────────────────────────────────────────┤
│ 1. Eksekusi `python3 adctf.py start` di awal. │ 1. Buka Terminal ke-2 (atau Tmux pane kanan). │
│ 2. Analisis bug via `python3 adctf.py next`.  │ 2. Jalankan Autopilot Radar:                  │
│ 3. Perbaiki source code aplikasi web.         │    `python3 adctf.py autopilot --targets ...` │
│ 4. Jalankan `python3 adctf.py done` / patch.  │ 3. Monitor layar: Jika ada [SLA ALERT],       │
│ 5. Audit tabel database & logika bisnis.      │    langsung teriak dan beritahu kamu!         │
└───────────────────────────────────────────────┴───────────────────────────────────────────────┘
```

---

## 🌐 2. Adaptasi Cepat Terhadap Segala Macam Environment (Anti-Kagok!)

Jangan panik jika environment lomba tidak sesuai dugaan. Framework `adctf.py` sudah didesain adaptif dengan flag fleksibel:

### 🔹 Skenario A: Standard PHP (Apache / Nginx + `/var/www/html`)
```bash
# Langsung jalankan default (Otomatis deteksi):
python3 adctf.py start --whitelist <IP_JURI>
```

### 🔹 Skenario B: Web Root Berbeda (Misal: `/app`, `/home/ctf/web`, atau `.` folder saat ini)
Jika source code tidak di `/var/www/html`, cukup tambahkan `--web-root`:
```bash
# Contoh jika web ada di /app
python3 adctf.py start --web-root /app --whitelist <IP_JURI>

# Contoh jika web ada di folder saat ini
python3 adctf.py start --web-root . --whitelist <IP_JURI>
```

### 🔹 Skenario C: Web Stack Berbasis Python (Flask / Django / Gunicorn)
Jika aplikasinya Python di port 5000 / 8000:
```bash
# 1. Start defense dengan webroot python
python3 adctf.py start --web-root /app

# 2. Pasang WAF middleware Python
python3 adctf.py waf --type python --web-root /app

# 3. Autopilot tembak ke port lawan (misal port 5000)
python3 adctf.py autopilot --targets 10.60.1-20.1 --port 5000 --submit-url http://10.0.0.1/api/submit --token TOKEN
```

### 🔹 Skenario D: Multiple Services / Port Berbeda (Misal: Port 80 & 8080)
Jika di server ada 2 service web sekaligus:
```bash
# Replay ke port 8080 musuh
python3 adctf.py attack 10.60.1-20.1 --port 8080

# Probe spesifik ke port 8080
python3 adctf.py probe -t 10.60.1-20.1 --port 8080 -p id --payload "1' OR 1=1--"
```

### 🔹 Skenario E: Format Flag Panitia Berbeda (Bukan `FLAG{...}`)
Jika panitia memakai format khusus (contoh: `JCSC{...}` atau `CYBER{...}`):
```bash
# Tambahkan flag --pattern pada autopilot
python3 adctf.py autopilot --targets 10.60.1-20.1 --pattern "JCSC\{[^\}]+\}" --submit-url http://10.0.0.1/api/submit --token TOKEN
```

---

## ⏱️ 3. Timeline Taktis Menit-per-Menit (Step-by-Step)

### 🟢 FASE 1: Menit 00:00 – 05:00 (Preparation Time / Tick 0)
> *Tujuan: Kunci server, amankan backup, pasang WAF, dan cari celah sebelum serangan musuh dimulai.*

1. **Login SSH ke Server Game:**
   ```bash
   ssh root@10.60.X.Y -p 22
   ```

2. **Ganti Password User Sendiri (Wajib):**
   ```bash
   passwd
   ```

3. **Clone / Upload Folder `cyber` dan Eksekusi 1 Komando:**
   ```bash
   cd cyber
   python3 adctf.py start --whitelist <IP_PANITIA_JURI>
   ```
   *(Selesai dalam 1.5 detik: Web di-backup, Git tagged, Sysctl dikunci, WAF aktif, Webshell dibersihkan, Celah dicatat ke SQLite).*

4. **1-Klik Patch Celah Umum:**
   ```bash
   python3 adctf.py autopatch
   ```
   *(Otomatis membungkus LFI dengan `basename`, SQLi dengan `(int)`, dan RCE dengan `escapeshellarg`)*.

---

### 🟡 FASE 2: Menit 05:00 – 15:00 (Tick 1 - First Blood Wave)
> *Tujuan: Mulai menyedot serangan lawan, pantulkan balik ke semua musuh, panen flag otomatis.*

1. **Buka Terminal / Tmux Khusus Temanmu (Operator):**
   Minta temanmu menjalankan perintah ini dan biarkan running terus:
   ```bash
   python3 adctf.py autopilot --targets 10.60.1-20.1 --submit-url http://10.0.0.1/api/submit --token TEAM_TOKEN
   ```
   *Keunggulan: WAF menangkap serangan lawan -> Autopilot memantulkan payload ke seluruh tim lawan -> Flag tercuri -> Auto-submit ke Game Server.*

2. **Kamu (Lead Coder) Fokus Menambal Bug yang Tersisa:**
   ```bash
   python3 adctf.py next
   ```
   - Layar akan menampilkan: file yang rentan, nomor baris, dan rekomendasi perbaikan.
   - Buka file dengan `nano <path>` atau text editor.
   - Perbaiki kode sesuai contekan `python3 adctf.py patch-guide`.
   - Setelah selesai, verifikasi:
     ```bash
     python3 adctf.py done
     ```

---

### 🔴 FASE 3: Menit 15:00 – Selesai (Mid-Game & Endgame)
> *Tujuan: Pertahankan skor SLA 100%, curi flag di setiap tick, dan amankan database.*

1. **Pantau Health SLA (Otomatis oleh Autopilot):**
   - Jika terminal autopilot menampilkan `[SLA HEALTH: OK (200)]`, server aman.
   - Jika muncul `[SLA ALERT: HTTP 500]`, kamu baru saja merusak file. Cek file terakhir yang kamu edit atau pulihkan dari `.bak`:
     ```bash
     cp index.php.bak index.php
     ```

2. **Hunting Manual ke Musuh Tertentu (Jika Ada Lawan yang Belum Kena):**
   Gunakan probe terarah (sequential & anti-DoS):
   ```bash
   python3 adctf.py probe -t 10.60.1-20.1 -p page --payload "../../../../flag"
   ```

3. **Periksa Queue Flag Jika Server Panitia Sempat Lag / Error:**
   ```bash
   python3 adctf.py submit --file captured_flags.txt
   ```
   *(Otomatis re-try semua flag yang pending di antrean SQLite)*.

---

## 🚨 4. Prosedur Darurat (Jika Terjadi Masalah / Troubleshooting)

| Masalah | Solusi Cepat (Kurang dari 10 Detik) |
|---|---|
| **SLA Server Tiba-tiba DOWN / Merah** | 1. Cek apakah web service aktif: `systemctl status nginx` / `apache2` / `php-fpm`.<br>2. Kembalikan file terakhir yang kamu edit dari `.bak`.<br>3. Jika parah, restore darurat: `python3 adctf.py restore --confirm`. |
| **WAF Memblokir Traffic Juri / SLA Drop** | Pastikan IP Juri sudah di-whitelist: `python3 adctf.py waf --whitelist <IP_JURI> --deploy`. |
| **Web Dihapus / Dirating Musuh** | Langsung jalankan restore baseline: `python3 adctf.py restore --confirm`. |
| **Teman Tim Bingung Harus Ngapain** | Suruh dia hanya fokus melihat layar Autopilot: jika hijau biarkan, jika ada teks merah bertuliskan `SLA DOWN`, dia langsung lapor ke kamu. |
| **Port Service Bukan Port 80** | Tambahkan `--port <PORT>` di perintah `autopilot`, `check`, dan `probe`. |

---

## 📋 5. Cheatsheet Copy-Paste Ringkas (Print / Simpan Ini!)

```bash
# === 1. START PERTAHANAN (Menit 0) ===
python3 adctf.py start --whitelist 10.0.0.254

# === 2. 1-KLIK AUTO-PATCH (Menit 2) ===
python3 adctf.py autopatch

# === 3. RADAR & AUTO-REPLAY TEMPIR (Menit 5 dst - Temanmu) ===
python3 adctf.py autopilot --targets 10.60.1-20.1 --submit-url http://10.0.0.1/api/submit --token TEAM_TOKEN

# === 4. GUIDED PATCHING MANUAL (Kamu) ===
python3 adctf.py next
python3 adctf.py done

# === 5. LIHAT ARSENAL EXPLOIT PAYLOAD (SQLi, LFI, RCE, SSTI) ===
python3 adctf.py arsenal

# === 6. MANUAL TARGETED PROBE KE LAWAN TERTENTU ===
python3 adctf.py probe -t 10.60.1-20.1 -p page --payload "../../../../flag"
python3 adctf.py list

# === 5. CEK SLA & HEALTH ===
python3 adctf.py check

# === 6. DARURAT: RESTORE SEMUA DARI BACKUP ===
python3 adctf.py restore --confirm
```

---

## 📚 6. Daftar Cheat Sheet Khusus Pertandingan (`docs/references/`)

Jika butuh contekan teknis mendalam selama pertandingan, buka file-file berikut:

1. **Ringkasan Darurat 1 Halaman**: [`ULTIMATE-QUICK-REFERENCE.md`](file:///c:/Users/Good-User/Downloads/cyber/docs/references/ULTIMATE-QUICK-REFERENCE.md)
2. **Kamus Perintah Linux & Incident Response**: [`LINUX-EMERGENCY-BIBLE.md`](file:///c:/Users/Good-User/Downloads/cyber/docs/references/LINUX-EMERGENCY-BIBLE.md)
3. **Kamus Celah & Patch PHP**: [`PHP-VULN-PATCH-BIBLE.md`](file:///c:/Users/Good-User/Downloads/cyber/docs/references/PHP-VULN-PATCH-BIBLE.md)
4. **Kamus Celah & Patch Python (Flask/FastAPI)**: [`PYTHON-FLASK-FASTAPI-BIBLE.md`](file:///c:/Users/Good-User/Downloads/cyber/docs/references/PYTHON-FLASK-FASTAPI-BIBLE.md)
5. **Kamus Database MySQL/MariaDB/SQLite**: [`MYSQL-DEFENSE-BIBLE.md`](file:///c:/Users/Good-User/Downloads/cyber/docs/references/MYSQL-DEFENSE-BIBLE.md)
6. **Kamus Backdoor & Webshell Hunting**: [`REVERSE-SHELL-BACKDOOR-BIBLE.md`](file:///c:/Users/Good-User/Downloads/cyber/docs/references/REVERSE-SHELL-BACKDOOR-BIBLE.md)
7. **Kamus Hardening Nginx & Apache**: [`WEBSERVER-HARDENING-BIBLE.md`](file:///c:/Users/Good-User/Downloads/cyber/docs/references/WEBSERVER-HARDENING-BIBLE.md)
8. **Kamus Teknik Curi Flag Lawan (Offensive)**: [`FLAG-HUNTING-BIBLE.md`](file:///c:/Users/Good-User/Downloads/cyber/docs/references/FLAG-HUNTING-BIBLE.md)
9. **Kamus Sniffing Traffic & PCAP**: [`TRAFFIC-ANALYSIS-WIRESHARK-TCPDUMP.md`](file:///c:/Users/Good-User/Downloads/cyber/docs/references/TRAFFIC-ANALYSIS-WIRESHARK-TCPDUMP.md)
10. **Panduan Proteksi SLA & Uptime Scoring**: [`SLA-PROTECTION-SURVIVAL-GUIDE.md`](file:///c:/Users/Good-User/Downloads/cyber/docs/references/SLA-PROTECTION-SURVIVAL-GUIDE.md)

