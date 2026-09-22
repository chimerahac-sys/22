# AD-CTF Master Battle Station - JCC 2026 Edition

Framework Attack-Defense CTF yang dimodifikasi khusus untuk **Jatim Cybersecurity Competition (JCC) 2026**.

## ⚠️ PENTING - Aturan JCC 2026

Berdasarkan Petunjuk Teknis JCC 2026:

1. **DILARANG** menggunakan automated scanner/tools seperti:
   - sqlmap
   - Burp Scanner
   - dirb
   - Tools automated lainnya

2. **HANYA DIPERBOLEHKAN** menggunakan:
   - LLM berbasis Web (Free dan/atau Paid) dari provider manapun
   - **DILARANG** menggunakan Agentic AI
   - Manual probing dengan input payload sendiri

3. **Format Lomba:**
   - Attack Defense dengan kategori: Cryptography, Web Exploitation, Binary Exploitation
   - Waktu: 08.30 - 16.00 WIB
   - Lokasi: Dinas Komunikasi dan Informatika Provinsi Jawa Timur

## 🚀 Quick Start

```bash
# Jalankan interactive menu
python3 adctf.py

# Atau gunakan command langsung
python3 adctf.py start --web-root /var/www/html
```

## 📋 Fitur Utama

### 1. Defense (Pertahanan)
- **Auto-Backup**: Backup source code sebelum patching
- **Hardening**: System permissions, sysctl, PHP hardening
- **Firewall Setup**: UFW rules dengan whitelist SLA checker
- **Webshell Hunter**: Deteksi backdoor dan webshell
- **Vulnerability Scanner**: Scan source code (MANUAL REVIEW REQUIRED)
- **Micro-WAF**: OWASP Top-10 protection
- **Health Checker**: SLA verification

### 2. Offense (Penyerangan) - COMPLIANT WITH JCC RULES
- **Manual Probe**: Single-shot exploit probe dengan delay aman (≥1.0s)
- **Replay Engine**: Replay captured attacks dengan rate limiting
- **Autopilot**: Live radar dengan anti-loop protection
- **Flag Submitter**: Submit flag ke JCC API

### 3. JCC 2026 Integration
- **WireGuard VPN**: Fetch target IPs via JCC API
- **Flag Submission**: Format API JCC 2026
  - Endpoint: `POST https://jcc.jatimprov.go.id/api/Game/<GAME_ID>/Ad/Submit`
  - Header: `Authorization: Bearer <API_TOKEN>`
  - Body: `{"flags":["flag{...}"]}`
- **Service Management**: `make start/restart/stop/compile`

## 🔧 Command Line Usage

### Defense Commands
```bash
# Full end-to-end defense pipeline
python3 adctf.py start --web-root /var/www/html

# Backup only
python3 adctf.py start --backup-only --web-root /var/www/html

# Hardening check
python3 adctf.py hardening --web-root /var/www/html

# Apply hardening (requires sudo)
python3 adctf.py hardening --apply --web-root /var/www/html

# Firewall setup
python3 adctf.py firewall --apply --whitelist "10.0.0.1,10.0.0.2"

# Webshell scan
python3 adctf.py webshell --web-root /var/www/html

# Vulnerability scan (MANUAL REVIEW REQUIRED)
python3 adctf.py scan --web-root /var/www/html

# Generate WAF
python3 adctf.py waf --type php --deploy
```

### Offense Commands (JCC Compliant)
```bash
# Manual targeted probe (delay ≥1.0s untuk hindari DoS)
python3 adctf.py probe -t "10.60.1-20.1" -e "/vuln.php" -p "id" \
  --payload "1' UNION SELECT 1,2,3--" --delay 1.5

# Replay captured attacks (rate limited)
python3 adctf.py attack "10.60.1-20.1" --delay 1.0 --threads 5

# Autopilot mode (manual review required)
python3 adctf.py autopilot -t "10.60.1-20.1" \
  -u "https://jcc.jatimprov.go.id/api/Game/GAME_ID/Ad/Submit" \
  --token "YOUR_API_TOKEN"
```

### Flag Submission
```bash
# Submit single flag
python3 adctf.py submit -u "https://jcc.jatimprov.go.id/api/Game/GAME_ID/Ad/Submit" \
  -t "YOUR_API_TOKEN" -f "flag{example_flag}"

# Submit from file
python3 adctf.py submit -u "https://jcc.jatimprov.go.id/api/Game/GAME_ID/Ad/Submit" \
  -t "YOUR_API_TOKEN" --file captured_flags.txt
```

### JCC API Integration
```bash
# Dalam interactive menu, pilih opsi 16 untuk:
# - WireGuard VPN setup guide
# - Fetch target IPs dari JCC API
```

### Service Management (Post-Patching)
```bash
# Dalam interactive menu, pilih opsi 17 untuk:
# - make start    : Menjalankan challenge
# - make restart  : Restart setelah patching
# - make stop     : Menghentikan challenge
# - make compile  : Kompilasi binary (kategori pwn)
```

## 🎯 Interactive Menu

Jalankan tanpa argumen untuk menu interaktif:

```bash
python3 adctf.py
```

Menu mencakup:
1. ⚡ 1-Command Auto-Defense
2. ★ Autopilot Battle Mode (Manual Only)
3. 🩹 Auto-Patcher (dengan backup & SLA rollback)
4. 🩺 Pre-Flight Doctor & Triage
5. 🛡️ Hardening
6. 🧱 Firewall Setup
7. 🕷️ Webshell Hunter
8. 🔍 Vuln Scanner (MANUAL REVIEW REQUIRED)
9. 📡 Log Monitor
10. 🛡️ WAF Generator
11. ⚡ Manual Exploit Replay (Rate Limited)
12. 🎯 Targeted Probe (JCC Compliant)
13. 🚩 Flag Submitter (JCC API)
14. 📖 Patch Guides
15. 🎯 Payload Arsenal
16. 🔑 WireGuard VPN & Target Fetcher (JCC API) **BARU**
17. 🔧 Service Management (make commands) **BARU**

## 📊 Scoring System (JCC 2026)

Total Score = ATK + DEF + SLA

- **Attack Points (ATK)**: Flag tim lawan yang berhasil diambil
- **Defense Points (DEF)**: Keberhasilan melindungi flag sendiri
- **SLA Points**: Service tetap berfungsi saat checker

### Flag Validity
- Flag baru dibuat setiap tick (60 detik)
- Flag berlaku selama 5 tick (5 menit)
- Flag dari round sebelumnya tidak berlaku di round baru

### API Response Status
- `accepted`: Flag diterima untuk skor
- `duplicate`: Flag sudah pernah dikirim tim ini
- `wrong`: Flag tidak valid
- `expired`: Masa berlaku flag habis
- `self_attack`: Flag dari target sendiri
- `not_started`: Pertandingan belum mulai
- `paused`: Penerimaan flag dihentikan sementara
- `ended`: Pertandingan berakhir

## ⚠️ Compliance Warning

Tools ini telah dimodifikasi untuk mematuhi aturan JCC 2026:

✅ **Compliant:**
- Manual probing dengan delay ≥1.0s
- Rate-limited replay (anti-DoS)
- No automated scanner integration
- Support untuk LLM Web (user menyediakan sendiri)

❌ **Non-Compliant (DIHAPUS/DIMODIFIKASI):**
- Automated scanner (sqlmap, burp, dirb) - TIDAK TERINTEGRASI
- Agentic AI - TIDAK DIDUKUNG
- Brute force berlebihan - DICEGAH dengan rate limiting

## 📝 Workflow Rekomendasi JCC 2026

### Phase 1: Preparation (08.30 - 09.00)
1. Aktifkan WireGuard VPN
2. Fetch target IPs dari JCC API
3. Jalankan `python3 adctf.py start` untuk defense baseline

### Phase 2: Defense First (09.00 - 10.00)
1. Backup source code
2. Scan vulnerabilities (review manual!)
3. Patch kerentanan kritis
4. Deploy WAF
5. Restart service: `make restart`
6. Verify SLA: `python3 adctf.py health`

### Phase 3: Offense (10.00 - 15.00)
1. Gunakan manual probe untuk enumerasi
2. Eksploitasi dengan payload manual (LLM-assisted)
3. Submit flag segera ke JCC API
4. Monitor log untuk serangan masuk
5. Re-patch jika diperlukan

### Phase 4: Final Defense (15.00 - 16.00)
1. Pastikan semua service OK
2. Submit semua flag yang belum terkirim
3. Monitor SLA hingga akhir

## 🔗 References

- [JCC 2026 Technical Guidelines](JCC_2026_Technical_Guidelines.md)
- [ATKLAB v2 Scoring Reference](https://gist.github.com/miraicantsleep/21bffa21cff1a2fd3f02b2320e0e4edc)

## 📞 Support

Untuk pertanyaan teknis mengenai tools, hubungi tim developer.
Untuk pertanyaan lomba, hubungi panitia JCC 2026.

---

**Good luck dan semoga sukses di JCC 2026!** 🏆
