# 🛡️ STRATEGI "DUMB BUT SAFE" - JCC 2026

**Filosofi:** Service hidup > Patch sempurna. Jangan sok jago, jangan over-engineer.
**Target:** SLA OK terus, Attack ambil flag receh, Defense cukup aman.

---

## 📦 PERSIAPAN (SEBELUM LOMBA)

1. **Install WireGuard** di laptop & import config panitia.
2. **Simpan API Token** di notes/notepad (jangan sampai hilang).
3. **Siapkan 3 Senjata Utama:**
   - `adctf.py` (Auto-fetch IP & Submit Flag)
   - `waf_simple.py` (WAF Polosan buat Web)
   - `check_service.sh` (Cek status service simpel)
4. **Jangan install apa-apa lagi.** No pip install, no tools ribet.

---

## ⏱️ MENIT-MENIT AWAL (08.30 - 08.45 WIB)

**JANGAN LANGSUNG SERANG! Ikuti urutan ini:**

1. **Connect VPN:** Pastikan WireGuard nyala & bisa ping IP lawan.
2. **Cek Dashboard:** Lihat daftar challenge & IP tim sendiri.
3. **SSH ke Server Sendiri:**
   ```bash
   ssh user@IP_SENDIRI
   ```
4. **Backup Kode (WAJIB):**
   ```bash
   cp -r /path/to/challenge /path/to/challenge_backup_$(date +%s)
   ```
5. **Amankan SSH (Opsional tapi Recommended):**
   - Edit `/etc/ssh/sshd_config`, restrict IP cuma tim sendiri & checker.
   - Restart SSH: `systemctl restart sshd`
6. **Cek Service Jalan:**
   ```bash
   curl http://localhost:PORT
   # Atau test binary/crypto manual
   ```
7. **Submit Flag Ronde 1 (Jika ada sample flag):**
   - Gunakan `adctf.py` atau submit manual via web panel.

---

## 🔄 RUTINITAS LOOP (SETIAP 5 MENIT / 1 RONDE)

Ulangi langkah ini terus menerus sampai lomba selesai:

### 1. CEK STATUS SERVICE (DEFENSE CHECK)
Pastikan service lo masih "OK" di dashboard.
- Jika **OK/Mumble**: Lanjut attack.
- Jika **Offline/InternalError**: **STOP ATTACK**, fokus fix service segera!

### 2. AMBIL FLAG (ATTACK)
Jalankan script auto-fetch (jika ada) atau manual:
```bash
python3 adctf.py --mode attack
```
- Target: Ambil flag dari tim yang servisnya "Mumble" atau "Recovering" (mereka lemah).
- Submit secepat mungkin sebelum expired (5 tick).

### 3. PATCHING SEDERHANA (DEFENSE)
**Hanya lakukan jika kamu 100% yakin bug-nya di mana.**
- **Web:** Comment baris kode vulnerability, jangan hapus fungsi utama.
- **Binary:** Pakai `LD_PRELOAD` untuk hook fungsi berbahaya (jika bisa), atau chmod file flag.
- **Crypto:** Biasanya susah dipatch cepat, fokus rotasi key jika memungkinkan, atau biarkan jika terlalu rumit.
- **Restart Service:**
  ```bash
  make restart
  ```
- **Cek Ulang:** Pastikan service balik "OK".

### 4. MONITORING
- Cek dashboard tiap 1-2 menit.
- Jika ada serangan DDoS ringan, WAF simple bisa nyala.
- Jika service down mendadak: `make restart` ASAP.

---

## 🚨 PANIC BUTTON (DARURAT!)

Jika service down total atau salah patch:

1. **Stop Semua Script:** `Ctrl+C` semua terminal.
2. **Flush Firewall:** `iptables -F` (biar checker bisa masuk lagi).
3. **Kill WAF:** `pkill -f waf` atau `pkill python`.
4. **Restore Backup:**
   ```bash
   rm -rf /path/to/challenge
   cp -r /path/to/challenge_backup_XXXXXX /path/to/challenge
   ```
5. **Restart Service:** `make restart`
6. **Verifikasi:** Cek lokal apakah service udah nyala.

---

## 💡 TIPS KRUSIAL PER KATEGORI

| Kategori | Strategi Defense | Strategi Attack |
| :--- | :--- | :--- |
| **Web** | Jalankan WAF simple. Patch manual sedikit (comment code). | Curl loop ke IP lawan, grep flag. |
| **Binary** | **JANGAN PAKE WAF.** Chmod file flag (`chmod 600 /flag`). Restart rutin. | Kirim payload exploit sederhana (netcat/python). |
| **Crypto** | **JANGAN PATCH.** Risiko tinggi bikin logic rusak. Fokus jaga server tetap nyala. | Analisis ciphertext, cari pola, brute force terbatas. |

---

## ⛔ LARANGAN KERAS (BIAR GAK DIDISKUALIFIKASI)

- ❌ **NO Automated Scanner:** Jangan pakai sqlmap, dirb, burp scanner.
- ❌ **NO Agentic AI:** Cuma boleh chat manual ke LLM.
- ❌ **NO DDoS:** Jangan sampe server lawan mati total.
- ❌ **NO Serangan di Luar Scope:** Hanya serang IP target yang disediakan.
- ❌ **NO Hapus Flag:** File `/flag` wajib ada biar checker dapat poin SLA.

---

**INGAT:** Tim pemenang bukan yang paling banyak nge-hack, tapi yang servicenya paling jarang mati. **Stay Simple, Stay Safe.** 🚀
