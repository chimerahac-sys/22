# 🏆 Attack-Defense CTF Tactical Playbook & Mindset Guide

Buku panduan taktis, strategi mental, dan pembagian peran tim menggunakan satu tool terpadu: `adctf.py`.

---

## 🎯 1. Realita Kompetisi: "Sesulit Apa Sebenarnya Attack-Defense CTF?"

Banyak peserta pemula merasa terintimidasi oleh format Attack-Defense karena membayangkan harus melakukan hacking dan pertahanan sekaligus dalam hitungan detik.  
**Kenyataannya:** Format Attack-Defense jauh lebih terstruktur dan sering kali lebih realistis daripada CTF Jeopardy.

### 📊 Mekanisme Dasar A/D CTF
1. **Tick System (Ronde):**  
   Permainan dibagi menjadi ratusan *Tick* (biasanya berdurasi **60 detik s.d. 120 detik** per tick).
2. **Flag Lifecycle:**  
   Setiap tick, sebuah bot panitia (*Checker Bot*) akan memasukkan flag baru ke dalam server setiap tim (misal di database atau filesystem), lalu memeriksa apakah layanan web Anda berfungsi normal.
3. **Formula Skor:**  
   $$\text{Total Score} = \text{SLA Score} + \text{Defense Score} + \text{Attack Score}$$
   - **SLA Score (Service Level Agreement):** Skor jika server tim Anda **UP** dan fungsionalitas fiturnya tidak rusak.
   - **Defense Score:** Skor didapat jika flag tim Anda pada tick tersebut **tidak berhasil dicuri** oleh lawan.
   - **Attack Score:** Skor didapat jika Anda berhasil **mencuri flag lawan** dan mengirimkannya ke Flag Submission Server.

> [!CAUTION]
> **JANGAN PERNAH MEMATIKAN SERVER ATAU MERUSAK FITUR APLIKASI!**  
> Di A/D CTF, kehilangan SLA memberikan penalti skor yang jauh lebih menghancurkan daripada terkena hack 1-2 kali. Pertahanan terbaik adalah **Safe Micro-Patching**, bukan menutup seluruh akses.

---

## 👥 2. Pembagian Peran Tim (Optimal 3–4 Orang)

```
                      ┌────────────────────────────────────────┐
                      │    KAPTEN TIM / HARDENER & SLA         │
                      │  - Ganti Password, Firewall, adctf     │
                      │  - Jaga SLA Server Tetap Hijau (UP)    │
                      └──────────────────┬─────────────────────┘
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │                                               │
┌────────────────┴──────────────────┐         ┌──────────────────┴─────────────────┐
│     LOG SNIFFER & REPLAYER        │         │   AUDITOR KODE & EXPLOIT DEV       │
│  - python3 adctf.py watch         │         │  - python3 adctf.py scan / next    │
│  - python3 adctf.py attack <IP>   │         │  - Tulis Patch Aman (Micro-Patch)  │
│  - python3 adctf.py submit        │         │  - python3 adctf.py done           │
└───────────────────────────────────┘         └────────────────────────────────────┘
```

---

## ⏱️ 3. Checklist Bertanding Menit per Menit

### 🔴 Fase 1: Lockdown & Triage (Menit 00 – 10)
Tujuan: Mengamankan akses, memahami arsitektur server, dan membuat titik restore.

```bash
# 1. Jalankan Doctor & Triage otomatis dalam 1 detik
python3 adctf.py doctor
python3 adctf.py triage

# 2. Ganti password user sendiri
passwd

# 3. Buat Baseline Git & Backup Terverifikasi
python3 adctf.py start

# 4. Pasang firewall UFW aman (Whitelist IP Game Server & SSH)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from <IP_TIM_KAMU> to any port 22 proto tcp
sudo ufw allow from <IP_GAMESERVER_SLA> to any
sudo ufw allow 80/tcp
sudo ufw --force enable
```

---

### 🟡 Fase 2: Sniffing & Safe Patching (Menit 10 – 30)
Tujuan: Membuka sensor traffic, menemukan bug di kode, dan menambalnya tanpa merusak SLA.

```bash
# 1. Buka Tmux Window 1: Monitor Log Realtime (Deteksi serangan musuh)
python3 adctf.py watch --alert-only

# 2. Buka Tmux Window 2: Scan source code & guided patch
python3 adctf.py scan
python3 adctf.py next

# 3. Lakukan patch manual di file yang ditunjukkan, lalu verifikasi:
python3 adctf.py done

# 4. Uji SLA Web lokal:
python3 adctf.py check --url http://127.0.0.1/
```

---

### 🟢 Fase 3: The "Steal & Replay" Meta (Menit 30 – Selesai)
Tujuan: Membalikkan serangan musuh ke seluruh peserta lain secara otomatis.

1. `adctf.py watch` otomatis merekam payload musuh ke `captured_attacks.jsonl`.
2. Jalankan Replay Engine untuk menembakkan kembali payload tersebut ke semua IP musuh (`10.60.1-20.1`):
   ```bash
   python3 adctf.py attack 10.60.1-20.1 --port 80
   ```
3. Submit flag yang berhasil dicuri ke Game Server:
   ```bash
   python3 adctf.py submit --url "http://10.0.0.1/api/submit" --token "TEAM_TOKEN_HERE"
   ```

---

## 🛠️ 4. Semua Modul di Satu Tempat

Anda tidak perlu bingung mencari tool terpisah. Cukup panggil `python3 adctf.py` untuk melihat menu interaktif atau jalankan sub-perintah langsung.
Semua tool individual di `scripts/defense/` (01–12) tetap tersedia jika butuh granular execution, namun `adctf.py` adalah pengendali utama satu pintu.
