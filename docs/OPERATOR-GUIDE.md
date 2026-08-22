# 🎮 Panduan Singkat Operator (Khusus Teman Tim)

> **Untuk Temanmu:** Lu gak perlu pusing mikirin coding atau nyari celah keamanan. Tugas lu di sini adalah **Copilot / Operator Radar & Eksekutor Otomatis**. Ikuti panduan 3 langkah di bawah ini!

---

## ⚡ 3 Langkah Tugas Lu Sepanjang Lomba

### 1. Buka Terminal 1: Nyalakan Mode "AUTOPILOT" (Wajib)

Jalankan perintah ini di awal lomba dan **biarkan tetap jalan terus**:

```bash
# Ganti 10.60.1-20.1 dengan rentang IP musuh lomba
# Ganti TOKEN_TIM dengan token dari panitia
python3 adctf.py autopilot --targets 10.60.1-20.1 --submit-url http://10.0.0.1/api/submit --token TOKEN_TIM
```

**Apa yang dilakukan Autopilot secara otomatis?**
1. 📡 **Radar:** Membaca log server dan mendeteksi kalau ada musuh yang nyerang.
2. 🚀 **Auto-Replay:** Begitu musuh nyerang, Autopilot langsung mengambil serangan musuh itu dan menembakkannya balik ke **semua tim lawan** secara paralel!
3. 🎯 **Auto-Submit:** Flag yang berhasil dicuri dari lawan langsung otomatis disubmit ke server panitia!
4. 🩺 **SLA Guard:** Setiap 30 detik mengecek apakah web server kita masih hidup.

---

### 2. Buka Terminal 2: Penjaga SLA (Uji Web)

Tiap kali teman lu (si patcher) bilang: *"Gw abis edit file X, tolong cek web masih idup gak"*, lu cukup ketik:

```bash
python3 adctf.py check --url http://127.0.0.1/
```

- Jika muncul hijau `[✓ UP] (Status: 200)` ➡️ Bilang: *"Aman bro, web lancar!"*
- Jika muncul merah `[✗ DOWN]` ➡️ Teriak: *"BRO WEB CRASH / 500, ROLLBACK SEKARANG!"*

---

### 3. Buka Terminal 3: Menu Interaktif (Kalau Bingung Perintah)

Kalau lupa nama perintah, lu cukup ketik:

```bash
python3 adctf.py
```

Tinggal pilih angka **1 sampai 11** di keyboard:
- Tekan `1` ➡️ Cek kesehatan sistem (*Doctor*)
- Tekan `2` ➡️ Lihat siapa yang lagi connect ke server (*Triage*)
- Tekan `3` ➡️ Backup web & database (*Start*)
- Tekan `6` ➡️ Lihat live radar serangan musuh (*Watch*)
- Tekan `9` ➡️ Kirim ulang flag yang udah didapat (*Submit*)

---

## 🚨 Kapan Lu Harus Teriak / Kasih Tahu Teman Lu?

| Tulisan di Layar Lu | Artinya | Yang Harus Lu Lakukan |
|---|---|---|
| 🟩 `[SLA HEALTH: OK (200)]` | Server aman, normal, dapat poin SLA | Santai, ngopi, pantau monitor |
| 🚩 `FLAG DICURI DARI 10.x.x.x` | Autopilot berhasil nyolong flag musuh! | Rayakan poin nambah! |
| 🟨 `[HIGH:ATTACK] / [CRITICAL:EXPLOIT]` | Musuh lagi nyerang endpoint web kita | Kasih tahu temanmu: *"Bro musuh nyerang URL ini!"* |
| 🟥 `[SLA DOWN! ERROR]` | Web kita error / mati (Poin berkurang drastis!) | **TERIAK KE TEMANMU:** *"BRO WEB KITA DOWN, KODE TERAKHIR KEMBALIKAN DULU (`git restore .`)!"* |

---

## 💡 Ringkasan Cheat Code Buat Lu

```bash
# Nyalakan Autopilot (Senjata Utama)
python3 adctf.py autopilot --targets 10.60.1-20.1

# Cek Web Masih Idup
python3 adctf.py check

# Buka Menu Gampang
python3 adctf.py
```
