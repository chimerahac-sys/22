# PETUNJUK TEKNIS BABAK FINAL JATIM CYBERSECURITY COMPETITION (JCC) JAWA TIMUR TAHUN 2026

## MEKANISME LOMBA BABAK FINAL

1. Perlombaan akan dilaksanakan secara luring (offline) di Kantor Dinas Komunikasi dan Informatika Provinsi Jawa Timur.

2. Format perlombaan adalah **Attack Defense** dengan pembagian kategori sebagai berikut:
   - Cryptography
   - Web Exploitation
   - Binary Exploitation

3. Perlombaan akan dilaksanakan mulai dari pukul **08.30 WIB** sampai dengan pukul **16.00 WIB**.

4. Peserta diperkenankan untuk hanya menggunakan **LLM berbasis Web** (Free dan/atau Paid) dari provider manapun dan dilarang keras menggunakan **Agentic AI**.

5. Selama lomba berlangsung, peserta dilarang:
   a. Bekerja sama dengan tim lain dalam bentuk apapun
   b. Menggunakan automated scanner/tools seperti sqlmap, burp scanner, dirb, dan lain-lain pada platform
   c. Menyebabkan suatu kerugian atau gangguan dalam bentuk apapun terhadap peserta lain maupun panitia, seperti dan tidak terbatas pada:
      - Menghapus/mengganti jawaban (petunjuk jawaban)
      - Melakukan DDOS pada service atau platform yang digunakan
      - Melakukan brute force jawaban berlebihan pada platform hingga menyebabkan server menjadi down
      - Dilarang bertukar jawaban kepada tim lain
      - Gangguan secara teknis maupun non teknis lainnya
      - Menyerang di luar scope target (ruang lingkup)

6. **3 (tiga) tim terbaik** dengan poin tertinggi berhak untuk mendapatkan gelar pemenang Jatim Cybersecurity Competition 2026.

7. Untuk babak final, peserta **tidak diharuskan** untuk membuat writeup.

8. Sesi pemanasan atau **warm up** akan diadakan secara daring (online) pada hari **Selasa, 22 September 2026** pada pukul **09.00 WIB** sampai dengan pukul **16.00 WIB**.

---

## MEKANISME ATTACK DEFENSE

> **Catatan:** Seluruh informasi mengenai tata cara menggunakan platform Attack Defense dapat diakses di bagian **"A&D Toolkit"**

### 1. Akses Jaringan ke Target Challenge

Untuk melakukan akses terhadap setiap target challenge dari tim lain maupun tim anda, peserta dapat menggunakan **WireGuard**.

**Konfigurasi WireGuard:**
- Unduh konfigurasi WireGuard dari platform
- Install WireGuard sesuai OS yang Anda gunakan
- Lakukan import file `.conf` ke WireGuard
- Gunakan koneksi VPN untuk mengakses target challenge yang disediakan

### 2. Mendapatkan IP Tim Lain

Untuk mendapatkan IP setiap tim, lakukan request ke endpoint berikut:

```bash
curl -sS "https://jcc.jatimprov.go.id/api/Game/<GAME_ID>/Ad/Targets" \
  -H "Authorization: Bearer <API_TOKEN>"
```

Dimana `API_TOKEN` didapatkan dari interface platform. Response akan berisi IP dari tim lain.

**Target:** Menyerang tim lain untuk memperoleh flag.

### 3. Patching Service Sendiri

Setiap tim diperbolehkan melakukan **patching** sejak ronde pertama dimulai, tanpa harus berhasil memperoleh flag terlebih dahulu.

**Pembagian Tugas:**
Anggota tim dapat membagi tugas untuk:
- Menyerang (attacking)
- Memperbaiki kerentanan (patching)
- Memantau target (monitoring)

**Akses SSH untuk Patching:**
Petunjuk akses SSH tersedia pada bagian **Shell access (SSH)** di A&D Toolkit:
- Peserta dapat menggunakan public key masing-masing
- Atau melakukan generate key pair SSH

**Proses Patching:**
Lakukan SSH ke dalam service dan patch kode yang diperlukan. Pada saat patching, peserta harus:
- Mempertahankan fungsi utama target yang diuji oleh checker
- Memastikan perubahan tidak menyebabkan target tidak dapat digunakan secara normal

### 4. Restart Service Setelah Patching

Setelah melakukan patching, jalankan perintah berikut untuk me-restart service:

```bash
make restart
```

**Daftar Perintah yang Tersedia:**

| Perintah | Fungsi |
|----------|--------|
| `make start` | Menjalankan challenge |
| `make restart` | Melakukan restart pada challenge |
| `make stop` | Menghentikan challenge |
| `make compile` | Melakukan kompilasi pada file binary (khusus kategori pwn) |

### 5. Flag Submission

**Lokasi Flag:** `/flag` pada filesystem setiap challenge.

Flag yang berhasil diperoleh dari lawan harus dikirimkan ke platform sebelum kedaluwarsa dan sebelum pertandingan berakhir.

**Metode Submit Flag:**

**A. Via Interface Platform**

**B. Via API:**
```bash
curl -X POST "https://jcc.jatimprov.go.id/api/Game/<GAME_ID>/Ad/Submit" \
  -H "Authorization: Bearer API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"flags":["flag{CONTOH_FLAG_PERTAMA}","flag{CONTOH_FLAG_KEDUA}"]}'
```

**Response Status API:**

| Status | Keterangan |
|--------|------------|
| `accepted` | Flag diterima dan dicatat untuk perhitungan skor |
| `duplicate` | Flag yang sama sudah pernah diterima dari tim pengirim |
| `wrong` | Flag tidak dikenali atau tidak memenuhi validasi pertandingan |
| `expired` | Masa berlaku flag telah berakhir |
| `self_attack` | Flag berasal dari target milik tim pengirim sendiri |
| `not_started` | Pertandingan atau ronde pertama belum dimulai |
| `paused` | Penerimaan flag sedang dihentikan sementara |
| `ended` | Pertandingan telah berakhir |

### 6. Tick dan Round System

**Tick** adalah proses pengecekan SLA (Service Level Agreement) terhadap target menggunakan sejumlah test case dari checker.

**Status SLA Checker:**

| Status | Keterangan |
|--------|------------|
| `Ok` | Target berhasil melewati seluruh test case checker dan seluruh flag yang masih berlaku berhasil didapatkan |
| `Recovering` | Target berhasil melewati seluruh test case checker, tetapi sebagian flag dari round sebelumnya yang masih berlaku tidak berhasil didapatkan |
| `Mumble` | Target dapat terhubung dan merespons checker, tetapi terdapat fungsi atau layanan yang tidak bekerja sesuai dengan yang diharapkan sehingga test case checker gagal |
| `Offline` | Checker tidak dapat terhubung ke target |
| `InternalError` | Terjadi masalah internal pada proses checker sehingga pengecekan tidak dapat diselesaikan dengan normal |

**Round** adalah periode dimana flag yang diperoleh pada round tersebut masih berlaku. Setiap round menghasilkan flag baru untuk setiap target. Ketika memasuki round baru, flag dari round sebelumnya tidak lagi berlaku.

---

## SISTEM SKORING

Skoring menggunakan referensi dari **ATKLAB v2 - Attacking-Lab Wiki**.

**Rumus Total Score:**
```
Total Score = ATK + DEF + SLA
```

**Parameter Waktu:**
- Satu tick berlangsung selama **60 detik**
- Satu round tampilan terdiri dari **5 tick** atau **5 menit**
- Flag baru dibuat pada setiap tick
- Setiap flag berlaku selama **5 tick**, termasuk tick ketika flag dibuat
- Flag yang dibuat pada tick `t` dapat dikumpulkan sampai sebelum tick `t + 5`
- Satu tim hanya mendapatkan poin satu kali untuk flag yang sama (pengiriman duplikat tidak menambah poin)
- Nilai sebuah flag bergantung pada jumlah tim yang berhasil mendapatkan flag tersebut (**semakin sedikit tim yang mendapatkan flag, semakin tinggi nilainya**)

### 1. Attack Points (ATK)

Attack Points diperoleh ketika sebuah tim berhasil mengambil dan mengirimkan flag milik tim lain sebelum flag tersebut kedaluwarsa.

### 2. Defense Points (DEF)

Defense Points diperoleh ketika sebuah tim berhasil melindungi flag dari penyerang yang aktif.

### 3. Service Level Agreement Points (SLA)

SLA menunjukkan seberapa baik tim menjaga service tetap berfungsi dan mempertahankan flag yang masih berlaku.

**Referensi Detail Perhitungan Skor:**
[https://gist.github.com/miraicantsleep/21bffa21cff1a2fd3f02b2320e0e4edc](https://gist.github.com/miraicantsleep/21bffa21cff1a2fd3f02b2320e0e4edc)

---

**Terima kasih dan semoga sukses!**

---
*Dokumen ini merupakan ringkasan dari Petunjuk Teknis Babak Final Jatim Cybersecurity Competition (JCC) Jawa Timur Tahun 2026*
