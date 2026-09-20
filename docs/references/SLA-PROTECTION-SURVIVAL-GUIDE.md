# 🛡️ SLA Protection & Scoreboard Survival Guide — CTF A/D

> **Panduan Menjaga Poin SLA Tetap 100% Hijau & Menyelesaikan Masalah HTTP 500/502/504 dalam Hitungan Detik.**

---

## 1. 🎯 CARA KERJA CHECKER JURI (SLA / UPTIME SCORING)

Di kompetisi Attack-Defense (seperti JCC atau Cyber Jawara):
* **Setiap Tick (2–5 Menit)**, Game Server menjalankan bot otomatis (Checker) ke server kamu.
* **Checker Melakukan 3 Hal**:
  1. **PUT FLAG**: Checker login ke web kamu, mengunggah data atau menyimpan flag baru di database/filesystem.
  2. **GET FLAG**: Checker meminta kembali flag yang diunggah untuk memastikan integritas data.
  3. **HEALTH CHECK**: Checker mengakses endpoint utama (Home, Login, Search) untuk memastikan web merespons HTTP `200 OK`.
* **Jika Checker Gagal (Mendapat HTTP 403, 500, 502, atau Timeout)**:
  * Status layanan tim kamu menjadi **DOWN / FAULT**.
  * Kamu kehilangan poin SLA untuk tick tersebut.
  * Poin SLA yang hilang **tidak bisa dikembalikan**.

---

## 2. 🚨 PENYEBAB UTAMA SLA RUSAK & SOLUSINYA

### ❌ Masalah 1: WAF Memblokir Request Bersih dari Juri (HTTP 403)
* **Penyebab**: Rule WAF terlalu agresif atau regex WAF memblokir format data yang dikirim oleh checker juri.
* **Solusi Instan**:
  1. Whitelist IP Juri / Game Server di baris teratas file WAF (`$WHITELIST_IPS`).
  2. Masukkan kata kunci User-Agent juri (`SLA`, `Checker`, `Monitor`) ke whitelist.
  3. Jika darurat, matikan WAF sementara:
     * Hapus baris `require_once '/tmp/ctf_waf.php';` dari `index.php`.
     * Atau hapus file `.user.ini`.

---

### ❌ Masalah 2: Error Syntax Setelah Edit Kode (HTTP 500)
* **Penyebab**: Kamu mengedit kode PHP/Python lalu terjadi typo, missing semicolon, atau fungsi undefined.
* **Solusi Instan (Hitungan Detik)**:
  1. **Verifikasi Syntax PHP**:
     ```bash
     php -l /var/www/html/index.php
     ```
  2. **Rollback File `.bak`**:
     ```bash
     cp /var/www/html/file_yang_diedit.php.bak /var/www/html/file_yang_diedit.php
     ```
  3. **Rollback Penuh via Git / Backup**:
     ```bash
     cd /var/www/html && git checkout .
     # atau:
     python3 adctf.py restore --confirm
     ```

---

### ❌ Masalah 3: Nginx / PHP-FPM Gateway Timeout (HTTP 502 / 504)
* **Penyebab**: PHP-FPM crash, socket PHP-FPM tidak ditemukan, atau pool PHP-FPM kehabisan worker process karena traffic tinggi.
* **Solusi Instan**:
  ```bash
  # 1. Cek versi PHP yang terpasang:
  php -v

  # 2. Restart PHP-FPM dan Nginx:
  systemctl restart php*-fpm
  systemctl restart nginx

  # 3. Cek apakah socket PHP-FPM aktif:
  ls -la /run/php/

  # 4. Naikkan jumlah worker PHP-FPM jika kehabisan child process:
  # Edit /etc/php/*/fpm/pool.d/www.conf:
  # pm.max_children = 50
  # pm.start_servers = 10
  # systemctl restart php*-fpm
  ```

---

### ❌ Masalah 4: Database Down / Access Denied (HTTP 500)
* **Penyebab**: MySQL crash, disk penuh, atau password database yang diubah tidak disesuaikan di `config.php`.
* **Solusi Instan**:
  ```bash
  # 1. Cek status MySQL:
  systemctl status mysql

  # 2. Restart MySQL:
  systemctl restart mysql

  # 3. Cek apakah disk server penuh (100%):
  df -h
  # Jika penuh, hapus file log lama:
  > /var/log/nginx/access.log
  > /var/log/nginx/error.log
  rm -rf /tmp/*.pcap

  # 4. Pastikan password di config.php sesuai dengan user database:
  grep -i "pass" /var/www/html/config.php
  ```

---

### ❌ Masalah 5: Hak Akses File Terlalu Ketat (Permission Denied)
* **Penyebab**: Kamu sengaja atau tidak sengaja melakukan `chmod 000` atau mengubah pemilik file ke `root:root` sehingga `www-data` tidak bisa membaca file web.
* **Solusi Instan**:
  ```bash
  chown -R www-data:www-data /var/www/html
  find /var/www/html -type f -exec chmod 644 {} \;
  find /var/www/html -type d -exec chmod 755 {} \;
  ```

---

## 3. ⏱️ CHECKLIST UJI SLA SEBELUM SUBMIT PERUBAHAN KODE

Sebelum kamu meninggalkan hasil editan kodemu:
```bash
# 1. Cek HTTP Status Code dari localhost:
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1/

# 2. Jalankan health checker otomatis:
python3 adctf.py check --url http://127.0.0.1/

# 3. Pastikan outputnya [UP] Code: 200!
```
Jika status sudah `200 OK`, kamu aman melanjutkan perbaikan celah berikutnya.
