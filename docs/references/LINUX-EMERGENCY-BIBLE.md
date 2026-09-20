# 🚨 Linux Emergency Command Bible — CTF Attack-Defense

> **Kamus Darurat Linux: Semua Command yang PASTI Kamu Butuhkan Saat Lomba A/D CTF.**
> Copy-paste langsung, tanpa mikir.

---

## 1. ⚡ MENIT PERTAMA SETELAH SSH (Recon Instan)

```bash
# Ganti password SEGERA
passwd

# Siapa kamu di server ini?
whoami && id && hostname

# Info OS & Kernel
uname -a && cat /etc/os-release

# Disk & RAM
df -h && free -m

# Port yang terbuka (KRITIS: catat port service lomba)
ss -tulnp

# Proses berjalan (sortir by memory usage)
ps aux --sort=-%mem | head -30

# User aktif (bukan system user)
cat /etc/passwd | grep -v nologin | grep -v /bin/false

# Cron jobs (sering dipake attacker buat persistence)
crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null

# File PHP baru yang mencurigakan (ditambahkan < 60 menit lalu)
find /var/www -name '*.php' -mmin -60 2>/dev/null

# Koneksi jaringan aktif (siapa yang terkoneksi ke server kita)
ss -tupn | grep ESTABLISHED
```

---

## 2. 🕵️ MENEMUKAN BACKDOOR & PROSES MENCURIGAKAN

### 2.1 Cari Backdoor PHP di Webroot
```bash
# KILLER COMMAND: Cari semua file PHP dengan fungsi berbahaya
find /var/www -name '*.php' -exec grep -lE \
  'eval\(|assert\(|system\(|exec\(|passthru\(|shell_exec\(|base64_decode\(|preg_replace.*\/e|create_function|call_user_func|file_put_contents.*\$_(GET|POST|REQUEST)' \
  {} \;

# Cari file PHP yang baru dimodifikasi (< 30 menit)
find /var/www -name '*.php' -mmin -30

# Cari file tersembunyi (dotfiles)
find /var/www -name '.*' -type f 2>/dev/null
find /var/www -name '.*.php' -o -name '*.php.bak' -o -name '*.phtml' 2>/dev/null

# Cari file di /tmp (tempat favorit attacker)
ls -la /tmp /dev/shm /var/tmp /run/shm 2>/dev/null
find /tmp -type f -executable 2>/dev/null
```

### 2.2 Cari Proses Reverse Shell / Backdoor
```bash
# Proses dengan binary yang sudah dihapus (deleted) = PASTI BACKDOOR!
ls -la /proc/*/exe 2>/dev/null | grep deleted

# Cari proses mencurigakan
ps aux | grep -E 'nc |ncat |netcat |socat |/bin/sh|/bin/bash|python.*socket|perl.*socket|php.*-r'

# Koneksi reverse shell (port umum)
ss -tupn | grep -E ':(4444|1234|9001|1337|31337|5555|6666|8888)'

# Semua koneksi ESTABLISHED (lihat IP asing)
ss -tupn state established

# Proses yang membuka koneksi keluar (reverse shell indicator)
lsof -i -P -n 2>/dev/null | grep ESTABLISHED
```

### 2.3 Cari Persistence Attacker
```bash
# Crontab semua user
for u in $(cut -d: -f1 /etc/passwd); do echo "=== $u ==="; crontab -u $u -l 2>/dev/null; done

# Authorized keys (SSH backdoor)
find / -name authorized_keys 2>/dev/null
find / -name id_rsa 2>/dev/null

# .bashrc / .profile hooks
grep -r 'nc \|ncat \|python.*socket\|curl \|wget ' /home/*/.bashrc /home/*/.profile /root/.bashrc /root/.profile 2>/dev/null

# Systemd service jahat
find /etc/systemd/system -name '*.service' -mmin -60 2>/dev/null
ls -lt /etc/systemd/system/*.service 2>/dev/null | head -10
```

---

## 3. 🔪 MEMBUNUH PROSES BACKDOOR

```bash
# Kill proses spesifik by PID
kill -9 <PID>

# Kill semua proses netcat/socat/reverse shell
pkill -9 -f 'nc -'
pkill -9 -f 'ncat'
pkill -9 -f 'socat'
pkill -9 -f 'python.*socket'
pkill -9 -f 'python.*pty'
pkill -9 -f 'perl.*socket'
pkill -9 -f 'php.*-r'
pkill -9 -f 'bash -i'

# Kill semua proses user tertentu (jika attacker buat user baru)
pkill -9 -u <USERNAME>

# Hapus crontab jahat
crontab -r  # Hapus semua crontab user saat ini
# atau edit manual: crontab -e
```

---

## 4. 📡 MONITORING REAL-TIME

```bash
# Monitor access log Nginx (PALING PENTING)
tail -f /var/log/nginx/access.log

# Monitor access log Apache
tail -f /var/log/apache2/access.log

# Monitor hanya serangan (filter pattern berbahaya)
tail -f /var/log/nginx/access.log | grep -E "eval|exec|system|union|select|base64|\.\./"

# Monitor error log (deteksi SLA drop)
tail -f /var/log/nginx/error.log

# Monitor koneksi jaringan real-time
watch -n 2 'ss -tupn state established'

# Monitor perubahan file di webroot (butuh inotify-tools)
inotifywait -m -r /var/www/html -e create,modify,delete 2>/dev/null

# Monitor proses baru yang muncul
watch -n 1 'ps aux --sort=-start_time | head -15'
```

---

## 5. 👤 USER & SSH MANAGEMENT

```bash
# Lihat user non-system (UID >= 1000)
awk -F: '$3 >= 1000 {print $1, $3, $6, $7}' /etc/passwd

# Siapa yang sedang login?
w
who
last -10

# Cek login history
grep 'sshd' /var/log/auth.log 2>/dev/null | tail -20
grep 'Accepted' /var/log/auth.log 2>/dev/null | tail -10

# Lihat semua authorized_keys
find / -name authorized_keys -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null

# HAPUS SSH key lawan (PENTING!)
> /root/.ssh/authorized_keys
for dir in /home/*/; do > "${dir}.ssh/authorized_keys" 2>/dev/null; done

# Ganti password user lain (jika kamu root)
echo "username:NewStr0ngP@ss!" | chpasswd

# Lock user mencurigakan (jangan hapus, bisa jadi checker panitia!)
usermod -L <USERNAME>
```

---

## 6. 📁 FILE PERMISSION & OWNERSHIP

```bash
# Reset ownership webroot ke www-data (standar Nginx/Apache)
chown -R www-data:www-data /var/www/html

# Reset permission file & folder ke standar aman
find /var/www/html -type f -exec chmod 644 {} \;
find /var/www/html -type d -exec chmod 755 {} \;

# Kunci compiler & tools attacker (WAJIB!)
chmod 700 /usr/bin/gcc /usr/bin/g++ /usr/bin/gdb /usr/bin/make 2>/dev/null
chmod 700 /usr/bin/nc /usr/bin/ncat /usr/bin/netcat /usr/bin/socat 2>/dev/null
chmod 700 /usr/bin/python2 2>/dev/null
chmod 700 /usr/bin/wget /usr/bin/curl 2>/dev/null  # HATI-HATI: cek dulu apakah service butuh curl

# Cari file SUID (bisa dipakai privilege escalation)
find / -perm -4000 -type f 2>/dev/null
```

---

## 7. 🌐 NETWORK FORENSICS CEPAT

```bash
# Lihat iptables rules saat ini
iptables -L -n --line-numbers
iptables -t nat -L -n

# Capture traffic port 80 (100 paket pertama)
tcpdump -i eth0 -nn 'port 80' -c 100

# Capture traffic ke file pcap
tcpdump -i eth0 -w /tmp/capture.pcap &

# UFW quick setup (jika ada)
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow from <IP_CHECKER_PANITIA> to any
ufw --force enable
ufw status verbose

# Lihat routing table
ip route
ip addr show
```

---

## 8. ⚙️ SERVICE MANAGEMENT

```bash
# Cek status web server
systemctl status nginx
systemctl status apache2
systemctl status php*-fpm

# Restart web server (setelah edit config)
nginx -t && systemctl reload nginx                   # Nginx
apache2ctl -t && systemctl reload apache2            # Apache

# Lihat log error service
journalctl -u nginx -f --no-pager
journalctl -u apache2 -f --no-pager
journalctl -u php*-fpm -f --no-pager

# Cek config syntax
nginx -t           # Nginx
apache2ctl -t      # Apache
php -l file.php    # PHP syntax check

# Restart PHP-FPM
systemctl restart php*-fpm

# Lihat service apa saja yang berjalan
systemctl list-units --type=service --state=running
```

---

## 9. 🗄️ DATABASE EMERGENCY

```bash
# Login MySQL (coba tanpa password dulu)
mysql -u root
mysql -u root -p

# Quick recon
mysql -u root -e "SHOW DATABASES;"
mysql -u root -e "SHOW TABLES;" dbname
mysql -u root -e "SELECT * FROM flags;" dbname

# BACKUP DARURAT (WAJIB MENIT PERTAMA!)
mysqldump -u root --all-databases > /tmp/full_db_backup.sql
mysqldump -u root dbname > /tmp/dbname_backup.sql

# Ganti password root MySQL
mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'N3wStr0ngP@ss!';"
mysql -u root -e "FLUSH PRIVILEGES;"

# SQLite backup
sqlite3 /path/to/db.sqlite ".dump" > /tmp/sqlite_backup.sql
cp /path/to/db.sqlite /tmp/db_backup.sqlite

# PostgreSQL
pg_dumpall > /tmp/pg_full_backup.sql
```

---

## 10. 📜 GIT FORENSICS & ROLLBACK

```bash
# Lihat history perubahan
git log --oneline -20
git log --diff-filter=A --name-only --pretty=format: | sort -u  # File yang ditambahkan

# Lihat perubahan terkini
git diff
git diff --stat
git status

# Lihat siapa yang mengubah file
git log --oneline -- suspicious_file.php

# ROLLBACK DARURAT (Kembalikan semua file ke state awal!)
git checkout .
# atau
git stash

# Rollback file tertentu
git checkout -- path/to/file.php

# Hard reset ke commit tertentu
git log --oneline -5
git reset --hard <COMMIT_HASH>
```

---

## 11. 🔧 ONE-LINER POWER COMBO

```bash
# COMBO 1: Scan + Kill semua backdoor dalam 1 baris
find /var/www -name '*.php' -exec grep -lE 'eval\(|system\(|exec\(|base64_decode' {} \; | while read f; do echo "[!] Backdoor: $f"; mv "$f" "/tmp/quarantine_$(basename $f)"; done

# COMBO 2: Monitor + Alert (bunyi beep saat ada serangan)
tail -f /var/log/nginx/access.log | grep --line-buffered -E 'eval|exec|union|\.\./' | while read line; do echo -e "\a[ALERT] $line"; done

# COMBO 3: Cek semua port + proses + koneksi dalam 1 perintah
echo "=== PORTS ===" && ss -tulnp && echo "=== ESTABLISHED ===" && ss -tupn state established && echo "=== SUSPICIOUS PROCS ===" && ps aux | grep -E 'nc |ncat|socat|python.*socket'

# COMBO 4: Emergency lockdown (jalankan semua sekaligus)
passwd && \
find /var/www -name '*.php' -mmin -10 -ls && \
pkill -9 -f 'nc -' 2>/dev/null; \
pkill -9 -f 'socat' 2>/dev/null; \
chmod 700 /usr/bin/gcc /usr/bin/nc 2>/dev/null; \
echo "[OK] Emergency lockdown complete"
```
