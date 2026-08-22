# 🛡️ Master Cheatsheet: Incident Response, Micro-Patching & Hardening (AD-CTF)

Panduan pertahanan sistem komprehensif, modular, dan terpadu menggunakan satu CLI utama: `adctf.py`.

---

## ⚡ 1. Salin-Tempel Cepat (1-Menit Pertama)

Segera setelah terhubung ke SSH server lomba, jalankan rangkaian perintah berikut:

```bash
# 1. Ganti Password User Anda
passwd

# 2. Jalankan Pre-flight Diagnostic & Auto-Triage (Cek Kesiapan Server)
python3 adctf.py doctor
python3 adctf.py triage

# 3. Jalankan Backup Web & DB Terverifikasi + Init Git Otomatis
python3 adctf.py start

# 4. Aktifkan Firewall Minimalis (Aman untuk SLA Game Server)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8000/tcp
sudo ufw allow from <IP_GAMESERVER_SLA> to any
sudo ufw --force enable
```

---

## 🧭 2. Diagram Alur Keputusan (Saat Diserang)

```
                       [ SERANGAN TERDETEKSI DI LOG ]
                       (python3 adctf.py watch --alert-only)
                                     │
                 ┌───────────────────┴───────────────────┐
                 │                                       │
     1. Ambil Payload Lawan                 2. Jalankan Triage:
        (Tersimpan di JSONL)                   - Cek koneksi: `ss -tupn`
                 │                             - Cek binary deleted: `ls /proc/*/exe`
                 ▼                                       │
     Replay ke Semua Lawan:                              ▼
     `python3 adctf.py attack 10.60.1-20.1`  Temukan backdoor penyerang
                 │                           dan matikan prosesnya (`kill -9`)
                 ▼
     Lakukan Micro-Patch pada Kode
     (Terapkan parameter binding / whitelist)
                 │
                 ▼
     Uji SLA: `python3 adctf.py check --url http://127.0.0.1/`
                 │
        ┌────────┴────────┐
      [200 OK]          [ERROR 500 / CRASH]
        │                 │
      Aman!             Rollback Cepat: `git restore .` atau `python3 adctf.py restore --confirm`
```

---

## 🔧 3. Panduan Micro-Patching (PHP, Python, NodeJS)

> **Golden Rule of Patching:**  
> Jangan mengubah struktur input/output API aplikasi. Cukup lakukan validasi dan sanitasi parameter di controller/handler.

---

### 3.1 SQL Injection (SQLi)

#### 🔴 PHP (Vulnerable ➡️ Patched)

```php
// ❌ [RENTAN]
$id = $_GET['id'];
$user = $_POST['username'];
$res = $db->query("SELECT * FROM users WHERE id = $id AND username = '$user'");

// ✅ [PATCH 1: PDO Prepared Statement (Rekomendasi Utama)]
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id AND username = :user");
$stmt->execute([
    ':id'   => (int)$_GET['id'],
    ':user' => (string)$_POST['username']
]);
$res = $stmt->fetchAll(PDO::FETCH_ASSOC);

// ✅ [PATCH 2: Quick Integer Casting (1-Detik Patch untuk ID Angka)]
$clean_id = (int)$_GET['id']; // Langsung aman dari SQLi jika tipe data adalah angka!
$res = $db->query("SELECT * FROM users WHERE id = $clean_id");
```

#### 🐍 Python (Vulnerable ➡️ Patched)

```python
# ❌ [RENTAN]
user = request.form.get("username")
cursor.execute(f"SELECT * FROM users WHERE username = '{user}'")

# ✅ [PATCH: Parameterized Queries]
# MySQL / Postgres:
cursor.execute("SELECT * FROM users WHERE username = %s", (user,))

# SQLite:
cursor.execute("SELECT * FROM users WHERE username = ?", (user,))
```

---

### 3.2 Local File Inclusion & Path Traversal (LFI)

#### 🔴 PHP (Vulnerable ➡️ Patched)

```php
// ❌ [RENTAN]
$page = $_GET['page'];
include("pages/" . $page . ".php");

// ✅ [PATCH 1: Whitelist Array (Paling Aman)]
$allowed = ['home', 'about', 'contact', 'dashboard', 'profile'];
$page = basename($_GET['page'] ?? 'home');
if (!in_array($page, $allowed, true)) {
    http_response_code(403);
    die("Access Denied.");
}
include(__DIR__ . "/pages/" . $page . ".php");

// ✅ [PATCH 2: Realpath Boundary Check (Jika file dinamis)]
$base = realpath(__DIR__ . "/uploads");
$target = realpath($base . "/" . basename($_GET['file']));
if ($target === false || strpos($target, $base) !== 0 || !file_exists($target)) {
    http_response_code(404);
    die("File Not Found.");
}
readfile($target);
```

#### 🐍 Python / Flask (Vulnerable ➡️ Patched)

```python
# ❌ [RENTAN]
filename = request.args.get("file")
return open(f"uploads/{filename}").read()

# ✅ [PATCH: Secure Filename & Path Resolution]
from pathlib import Path
from werkzeug.utils import secure_filename
from flask import abort

base = Path("/var/www/app/uploads").resolve()
clean_name = secure_filename(filename)
target = (base / clean_name).resolve()

if not str(target).startswith(str(base)) or not target.is_file():
    abort(403)

return target.read_text()
```

---

### 3.3 Remote Code Execution & Command Injection (RCE)

#### 🔴 PHP (Vulnerable ➡️ Patched)

```php
// ❌ [RENTAN]
$ip = $_POST['ip'];
system("ping -c 1 " . $ip);

// ✅ [PATCH: Validasi Format Ketat & escapeshellarg]
$ip = $_POST['ip'] ?? '';
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    http_response_code(400);
    die("Format IP tidak valid.");
}

$safe_ip = escapeshellarg($ip);
exec("ping -c 1 " . $safe_ip, $output, $return_var);
echo implode("\n", $output);
```

#### 🐍 Python (Vulnerable ➡️ Patched)

```python
# ❌ [RENTAN]
target = request.form.get("target")
subprocess.run(f"ping -c 1 {target}", shell=True) # shell=True sangat berbahaya!

# ✅ [PATCH: Argument List (shell=False) & Regex Validation]
import subprocess
import re

target = request.form.get("target", "")
if not re.match(r"^[a-zA-Z0-9.\-]+$", target):
    return "Invalid hostname format", 400

# Eksekusi dengan list terpisah tanpa shell
res = subprocess.run(["ping", "-c", "1", target], capture_output=True, text=True, check=True)
return res.stdout
```

---

### 3.4 Insecure Deserialization (PHP & Python)

```php
// 🔴 PHP: Ganti unserialize() dengan json_decode()
// ❌ RENTAN: $data = unserialize($_COOKIE['session']);
// ✅ AMAN:   $data = json_decode(base64_decode($_COOKIE['session']), true);
```

```python
# 🐍 Python: Hapus pickle.loads() sepenuhnya!
# ❌ RENTAN: data = pickle.loads(raw_data)
# ✅ AMAN:   data = json.loads(raw_data)
```

---

## 🔍 4. Forensik & Perburuan Backdoor di Linux

Gunakan perintah-perintah ini untuk mendeteksi penyerang yang sudah memiliki shell aktif:

```bash
# 1. Cari binary yang berjalan tapi filenya sudah dihapus penyerang (Stealth Backdoor)
ls -l /proc/*/exe 2>/dev/null | grep '(deleted)'

# 2. Cari semua koneksi ESTABLISHED keluar (Cari IP lawan)
ss -tupn state established

# 3. Bekukan proses untuk analisis, lalu matikan paksa
kill -STOP <PID>
kill -9 <PID>
pkill -9 -f "reverse_shell|nc|socat|python -c|bash -i"

# 4. Deteksi Webshell baru yang dimodifikasi dalam 30 menit terakhir
find /var/www/ -type f -name "*.php" -mmin -30 -ls

# 5. Cari fungsi berbahaya yang tertanam di seluruh webroot
grep -rnEi "(eval\s*\(|assert\s*\(|system\s*\(|shell_exec\s*\(|base64_decode\s*\(\s*\$_)" /var/www/html/ --exclude-dir={vendor,node_modules}

# 6. Audit crontab seluruh user
for u in $(cut -f1 -d: /etc/passwd); do echo "User $u:"; crontab -u $u -l 2>/dev/null; done
```

---

## 🔄 5. Backup Otomatis & Rapid Rollback

```bash
# 1. Inisialisasi awal via CLI
python3 adctf.py start

# 2. Watchdog background (Auto-commit setiap 15 detik jika ada perubahan)
while true; do cd /var/www/html; [[ -n $(git status --porcelain) ]] && git add . && git commit -m "Auto snapshot $(date +%T)"; sleep 15; done &

# 3. ROLLBACK DARURAT (Jika salah patch atau disusupi webshell):
git restore .
git clean -fd
# Atau restore backup tar.gz via adctf:
python3 adctf.py restore --confirm
```

---

## 🛡️ 6. Drop-in Micro WAF (Emergency Guard)

Jika kode web sangat kompleks dan waktu hampir habis:

```bash
# Buat file WAF instan
python3 adctf.py waf --type php --out /tmp/ctf_waf.php

# Pasang secara global di php.ini:
# auto_prepend_file = /tmp/ctf_waf.php

# Atau masukkan di baris paling awal /var/www/html/index.php:
# <?php require_once '/tmp/ctf_waf.php'; ?>
```

---

## 🎯 7. Matrix Perintah Lengkap `adctf.py`

| Perintah | Deskripsi Fungsi |
|---|---|
| `python3 adctf.py doctor` | Cek kesiapan Python, tool Linux, izin log, dan webroot |
| `python3 adctf.py triage` | Audit kilat spek server, port, database, dan koneksi aktif |
| `python3 adctf.py start` | Full backup web & DB terverifikasi + Git init baseline |
| `python3 adctf.py scan` | Scan static vulnerability pada PHP, Python, JS |
| `python3 adctf.py next` | Tampilkan 1 bug prioritas dengan context code & cara patch |
| `python3 adctf.py done` | Verifikasi perubahan kode & tandai bug selesai |
| `python3 adctf.py list` | Tampilkan checklist progress patch (✅ / ⬜) |
| `python3 adctf.py watch` | Monitor log realtime & rekam payload serangan lawan berwarna |
| `python3 adctf.py check` | Uji kesehatan layanan & SLA web lokal/remote |
| `python3 adctf.py attack <IP>` | Replay payload musuh ke tim lawan secara paralel |
| `python3 adctf.py submit` | Otomasi submit batch flag ke Scoring Server |
| `python3 adctf.py waf` | Generate micro-WAF drop-in untuk PHP / Python Flask |
| `python3 adctf.py restore` | Pulihkan webroot dari backup archive tar.gz |
| `python3 adctf.py` | Buka Menu Terminal Interaktif |
