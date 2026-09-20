# 🐘 PHP Vulnerability & Instant Patch Bible (Attack-Defense CTF)

> **Kamus Lengkap Celah PHP Paling Sering Keluar di A&D CTF + Cara Patch 1 Baris Tanpa Merusak SLA.**

---

## 📑 Daftar Isi Celah PHP
1. [SQL Injection (PDO, MySQLi, SQLite)](#1-sql-injection)
2. [Local File Inclusion / Path Traversal & PHP Wrappers](#2-lfi--php-wrappers)
3. [Remote Code Execution & Command Injection](#3-rce--command-injection)
4. [Insecure File Upload & Webshells](#4-insecure-file-upload)
5. [Insecure Deserialization (unserialize / POP Chains)](#5-insecure-deserialization)
6. [Type Juggling & Loose Comparison (`==` vs `===`)](#6-type-juggling--loose-comparison)
7. [Server-Side Request Forgery (SSRF)](#7-server-side-request-forgery-ssrf)
8. [XML External Entity (XXE)](#8-xml-external-entity-xxe)
9. [Hardening PHP Configuration (`php.ini` / `.user.ini`)](#9-php-configuration-hardening)

---

## 1. SQL Injection

### 🔴 Kasus 1: ID Numerik
```php
// ❌ [RENTAN]
$id = $_GET['id'];
$res = $db->query("SELECT * FROM products WHERE id = " . $id);

// ✅ [PATCH 1 DETIK: Typecasting (int)]
$id = (int)($_GET['id'] ?? 0);
$res = $db->query("SELECT * FROM products WHERE id = " . $id);
```

### 🔴 Kasus 2: String Input (Login / Search) - PDO
```php
// ❌ [RENTAN]
$user = $_POST['user'];
$pass = $_POST['pass'];
$res = $pdo->query("SELECT * FROM users WHERE user = '$user' AND pass = '$pass'");

// ✅ [PATCH: Parameter Binding PDO]
$stmt = $pdo->prepare("SELECT * FROM users WHERE user = :u AND pass = :p");
$stmt->execute([
    ':u' => (string)($_POST['user'] ?? ''),
    ':p' => (string)($_POST['pass'] ?? ''),
]);
$user_data = $stmt->fetch(PDO::FETCH_ASSOC);
```

### 🔴 Kasus 3: String Input - MySQLi
```php
// ❌ [RENTAN]
$name = $_POST['name'];
$res = mysqli_query($conn, "SELECT * FROM users WHERE name = '$name'");

// ✅ [PATCH 1: Prepared Statement MySQLi]
$stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE name = ?");
$clean_name = (string)($_POST['name'] ?? '');
mysqli_stmt_bind_param($stmt, "s", $clean_name);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);

// ✅ [PATCH CEPAT 2: mysqli_real_escape_string (Jika query kompleks)]
$clean_name = mysqli_real_escape_string($conn, (string)($_POST['name'] ?? ''));
$res = mysqli_query($conn, "SELECT * FROM users WHERE name = '$clean_name'");
```

---

## 2. LFI & PHP Wrappers

### 🔴 Kasus 1: include / require Dinamis
```php
// ❌ [RENTAN: LFI ../../../../etc/passwd atau php://filter]
$page = $_GET['page'];
include($page . ".php");

// ✅ [PATCH TERBAIK: Whitelist Array + basename()]
$allowed = ['home', 'about', 'contact', 'login', 'dashboard'];
$page = basename($_GET['page'] ?? 'home');
if (!in_array($page, $allowed, true)) {
    $page = 'home'; // Fallback aman, SLA tidak crash
}
include(__DIR__ . "/pages/" . $page . ".php");
```

### 🔴 Kasus 2: PHP Stream Wrappers (`php://filter`, `data://`, `php://input`)
Attacker sering membaca source code via:
`?page=php://filter/convert.base64-encode/resource=config`
```php
// ✅ [PATCH CEPAT: Blokir Protokol Wrapper]
$page = (string)($_GET['page'] ?? 'home');
if (preg_match('/^(php|data|file|phar|zip|glob|expect|http|https):\/\//i', $page)) {
    http_response_code(400);
    die("Access Denied");
}
$page = basename($page);
include(__DIR__ . "/templates/" . $page . ".php");
```

---

## 3. RCE & Command Injection

### 🔴 Kasus 1: Ping Tool / Shell Execution
```php
// ❌ [RENTAN: ip = 127.0.0.1; cat /flag]
$ip = $_POST['ip'];
system("ping -c 1 " . $ip);

// ✅ [PATCH 1: Validasi Tipe Data + escapeshellarg()]
$ip = trim($_POST['ip'] ?? '');
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    die("Invalid IP format");
}
exec("ping -c 1 " . escapeshellarg($ip), $output);
```

### 🔴 Kasus 2: Dynamic Function Call / Callback (`eval`, `assert`, `$$var`)
```php
// ❌ [RENTAN: $_GET['func'] = 'system', $_GET['arg'] = 'id']
$func = $_GET['func'];
$func($_GET['arg']);

// ❌ [RENTAN: preg_replace dengan /e modifier]
preg_replace('/(.*)/e', 'strtoupper("\\1")', $_GET['input']);

// ✅ [PATCH: Whitelist Fungsi Eksplisit]
$allowed_funcs = ['strtoupper', 'strtolower', 'trim', 'htmlspecialchars'];
$func = $_GET['func'] ?? 'strtoupper';
if (!in_array($func, $allowed_funcs, true)) {
    $func = 'strtoupper';
}
$output = $func((string)($_GET['arg'] ?? ''));
```

---

## 4. Insecure File Upload

### 🔴 Celah Upload Umum di CTF:
1. Hanya mengecek ekstensi di client-side.
2. Mengecek `Content-Type: image/png` tapi ekstensi tetap `.php`.
3. Double extension: `shell.php.jpg` atau `shell.phtml`.
4. Menyimpan file di folder yang bisa dieksekusi web server (`/uploads/shell.php`).

```php
// ❌ [RENTAN]
$target = "uploads/" . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $target);

// ✅ [PATCH KOMPREHENSIF: Whitelist Ekstensi + Random Hash + Cek MIME]
$allowed_exts = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'txt'];
$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain'];

$file_name = $_FILES['file']['name'] ?? '';
$file_tmp  = $_FILES['file']['tmp_name'] ?? '';

if (!is_uploaded_file($file_tmp)) {
    die("Upload failed");
}

$ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $file_tmp);
finfo_close($finfo);

if (!in_array($ext, $allowed_exts, true) || !in_array($mime, $allowed_mimes, true)) {
    die("Format file dilarang!");
}

// Rename ke random hash agar attacker tidak bisa menebak nama file
$safe_name = bin2hex(random_bytes(16)) . "." . $ext;
$target_dir = __DIR__ . "/uploads/";
move_uploaded_file($file_tmp, $target_dir . $safe_name);
```

### 🛡️ Kunci Folder Uploads via `.htaccess` (Apache):
Buat file `/var/www/html/uploads/.htaccess`:
```apache
# Matikan eksekusi PHP di folder uploads
<FilesMatch "(?i)\.(php|phtml|php3|php4|php5|php7|phar|inc)$">
    Order Deny,Allow
    Deny from all
</FilesMatch>
php_flag engine off
```

---

## 5. Insecure Deserialization

### 🔴 Kasus: `unserialize()` User Input
```php
// ❌ [RENTAN: Object Injection / Magic Methods __destruct, __wakeup]
$session = unserialize(base64_decode($_COOKIE['auth']));

// ✅ [PATCH 1: Ganti ke JSON (Paling Aman)]
$session = json_decode(base64_decode($_COOKIE['auth'] ?? ''), true);
if (!is_array($session)) {
    $session = [];
}

// ✅ [PATCH 2: Jika terpaksa unserialize, matikan instansiasi class]
$session = @unserialize(base64_decode($_COOKIE['auth'] ?? ''), ["allowed_classes" => false]);
```

---

## 6. Type Juggling & Loose Comparison

### 🔴 Kasus 1: Password / Token Verification (`==` vs `===`)
```php
// ❌ [RENTAN: "0e12345" == "0e98765" -> TRUE (Magic Hashes!)]
// ❌ [RENTAN: strcmp($_POST['pass'], $secret) == 0 (Jika pass array [] -> strcmp return NULL -> NULL == 0 -> TRUE!)]
if ($_POST['token'] == "0e888888888888888888888888888888") { ... }
if (strcmp($_POST['password'], $admin_pass) == 0) { ... }

// ✅ [PATCH: Strict Comparison === & hash_equals()]
$input_token = (string)($_POST['token'] ?? '');
if (hash_equals($secret_token, $input_token)) {
    // Login berhasil
}

// Atau pastikan string & gunakan ===
if (is_string($_POST['password']) && (string)$_POST['password'] === $admin_pass) {
    // Login berhasil
}
```

---

## 7. Server-Side Request Forgery (SSRF)

### 🔴 Kasus: `curl` / `file_get_contents` ke URL User
```php
// ❌ [RENTAN: url = http://127.0.0.1:8080/admin atau http://169.254.169.254]
$url = $_GET['url'];
$content = file_get_contents($url);

// ✅ [PATCH: Validasi Skema & Larang IP Private/Localhost]
$url = (string)($_GET['url'] ?? '');
$parsed = parse_url($url);

if (!isset($parsed['scheme']) || !in_array(strtolower($parsed['scheme']), ['http', 'https'], true)) {
    die("Hanya protokol HTTP/HTTPS yang diizinkan");
}

$host = $parsed['host'] ?? '';
$ip = gethostbyname($host);

// Cek apakah IP private / loopback
if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) || $ip === '127.0.0.1') {
    die("Akses ke jaringan internal dilarang!");
}

$content = file_get_contents($url);
```

---

## 8. XML External Entity (XXE)

```php
// ❌ [RENTAN: libxml memproses entity eksternal <!ENTITY xxe SYSTEM "file:///flag">]
$xml_data = file_get_contents('php://input');
$doc = simplexml_load_string($xml_data);

// ✅ [PATCH: Matikan libxml entity loader & external entity]
libxml_disable_entity_loader(true); // PHP < 8.0
$doc = simplexml_load_string($xml_data, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDLOAD);
```

---

## 9. PHP Configuration Hardening (`.user.ini` / `php.ini`)

Tambahkan baris berikut ke `/var/www/html/.user.ini` atau `/etc/php/*/fpm/php.ini`:

```ini
; Sembunyikan versi PHP
expose_php = Off

; Matikan eksekusi URL jarak jauh pada include
allow_url_fopen = Off
allow_url_include = Off

; Matikan fungsi berbahaya yang sering dipakai reverse shell
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

; Batasi akses filesystem hanya ke webroot dan /tmp
open_basedir = /var/www/html:/tmp:/var/tmp
```
*(Catatan: Jangan matikan `curl_exec` jika aplikasi web kamu memang membutuhkan API curl untuk fungsi bisnis normal).*
