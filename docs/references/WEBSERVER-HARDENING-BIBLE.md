# 🧱 Nginx & Apache Hardening Bible — CTF A/D

> **Hardening Web Server untuk CTF Attack-Defense: Copy-paste langsung ke config.**

---

## 1. 🟢 NGINX — KONFIGURASI AMAN

### 1.1 Lokasi File Config
```bash
/etc/nginx/nginx.conf                    # Config utama
/etc/nginx/sites-enabled/default         # Virtual host default
/etc/nginx/conf.d/*.conf                 # Additional configs
/var/log/nginx/access.log                # Access log
/var/log/nginx/error.log                 # Error log
```

### 1.2 Hardening Config (Copy-Paste ke `/etc/nginx/nginx.conf`)

Tambahkan di blok `http { }`:
```nginx
# === SECURITY HARDENING === #

# Sembunyikan versi Nginx dari response header
server_tokens off;

# Batasi ukuran body request (anti upload shell besar)
client_max_body_size 2m;

# Batasi ukuran buffer (anti buffer overflow attack)
client_body_buffer_size 16k;
client_header_buffer_size 1k;
large_client_header_buffers 2 1k;

# Timeout protection
client_body_timeout 10;
client_header_timeout 10;
send_timeout 10;
keepalive_timeout 15;

# Rate limiting (anti brute-force & anti-DoS)
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=3r/s;
```

### 1.3 Hardening Virtual Host (Copy-Paste ke `sites-enabled/default`)

Tambahkan di blok `server { }`:
```nginx
server {
    listen 80;
    server_name _;
    root /var/www/html;
    index index.php index.html;

    # === SECURITY HEADERS === #
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # === BLOKIR FILE SENSITIF === #
    location ~ /\.(git|svn|env|htaccess|htpasswd) {
        deny all;
        return 404;
    }

    # Blokir akses langsung ke file backup/config
    location ~* \.(sql|bak|old|backup|log|ini|yml|yaml|config|conf)$ {
        deny all;
        return 404;
    }

    # === BLOKIR EKSEKUSI PHP DI UPLOADS === #
    location ~* /uploads/.*\.php$ {
        deny all;
        return 403;
    }
    location ~* /upload/.*\.php$ {
        deny all;
        return 403;
    }
    location ~* /images/.*\.php$ {
        deny all;
        return 403;
    }
    location ~* /tmp/.*\.php$ {
        deny all;
        return 403;
    }

    # === BLOKIR WEBSHELL FILENAME UMUM === #
    location ~* /(shell|cmd|backdoor|c99|r57|wso|b374k|alfa|phpinfo|adminer|phpmyadmin)\.php$ {
        deny all;
        return 404;
    }

    # === PHP-FPM HANDLER === #
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php-fpm.sock;
        # atau: fastcgi_pass 127.0.0.1:9000;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_intercept_errors on;
    }

    # Rate limiting pada endpoint login
    location ~ /login {
        limit_req zone=login burst=5 nodelay;
        try_files $uri $uri/ =404;
    }
}
```

### 1.4 Whitelist SLA Checker IP

```nginx
# Tambahkan di blok http { } di nginx.conf
geo $is_checker {
    default         0;
    10.0.0.1        1;   # IP SLA checker panitia
    172.16.0.1      1;   # IP game server
    # Tambahkan IP checker lainnya di sini
}

# Gunakan di server block untuk bypass rate limit
# if ($is_checker) { set $limit_key ""; }
```

### 1.5 Test & Restart
```bash
# Test syntax config (WAJIB sebelum restart!)
nginx -t

# Reload config (tanpa downtime)
systemctl reload nginx

# Restart (jika reload gagal)
systemctl restart nginx

# Cek status
systemctl status nginx

# Cek log error
journalctl -u nginx --no-pager -n 30
tail -f /var/log/nginx/error.log
```

---

## 2. 🟠 APACHE — KONFIGURASI AMAN

### 2.1 Lokasi File Config
```bash
/etc/apache2/apache2.conf                # Config utama
/etc/apache2/sites-enabled/000-default.conf  # Virtual host
/etc/apache2/conf-enabled/*.conf         # Additional configs
/var/www/html/.htaccess                  # Per-directory config
/var/log/apache2/access.log              # Access log
/var/log/apache2/error.log               # Error log
```

### 2.2 .htaccess Hardening (Copy-Paste ke `/var/www/html/.htaccess`)

```apache
# === SEMBUNYIKAN VERSI === #
ServerSignature Off

# === MATIKAN DIRECTORY LISTING === #
Options -Indexes

# === BLOKIR FILE SENSITIF === #
<FilesMatch "(?i)\.(git|env|svn|bak|old|sql|log|config|ini|yml|yaml|backup|sqlite|db)$">
    Require all denied
</FilesMatch>

# Blokir .htaccess, .htpasswd
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>

# === MATIKAN PHP DI FOLDER UPLOADS === #
<IfModule mod_php.c>
    <Directory "/var/www/html/uploads">
        php_flag engine off
    </Directory>
</IfModule>

# Alternatif: blokir eksekusi PHP di uploads via FilesMatch
<DirectoryMatch "^/var/www/html/(uploads|upload|images|tmp)/">
    <FilesMatch "\.php$">
        Require all denied
    </FilesMatch>
</DirectoryMatch>

# === SECURITY HEADERS === #
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "no-referrer-when-downgrade"
</IfModule>

# === LIMIT REQUEST SIZE (Anti Upload Shell Besar) === #
LimitRequestBody 2097152

# === BLOKIR WEBSHELL URI === #
<LocationMatch "(?i)/(shell|cmd|backdoor|c99|r57|wso|b374k|alfa|phpinfo|adminer)\.php">
    Require all denied
</LocationMatch>
```

### 2.3 Folder Uploads — Matikan PHP (WAJIB!)

Buat file `/var/www/html/uploads/.htaccess`:
```apache
# Matikan eksekusi PHP di folder uploads (SANGAT PENTING!)
<FilesMatch "(?i)\.(php|phtml|php3|php4|php5|php7|phar|inc)$">
    Require all denied
</FilesMatch>

# Alternatif: matikan engine PHP sepenuhnya
<IfModule mod_php.c>
    php_flag engine off
</IfModule>
```

### 2.4 Test & Restart Apache
```bash
# Test syntax config
apache2ctl -t

# Reload (tanpa downtime)
systemctl reload apache2

# Restart
systemctl restart apache2

# Cek status
systemctl status apache2

# Log error
journalctl -u apache2 --no-pager -n 30
tail -f /var/log/apache2/error.log
```

---

## 3. ⚙️ PHP-FPM CONFIGURATION HARDENING

### 3.1 Lokasi Config PHP
```bash
# Cari versi PHP yang aktif
php -v
ls /etc/php/

# Config files
/etc/php/8.*/fpm/php.ini           # PHP config utama (FPM)
/etc/php/8.*/cli/php.ini           # PHP config untuk CLI
/etc/php/8.*/fpm/pool.d/www.conf   # FPM pool config
```

### 3.2 Hardening php.ini (Tambahkan/Edit di php.ini)
```ini
; === SEMBUNYIKAN INFO PHP === ;
expose_php = Off

; === MATIKAN FUNGSI BERBAHAYA === ;
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,pcntl_exec,proc_get_status,proc_terminate,proc_close

; === MATIKAN REMOTE FILE INCLUSION === ;
allow_url_fopen = Off
allow_url_include = Off

; === BATASI FILESYSTEM ACCESS === ;
open_basedir = /var/www/html:/tmp:/var/tmp

; === BATASI UPLOAD === ;
file_uploads = On
upload_max_filesize = 2M
max_file_uploads = 5

; === ERROR HANDLING (Jangan tampilkan error ke user!) === ;
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log

; === SESSION HARDENING === ;
session.cookie_httponly = 1
session.cookie_secure = 0
session.use_strict_mode = 1
```

> ⚠️ **PERHATIAN**: Jangan matikan `exec` dan `system` jika aplikasi web memang membutuhkan fungsi tersebut (misal: fitur ping tool yang merupakan bagian dari service SLA checker). Cek dulu source code sebelum mematikan!

### 3.3 Restart PHP-FPM
```bash
systemctl restart php*-fpm
systemctl status php*-fpm
```

---

## 4. 🔍 QUICK DIAGNOSTIC COMMANDS

```bash
# Test apakah header security sudah aktif
curl -I http://localhost 2>/dev/null | grep -iE 'server|x-frame|x-content|x-xss'

# Test apakah versi server tersembunyi
curl -I http://localhost 2>/dev/null | grep -i server

# Test akses file sensitif (harus return 403/404)
curl -s -o /dev/null -w "%{http_code}" http://localhost/.env
curl -s -o /dev/null -w "%{http_code}" http://localhost/.git/config
curl -s -o /dev/null -w "%{http_code}" http://localhost/uploads/test.php

# Test SLA endpoint (HARUS return 200!)
curl -s -o /dev/null -w "%{http_code}" http://localhost/
curl -s -o /dev/null -w "%{http_code}" http://localhost/index.php

# Test PHP info (harus GAGAL setelah hardening)
curl -s -o /dev/null -w "%{http_code}" http://localhost/phpinfo.php
```
