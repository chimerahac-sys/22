# Metasploit — CTF/AD Quick Reference

Gunakan hanya terhadap target yang tercantum di scope lomba. Template di bawah sengaja memakai satu `RHOSTS` dan tidak menjalankan discovery massal, brute force, persistence, atau evasion.

## Alur dasar satu target

```text
msfconsole -q
search type:exploit name:<service-or-cve>
info <module/path>
use <module/path>
show options
set RHOSTS 10.10.10.5
set RPORT 80
check
run
back
exit -y
```

`check` hanya dipakai bila modul mendukungnya. Jika modul tidak mendukung `check`, lakukan verifikasi manual dari service dan source code lomba terlebih dahulu.

## Template berdasarkan temuan

### HTTP service / versi komponen

```text
search type:auxiliary name:http
info auxiliary/scanner/http/http_version
use auxiliary/scanner/http/http_version
set RHOSTS 10.10.10.5
set RPORT 80
run
```

Gunakan hanya untuk satu host yang sudah diketahui, bukan rentang IP.

### Temuan CVE spesifik

```text
search cve:<CVE-ID>
info exploit/<platform>/<type>/<path>
use exploit/<platform>/<type>/<path>
show options
set RHOSTS 10.10.10.5
set RPORT <port-yang-terverifikasi>
check
run
```

Jangan menebak modul dari nama service saja. Cocokkan versi, konfigurasi, dan hasil `check` dengan bukti dari target.

### Auxiliary module yang tidak mengubah target

```text
search type:auxiliary <keyword>
info auxiliary/<path>
use auxiliary/<path>
show options
set RHOSTS 10.10.10.5
run
```

Hindari modul yang melakukan password spraying, destructive testing, database dump besar, atau perubahan konfigurasi kecuali aturan lomba secara eksplisit mengizinkannya.

## Checklist sebelum `run`

- Target ada di `targets.txt`/scope resmi.
- Hanya satu `RHOSTS`.
- Port dan service sudah terverifikasi.
- Modul tidak brute-force, tidak mass-scan, dan tidak destructive.
- SLA checker tetap dipantau dengan `python3 scripts/adctf.py check`.
- Catat modul, waktu, target, hasil, dan perubahan yang terjadi.

## Troubleshooting aman

```text
show missing
show advanced
show payloads
show targets
unsetg RHOSTS
setg RHOSTS 10.10.10.5
```

Jika target menjadi tidak sehat setelah percobaan, hentikan pengiriman, jalankan health check, dan pulihkan dari backup bila memang diperlukan.
