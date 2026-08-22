# Attack-Defense Quick Reference

## Menit pertama

```text
1. Catat IP, port, web root, dan endpoint checker.
2. Backup dan validasi arsip.
3. Simpan baseline health check.
4. Cek port dan proses.
5. Scan source secara read-only.
6. Tangani HIGH dahulu, lalu MEDIUM.
7. Setelah satu patch: scan ulang + health check.
8. Pantau log lokal sepanjang ronde.
```

## Perintah inti

```bash
python3 scripts/adctf.py start --web-root /var/www/html --port 80 --endpoint /
python3 scripts/adctf.py scan --web-root /var/www/html
python3 scripts/adctf.py next
python3 scripts/adctf.py check --url http://127.0.0.1/
python3 scripts/adctf.py done --base http://127.0.0.1 --endpoint /
python3 scripts/adctf.py watch --log-file /var/log/apache2/access.log
python3 scripts/adctf.py status
```

## Jika service bermasalah

```bash
python3 scripts/adctf.py check --url http://127.0.0.1/
ss -lntup
ps aux --sort=-%cpu | head
tail -n 50 /var/log/nginx/error.log
tail -n 50 /var/log/apache2/error.log
```

Jangan langsung restart atau restore sebelum menyimpan bukti error. Preview restore terlebih dahulu:

```bash
python3 scripts/adctf.py restore
python3 scripts/adctf.py restore --confirm
```

## Prinsip ronde

- Satu perubahan kecil per iterasi.
- Simpan output/error sebelum mengubah konfigurasi.
- Jangan memblokir jaringan sebelum tahu alamat SLA checker.
- Jangan memperlakukan `404` sebagai service sehat.
- Jangan menganggap scanner dengan nol temuan berarti aman.
