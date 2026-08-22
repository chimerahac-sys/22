# SLA / Health Debugging

## Tes bertahap

```bash
curl -i --max-time 5 http://127.0.0.1/
curl -i --max-time 5 http://127.0.0.1/health
curl -i --max-time 5 http://127.0.0.1/login
```

Jika hanya satu endpoint gagal, jangan restore seluruh aplikasi. Cari route dan dependency endpoint tersebut.

| Gejala | Kemungkinan |
|---|---|
| Connection refused | service mati atau port salah |
| Timeout | proses macet, dependency lambat, atau bind address salah |
| HTTP 404 | route/path checker salah atau route hilang |
| HTTP 403 | permission/auth/web server policy |
| HTTP 502/503 | upstream PHP-FPM/Node/Flask mati |
| HTTP 500 | exception atau syntax/runtime error |
| Response kosong | handler berjalan tetapi gagal menghasilkan body |

## Log yang diperiksa

```bash
tail -n 80 /var/log/nginx/error.log
tail -n 80 /var/log/apache2/error.log
tail -n 80 /var/log/php*-fpm.log
journalctl -u nginx -n 80 --no-pager
journalctl -u apache2 -n 80 --no-pager
```

## Setelah patch

```text
1. Endpoint utama.
2. Endpoint yang disentuh patch.
3. Login atau checker path.
4. Error log.
5. Baru tandai done.
```
