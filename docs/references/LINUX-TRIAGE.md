# Linux Local Triage

Perintah di sini read-only dan ditujukan untuk server sendiri.

## Sistem dan resource

```bash
id
uname -a
cat /etc/os-release
df -h
free -m
uptime
```

## Port dan proses

```bash
ss -lntup
ps aux --sort=-%cpu | head -20
ps aux --sort=-%mem | head -20
systemctl --type=service --state=running
```

## Service umum

```bash
systemctl status nginx --no-pager
systemctl status apache2 --no-pager
systemctl status php8.2-fpm --no-pager
systemctl status mysql --no-pager
systemctl status mariadb --no-pager
systemctl status postgresql --no-pager
```

Nama unit bisa berbeda. Jika tidak ditemukan, lanjutkan dengan proses dan port; jangan langsung mengubah service.

## File yang baru berubah

```bash
find /var/www -type f -mmin -30 -print 2>/dev/null
find /app -type f -mmin -30 -print 2>/dev/null
```

## Cron dan startup review

```bash
crontab -l 2>/dev/null
ls -la /etc/cron.d /etc/cron.daily /etc/systemd/system
```

Jangan menghapus item hanya karena namanya tidak dikenal. Catat path, owner, waktu perubahan, dan proses yang memakainya.
