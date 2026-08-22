# Database Defense Quick Reference

## MySQL/MariaDB

```bash
mysql --version
mysqladmin ping
mysql -e 'SHOW DATABASES;'
```

Pertahankan prepared statements, batasi user aplikasi, dan jangan membuka port database ke jaringan lomba bila aplikasi hanya membutuhkan localhost.

## PostgreSQL

```bash
psql --version
pg_isready
```

Gunakan parameterized query dan role aplikasi dengan permission minimum.

## SQLite

```bash
sqlite3 /path/to/app.sqlite3 'PRAGMA integrity_check;'
```

Jangan menyalin SQLite ketika aplikasi sedang write tanpa memahami risiko snapshot tidak konsisten.

## Cek eksposur port

```bash
ss -lntup | grep -E '3306|5432|6379|27017'
```

Perubahan firewall bukan default karena dapat memblokir SLA checker. Prioritaskan binding database ke localhost dan patch di level aplikasi.
